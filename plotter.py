#!/usr/bin/env python3
"""
Single script to parse raw temp TXT + disk test LOG files and plot speed vs temp.

Modes:
1) Targeted:
   python plotter.py --log disk_test.log --txt 02181235.TXT 02190515.TXT
2) Auto directory matching (default):
   python plotter.py --dir .

For auto mode, each .log is matched to .txt files by overlapping timestamps.
One plot + merged CSV is produced per .log file.
"""

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


TEMP_MIN = -40
TEMP_MAX = 80
SPEED_MAX = 2000


def parse_temp_file(path: Path) -> pd.DataFrame:
    rows = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.startswith("AT"):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            ts = f"{parts[1]} {parts[2]}"
            try:
                temp1 = float(parts[4])
            except ValueError:
                continue
            rows.append((pd.to_datetime(ts, errors="coerce"), temp1))

    if not rows:
        return pd.DataFrame(columns=["Timestamp", "Temp1"])

    df = pd.DataFrame(rows, columns=["Timestamp", "Temp1"]).dropna(subset=["Timestamp"])
    return df.sort_values("Timestamp")


def parse_log_file(path: Path) -> tuple[pd.DataFrame, str]:
    speed_rows = []
    capacities = []

    speed_re = re.compile(
        r"^\[(?P<ts>.+?)\]\s+(?P<mode>SEQUENTIAL|RANDOM)\s+(?P<op>write|read):\s+(?P<speed>[\d.]+)\s+MiB/s",
        re.IGNORECASE,
    )
    cap_re = re.compile(r"Capacity:\s*total=(?P<total>[^,]+),\s*free=(?P<free>.+)$")

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            cap_m = cap_re.search(line)
            if cap_m:
                capacities.append(f"{cap_m.group('total').strip()} total")

            m = speed_re.search(line)
            if not m:
                continue
            ts = pd.to_datetime(m.group("ts"), errors="coerce")
            if pd.isna(ts):
                continue
            speed = float(m.group("speed"))
            mode = m.group("mode").upper()
            op = m.group("op").lower()
            speed_rows.append((ts, mode, op, speed))

    if not speed_rows:
        return pd.DataFrame(columns=["Timestamp", "Mode", "Operation", "SpeedMiB"]), "Unknown capacity"

    speed_df = pd.DataFrame(speed_rows, columns=["Timestamp", "Mode", "Operation", "SpeedMiB"])
    speed_df = speed_df.sort_values("Timestamp").reset_index(drop=True)
    capacity_text = ", ".join(sorted(set(capacities))) if capacities else "Unknown capacity"
    return speed_df, capacity_text


def get_time_range(df: pd.DataFrame) -> tuple[pd.Timestamp | None, pd.Timestamp | None]:
    if df.empty:
        return None, None
    return df["Timestamp"].min(), df["Timestamp"].max()


def ranges_overlap(a0, a1, b0, b1) -> bool:
    if any(x is None for x in (a0, a1, b0, b1)):
        return False
    return (a0 <= b1) and (b0 <= a1)


def merge_and_aggregate(
    temp_df: pd.DataFrame,
    speed_df: pd.DataFrame,
    temp_offset_hours: float,
    max_temp_gap_sec: int,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    temp_df = temp_df.copy()
    speed_df = speed_df.copy()

    temp_df["Timestamp"] = temp_df["Timestamp"] + pd.to_timedelta(temp_offset_hours, unit="h")

    merged = pd.merge_asof(
        speed_df.sort_values("Timestamp"),
        temp_df.sort_values("Timestamp"),
        on="Timestamp",
        direction="nearest",
        tolerance=pd.Timedelta(seconds=max_temp_gap_sec),
    )

    merged = merged[merged["SpeedMiB"] < SPEED_MAX]
    merged = merged[merged["Temp1"].between(TEMP_MIN, TEMP_MAX, inclusive="both")]

    merged["TimeBlock"] = merged["Timestamp"].dt.floor("1min")
    merged["TempRounded"] = merged["Temp1"].round()

    agg = (
        merged.groupby(["Mode", "Operation", "TempRounded", "TimeBlock"])["SpeedMiB"]
        .mean()
        .reset_index()
        .groupby(["Mode", "Operation", "TempRounded"])["SpeedMiB"]
        .mean()
        .reset_index()
        .sort_values(["Mode", "Operation", "TempRounded"])
    )

    return merged, agg


def plot_agg(agg_df: pd.DataFrame, title: str, out_png: Path, show: bool) -> None:
    plt.figure(figsize=(10, 5))
    series_cfg = [
        ("SEQUENTIAL", "read", "Sequential Read", "#1f77b4", "-"),
        ("SEQUENTIAL", "write", "Sequential Write", "#ff7f0e", "-"),
        ("RANDOM", "read", "Random Read", "#2ca02c", "--"),
        ("RANDOM", "write", "Random Write", "#d62728", "--"),
    ]

    for mode, op, label, color, style in series_cfg:
        part = agg_df[(agg_df["Mode"] == mode) & (agg_df["Operation"] == op)]
        if part.empty:
            continue
        plt.plot(
            part["TempRounded"],
            part["SpeedMiB"],
            label=f"{label} (MiB/s)",
            linewidth=2,
            color=color,
            linestyle=style,
        )

    plt.title(title, fontsize=12, fontweight="bold")
    plt.xlabel("Temperature (C)")
    plt.ylabel("Speed (MiB/s)")
    plt.xlim(TEMP_MIN, 70)
    plt.xticks(range(TEMP_MIN, 71, 10))
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    if show:
        plt.show()
    plt.close()


def process_single_log(
    log_path: Path,
    txt_paths: list[Path],
    out_dir: Path,
    temp_offset_hours: float,
    max_temp_gap_sec: int,
    show: bool,
) -> None:
    speed_df, capacity = parse_log_file(log_path)
    if speed_df.empty:
        print(f"[skip] {log_path.name}: no speed rows parsed")
        return

    temp_frames = [parse_temp_file(p) for p in txt_paths]
    temp_df = pd.concat(temp_frames, ignore_index=True) if temp_frames else pd.DataFrame(columns=["Timestamp", "Temp1"])
    if temp_df.empty:
        print(f"[skip] {log_path.name}: no temp rows parsed from matched TXT files")
        return

    merged, agg = merge_and_aggregate(temp_df, speed_df, temp_offset_hours, max_temp_gap_sec)
    if agg.empty:
        print(f"[skip] {log_path.name}: merged data empty after filtering")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    stem = log_path.stem
    merged_csv = out_dir / f"{stem}_merged.csv"
    plot_png = out_dir / f"{stem}_temp_speed.png"

    merged.to_csv(merged_csv, index=False)
    summary = (
        merged.groupby(["Mode", "Operation"])["SpeedMiB"]
        .mean()
        .reset_index()
        .sort_values(["Mode", "Operation"])
    )
    quant_parts = [
        f"{row.Mode[:3]}-{row.Operation[0].upper()} {row.SpeedMiB:.1f}"
        for row in summary.itertuples(index=False)
    ]
    quant_text = " | ".join(quant_parts)
    title = f"{log_path.name} | Capacity: {capacity} | Avg MiB/s: {quant_text}"
    plot_agg(agg, title, plot_png, show=show)

    print(f"[ok] {log_path.name}")
    print(f"  matched txt: {', '.join(p.name for p in txt_paths)}")
    print(f"  merged csv : {merged_csv}")
    print(f"  plot png   : {plot_png}")


def discover_pairs(base_dir: Path) -> list[tuple[Path, list[Path]]]:
    logs = sorted(base_dir.glob("*.log"))
    txts = sorted(list(base_dir.glob("*.TXT")) + list(base_dir.glob("*.txt")))
    if not logs:
        return []

    txt_ranges = {}
    for txt in txts:
        tdf = parse_temp_file(txt)
        txt_ranges[txt] = get_time_range(tdf)

    pairs = []
    for log in logs:
        speed_df, _ = parse_log_file(log)
        l0, l1 = get_time_range(speed_df)
        matched = []
        for txt, (t0, t1) in txt_ranges.items():
            if ranges_overlap(l0, l1, t0, t1):
                matched.append(txt)

        if not matched and txts:
            matched = txts
        pairs.append((log, matched))

    return pairs


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Merge temp TXT + disk test LOG and generate plots.")
    p.add_argument("--dir", default=".", help="Directory for auto mode (default: current dir).")
    p.add_argument("--log", help="Single log file path for targeted mode.")
    p.add_argument("--txt", nargs="+", help="One or more temp TXT files for targeted mode.")
    p.add_argument("--outdir", default="plots_out", help="Output directory for plots and merged CSVs.")
    p.add_argument("--temp-offset-hours", type=float, default=0.0, help="Shift temp timestamps by hours (default: 0).")
    p.add_argument("--max-temp-gap-sec", type=int, default=120, help="Max allowed time gap for timestamp matching.")
    p.add_argument("--show", action="store_true", help="Show plots interactively.")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.outdir)

    # Targeted mode: explicit --log + --txt
    if args.log or args.txt:
        if not (args.log and args.txt):
            raise SystemExit("Targeted mode requires both --log and --txt.")
        log_path = Path(args.log)
        txt_paths = [Path(x) for x in args.txt]
        process_single_log(
            log_path=log_path,
            txt_paths=txt_paths,
            out_dir=out_dir,
            temp_offset_hours=args.temp_offset_hours,
            max_temp_gap_sec=args.max_temp_gap_sec,
            show=args.show,
        )
        return

    # Auto mode: scan directory and match each log to overlapping txt files
    base_dir = Path(args.dir)
    pairs = discover_pairs(base_dir)
    if not pairs:
        raise SystemExit(f"No .log files found in: {base_dir}")

    for log_path, txt_paths in pairs:
        if not txt_paths:
            print(f"[skip] {log_path.name}: no txt files available")
            continue
        process_single_log(
            log_path=log_path,
            txt_paths=txt_paths,
            out_dir=out_dir,
            temp_offset_hours=args.temp_offset_hours,
            max_temp_gap_sec=args.max_temp_gap_sec,
            show=args.show,
        )


if __name__ == "__main__":
    main()
