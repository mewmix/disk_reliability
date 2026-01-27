#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unified chart tool:
- Parse disk_test.log files (current Python temp summary lines or legacy Rust lines)
- Parse raw temperature TXT files (AT lines)
- Merge by nearest timestamps
- Aggregate by temperature and minute blocks
- Plot read/write speed vs temperature
"""

import argparse
import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent

TIME_COL = "Timestamp"
TEMP_COL = "TempC"
READ_COL = "ReadSpeed"
WRITE_COL = "WriteSpeed"
OP_COL = "Op"
DEVICE_COL = "Device"

TEMP_LINE_PREFIX = "AT"

TEMP_PATTERN = re.compile(r"^AT\b")
LEGACY_LOG_PATTERN = re.compile(
    r"\[(?P<ts>[^\]]+)\].*?(?P<write>[\d\.]+)\s+MiB/s W,\s+(?P<read>[\d\.]+)\s+MiB/s R",
    re.IGNORECASE,
)
TEMP_LOG_PATTERN = re.compile(
    r"\[(?P<ts>[^\]]+)\]\s+TEMP\s+(?P<op>[\w_]+)\s+(?P<rw>read|write):\s+(?P<speed>[\d\.]+)\s+MiB/s",
    re.IGNORECASE,
)


def _parse_temp_line(line: str):
    if not TEMP_PATTERN.match(line):
        return None
    parts = line.split()
    if len(parts) < 3:
        return None
    timestamp_str = f"{parts[1]} {parts[2]}"
    numeric_values = re.findall(r"-?\d+(?:\.\d+)?", line)
    if not numeric_values:
        return None
    try:
        temp_value = float(numeric_values[-1])
    except ValueError:
        return None
    return timestamp_str, temp_value


def load_temperature_data(temp_dir: Path, offset_hours: int) -> pd.DataFrame:
    records = []
    for txt_file in sorted(temp_dir.glob("*.TXT")):
        with txt_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                parsed = _parse_temp_line(line)
                if parsed:
                    timestamp_str, temp_value = parsed
                    records.append((timestamp_str, temp_value))

    temp_df = pd.DataFrame(records, columns=[TIME_COL, TEMP_COL])
    if temp_df.empty:
        return temp_df

    temp_df[TIME_COL] = pd.to_datetime(temp_df[TIME_COL], errors="coerce")
    temp_df = temp_df.dropna(subset=[TIME_COL])
    if offset_hours:
        temp_df[TIME_COL] = temp_df[TIME_COL] - pd.Timedelta(hours=offset_hours)
    return temp_df.sort_values(TIME_COL)


def parse_disk_log(log_path: Path) -> pd.DataFrame:
    rows = []
    with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = TEMP_LOG_PATTERN.search(line)
            if match:
                ts_str = match.group("ts")
                op = match.group("op")
                rw = match.group("rw").lower()
                speed = float(match.group("speed"))
                read_speed = speed if rw == "read" else None
                write_speed = speed if rw == "write" else None
                rows.append((ts_str, read_speed, write_speed, op))
                continue

            match = LEGACY_LOG_PATTERN.search(line)
            if match:
                ts_str = match.group("ts")
                read_speed = float(match.group("read"))
                write_speed = float(match.group("write"))
                rows.append((ts_str, read_speed, write_speed, "legacy"))

    df = pd.DataFrame(rows, columns=[TIME_COL, READ_COL, WRITE_COL, OP_COL])
    if df.empty:
        return df
    df[TIME_COL] = pd.to_datetime(df[TIME_COL], errors="coerce")
    df[READ_COL] = pd.to_numeric(df[READ_COL], errors="coerce")
    df[WRITE_COL] = pd.to_numeric(df[WRITE_COL], errors="coerce")
    return df.dropna(subset=[TIME_COL])


def merge_with_temps(speed_df: pd.DataFrame, temp_df: pd.DataFrame, tolerance_minutes: int) -> pd.DataFrame:
    if temp_df.empty or speed_df.empty:
        return pd.DataFrame(columns=[TIME_COL, READ_COL, WRITE_COL, TEMP_COL, OP_COL, DEVICE_COL])

    speed_sorted = speed_df.sort_values(TIME_COL)
    temp_sorted = temp_df.sort_values(TIME_COL)

    merged = pd.merge_asof(
        speed_sorted,
        temp_sorted,
        on=TIME_COL,
        direction="nearest",
        tolerance=pd.Timedelta(minutes=tolerance_minutes),
    )
    return merged.dropna(subset=[TEMP_COL])


def aggregate_by_temp(df: pd.DataFrame, time_block: str) -> pd.DataFrame:
    if df.empty:
        return df
    work = df.copy()
    work["TimeBlock"] = work[TIME_COL].dt.floor(time_block)
    work["TempRounded"] = work[TEMP_COL].round()

    agg = (
        work.groupby(["TempRounded", "TimeBlock"])[[READ_COL, WRITE_COL]]
        .mean()
        .reset_index()
        .groupby("TempRounded")[[READ_COL, WRITE_COL]]
        .mean()
        .reset_index()
        .sort_values("TempRounded")
    )
    return agg


def plot_lines(agg: pd.DataFrame, title: str, out_path: Path):
    if agg.empty:
        print(f"[WARN] No data to plot for {out_path}")
        return
    agg = agg.dropna(subset=[READ_COL, WRITE_COL], how="all")
    if agg.empty:
        print(f"[WARN] No numeric data to plot for {out_path}")
        return

    plt.figure(figsize=(10, 5))
    if agg[READ_COL].notna().any():
        plt.plot(
            agg["TempRounded"],
            agg[READ_COL],
            label="Read Speed (MiB/s)",
            linewidth=2,
            color="skyblue",
            marker="o",
        )
    if agg[WRITE_COL].notna().any():
        plt.plot(
            agg["TempRounded"],
            agg[WRITE_COL],
            label="Write Speed (MiB/s)",
            linewidth=2,
            color="orange",
            marker="o",
        )

    plt.title(title, fontsize=14, fontweight="bold")
    plt.xlabel("Temperature (C)")
    plt.ylabel("Speed (MiB/s)")
    plt.xlim(-10, 70)
    plt.xticks(range(-10, 71, 10))
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend()
    plt.tight_layout()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"[OK] Plot saved to {out_path}")


def find_log_files(paths):
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
            continue
        if path.is_dir():
            for log_path in path.rglob("disk_test.log"):
                yield log_path


def main():
    parser = argparse.ArgumentParser(
        description="Merge disk_test.log files with temperature data and plot speed vs temperature."
    )
    parser.add_argument(
        "--log-path",
        action="append",
        default=[],
        help="disk_test.log file or a directory to search (repeatable)",
    )
    parser.add_argument(
        "--temp-dir",
        default=str(BASE_DIR / "Raw_Temp"),
        help="Directory containing temperature TXT files (default: Raw_Temp)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(BASE_DIR / "output"),
        help="Output directory for merged CSVs",
    )
    parser.add_argument(
        "--plot-dir",
        default=str(BASE_DIR / "plots"),
        help="Output directory for plots",
    )
    parser.add_argument(
        "--time-block",
        default="1min",
        help="Pandas time block for smoothing (default: 1min)",
    )
    parser.add_argument(
        "--tolerance-minutes",
        type=int,
        default=5,
        help="Max time gap allowed for temp alignment (default: 5)",
    )
    parser.add_argument(
        "--temp-offset-hours",
        type=int,
        default=0,
        help="Offset temperature timestamps by hours (default: 0)",
    )

    args = parser.parse_args()
    temp_dir = Path(args.temp_dir)
    out_dir = Path(args.out_dir)
    plot_dir = Path(args.plot_dir)

    if not args.log_path:
        args.log_path = [str(BASE_DIR)]

    temp_df = load_temperature_data(temp_dir, args.temp_offset_hours)
    if temp_df.empty:
        raise RuntimeError(f"No temperature data found in {temp_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)
    plot_dir.mkdir(parents=True, exist_ok=True)

    combined_frames = []
    for log_path in find_log_files(args.log_path):
        speed_df = parse_disk_log(log_path)
        if speed_df.empty:
            print(f"[WARN] No speed data found in {log_path}")
            continue

        merged = merge_with_temps(speed_df, temp_df, args.tolerance_minutes)
        if merged.empty:
            print(f"[WARN] No merged rows for {log_path}")
            continue

        device_name = log_path.parent.name or log_path.stem
        merged[DEVICE_COL] = device_name

        out_file = out_dir / f"{device_name}_merged.csv"
        merged.to_csv(out_file, index=False)
        combined_frames.append(merged)
        print(f"[OK] Wrote {out_file}")

        agg = aggregate_by_temp(merged, args.time_block)
        plot_lines(agg, f"{device_name} Average Speed vs Temperature", plot_dir / f"{device_name}.png")

    if not combined_frames:
        raise RuntimeError("No disk_test.log files found or no valid data parsed.")

    combined = pd.concat(combined_frames).sort_values(TIME_COL)
    combined_file = out_dir / "combined_merged.csv"
    combined.to_csv(combined_file, index=False)
    print(f"[OK] Wrote {combined_file}")

    combined_agg = aggregate_by_temp(combined, args.time_block)
    plot_lines(combined_agg, "Combined Average Speed vs Temperature", plot_dir / "combined.png")


if __name__ == "__main__":
    main()
