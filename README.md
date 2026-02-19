# disk_reliability

Minimal usage for `disk_tester.py` and `plotter.py`.

## Prerequisites

- Python 3.10+
- `fio` installed and available on `PATH` (required by `disk_tester.py`)

Install Python dependencies:

```bash
pip install -r requirements-online.txt
```

## 1) Run disk_tester

Example (temperature workload with log output):

```bash
python disk_tester.py temp --path D:\ --interval 60 --duration 3600
```

This produces a `.log` file such as `disk_test_*.log`.

## 2) Run plotter

Auto mode (scan a directory for `.log` + `.TXT/.txt`, match by timestamp overlap):

```bash
python plotter.py --dir . --outdir plots_out
```

Targeted mode (explicit files):

```bash
python plotter.py --log disk_test.log --txt Raw_Temp\02181235.TXT Raw_Temp\02190515.TXT --outdir plots_out
```

Outputs:

- merged CSV: `*_merged.csv`
- plot image: `*_temp_speed.png`
