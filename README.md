# Disk Tester (Python/FIO)

A cross-platform disk reliability and benchmarking tool, implemented in Python using `fio` as the backend. This tool is designed to replicate and extend the functionality of the original Rust-based disk tester.

## Features

*   **Benchmark (`bench`)**: Sequential (1M) and Random (4k) Read/Write tests.
*   **Reliability Stress (`stress`)**: Full-disk (90% capacity) sequential write with CRC32C verification.
*   **Temperature Generation (`temp`)**: Periodic bursts of sequential and random writes to generate heat, with sleep intervals for polling temperature (without cache exhaustion).
*   **Cross-Platform**: Supports Linux (`libaio`), Windows (`windowsaio`), and macOS (`posixaio`).
*   **Safety**: Defaults to using 90% of available free space (or disk size) to avoid filling the disk completely.

## Prerequisites

*   Python 3.x
*   [fio](https://github.com/axboe/fio) installed and in your system PATH.
    *   **Linux**: `sudo apt install fio` (Debian/Ubuntu) or `sudo dnf install fio` (Fedora).
    *   **macOS**: `brew install fio`
    *   **Windows**: Download binary from [bluestop.org/fio](https://bluestop.org/fio/) or use WSL.

## Usage

Run the script directly:

```bash
chmod +x disk_tester.py
./disk_tester.py [command] [options]
```

### Global Options

*   `--path <path>`: Target file or directory. If a directory is provided, a `disk_test.dat` file is created inside. (Default: `./disk_test.dat`)
*   `--direct` / `--no-direct`: Enable/Disable Direct I/O (Default: Enabled).
*   `--size <size>`: Override test size (e.g., `10G`, `500M`). If not specified, uses 90% of free space.

### Commands

#### 1. Benchmark

Runs standard sequential and random performance tests.

```bash
./disk_tester.py bench --path /mnt/nvme_drive
```

#### 2. Reliability Stress Test

Writes to the defined area and verifies data integrity using CRC32C.

```bash
./disk_tester.py stress --path /mnt/nvme_drive
```

#### 3. Temperature Generation

Runs periodic bursts to heat the drive.

```bash
./disk_tester.py temp --path /mnt/nvme_drive --interval 60 --duration 3600
```
*   `--interval`: Cycle time in seconds (Work + Sleep). Work is ~10s.
*   `--duration`: Total test duration in seconds.

## Legacy Code

The original Rust implementation has been moved to the `legacy_rust/` directory.
