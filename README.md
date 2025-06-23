# Cross‑Platform Disk Reliability Testing Tool

A **Rust-based utility** for aggressive read/write/verify burn‑in of any block device or regular file. Runs on **Linux, macOS and Windows** and can be built with an optional *direct‑I/O* feature to bypass the page‑cache for real hardware reliability testing.

---

## 1  Prerequisites

| Platform    | Requirements                                                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **All**     | *Rust 1.78+* ([https://rustup.rs](https://rustup.rs))                                                                                                               |
| **Linux**   | glibc ≥ 2.17, permissions to open the test path in read/write mode. <br>For direct‑I/O the filesystem must accept `O_DIRECT` (ext4, xfs, btrfs, etc.).              |
| **macOS**   | macOS 12+. Direct‑I/O not available (kernel rejects `O_DIRECT`).                                                                                                    |
| **Windows** | Windows 10 (1903)+, MSVC build chain. For direct‑I/O the volume must be NTFS and the process must run as Administrator or have the *SeManageVolumePrivilege* right. |

---

## 2  Building & Installing

### 2.1 Standard (buffered‑I/O) build

```bash
# Clone
$ git clone https://github.com/your-org/disk‑tester.git
$ cd disk‑tester

# Release build (optimised)
$ cargo build --release    # binary will be target/release/disk-tester
```

### 2.2 Enabling Direct I/O support

```bash
$ cargo build --release --features direct  # adds --direct-io flag at runtime
```

> **Note**  Direct‑I/O will refuse to run if the chosen `--block-size` is not a multiple of 512 bytes or if the memory buffer is not 4096‑byte aligned (the program does this for you when built with the feature).

### 2.3 Install system‑wide (optional)

```bash
$ install -Dm755 target/release/disk-tester /usr/local/bin/disk-tester   # Linux & macOS
# Or copy .exe somewhere in %PATH% on Windows
```

---

## 3  CLI Overview

The binary understands **six** sub‑commands (run with `--help` for the full syntax):

| Sub‑command    | Purpose                                                            |
| -------------- | ------------------------------------------------------------------ |
| `full-test`    | End‑to‑end write → read → verify of a contiguous region (default). |
| `read-sector`  | Dump a single logical sector to stdout/log.                        |
| `write-sector` | Overwrite one sector with a chosen pattern.                        |
| `range-read`   | Sequentially read a slice and optionally hex‑preview the data.     |
| `range-write`  | Fill a slice with the chosen pattern.                              |
| `verify-range` | Compare on‑disk data against an expected pattern.                  |

Common flags (global or per‑command):

```
--path <FILE|DIR>        Target test file or directory (default ./disk_test_file.bin)
--block-size <SIZE>      Logical sector size, accepts 4K, 1M, 512, etc. (default 4K)
--batch-size <SIZE>      Bytes processed per worker batch (default 1M)
--threads <N>            Worker thread count (default 1; I/O is single‑fd so >1 rarely helps)
--data-type <hex|text|binary|file|random>   Pattern generator (default binary)
--data-file <FILE>       Pattern source when --data-type file
--dual-pattern           Alternate between random and sequential data
--passes <1‑3>           Repeat full-test up to 3 times (default 1)
--resume-from-sector <S> Start offset inside existing file
--preallocate            posix_fallocate / SetFileInformationByHandle before test
--direct-io              Only present if compiled with `--features direct`
--verbose                Chatty logging
```

---

## 4  Quick Start Recipes

### 4.1 Minimal sanity check (buffered I/O)

```bash
$ disk-tester full-test --test-size 2G --threads 2
```

### 4.2 True device write/read at 4 KiB with Direct‑I/O

```bash
$ cargo build --release --features direct
$ sudo ./target/release/disk-tester full-test \
       --path /mnt/nvme/test.bin \
       --block-size 4K   --batch-size 4M \
       --test-size 10G   --direct-io --preallocate --verbose
```

### 4.3 Verify an existing image against a hex pattern

```bash
$ disk-tester verify-range --path /images/firmware.img \
       --start-sector 0 --end-sector 2048 --block-size 512 --data-type hex
```

---

## 5  Logging & Output

* **Progress bar** via `indicatif` (\<CTRL+C> safe).
* **Log file** `disk_test.log` contains every message with timestamps.
* **Test file** defaults to `disk_test_file.bin`; choose `--path` to change.

Errors (read/write mismatch, seek failure, etc.) are printed in‑line and appended to the log for post‑mortem analysis. The program exits non‑zero if any fatal or verification error is encountered.

---

## 6  Architecture Notes

1. **Single FD worker** – a background thread owns the file handle, eliminating seek contention.
2. **Ping‑pong buffer pool** – zero‑copy message passing to the worker.
3. **Pattern engine** – deterministic hex/text/binary tile or arbitrary byte blob.
4. **Direct‑I/O alignment** – `AlignedVec` provides 4096‑byte alignment when the `direct` feature is enabled.

---

## 7  Known Limitations / TODO

* No sparse‑file awareness: pre‑allocation equals full allocation on NTFS.
* macOS uses F_NOCACHE + F_RDAHEAD rather than true O_DIRECT.  It still
  bypasses the cache but may copy data one extra time in the kernel.
* SMB/NFS mounts may reject `O_DIRECT`/`FILE_FLAG_NO_BUFFERING`.
* No native checksum/hashing yet – mismatches are byte‑for‑byte.

---

© 2025 Alexander Klein / License MIT
