# Cross-Platform Disk Reliability Testing Tool

## Objective
The tool performs read/write/verify operations to test the integrity of storage devices across different platforms, including macOS, Linux, and Windows. It supports concurrent operations with multiple threads and provides real-time progress updates through a progress bar. It also logs errors and successful operations for post-run analysis.

---

## Features
1. **Cross-Platform Compatibility**:
   - Supports macOS, Linux, and Windows.
2. **Customizable Testing**:
   - Adjustable block sizes, threads, and data patterns.
3. **Real-Time Progress Updates**:
   - Visual progress bar for monitoring test status.
4. **Logging**:
   - Logs errors and sector verification results to `disk_test.log`.
5. **Graceful Interruption**:
   - Handles Ctrl+C to stop tests cleanly.

---

## Usage
Run the tool with the following customizable options:

### Command-Line Options
- `--path <file_or_directory>`: Path to the file or directory for testing. Default: `disk_test_file.bin`.
- `--threads <number>`: Number of concurrent threads for testing. Default: `4`.
- `--block-size <bytes>`: Size of each read/write block in bytes. Default: `4096` (4 KiB).
- `--start-sector <sector>`: Starting sector for testing. Default: `0`.
- `--end-sector <sector>`: Ending sector for testing. If omitted, tests until free space is exhausted.
- `--random`: Use random data patterns instead of sequential patterns.

### Example Commands
1. Basic Test:
   ```sh
   ./disk_tester
   ```

2. Custom Test with 8 Threads and 1 MiB Blocks:
   ```sh
   ./disk_tester --threads 8 --block-size 1048576
   ```

3. Test Specific Sectors:
   ```sh
   ./disk_tester --start-sector 1000 --end-sector 2000
   ```

4. Use Random Data Patterns:
   ```sh
   ./disk_tester --random
   ```

---

## How It Works

### Initialization
1. Parses CLI arguments for configuration.
2. Sets up a Ctrl+C handler to ensure clean interruption.
3. Validates the path and calculates free space.
4. Allocates or creates the test file with the specified size.

### Multi-Threaded Operations
1. Spawns threads to perform read/write/verify cycles concurrently.
2. Each thread:
   - Writes data to a specified block.
   - Reads data back and verifies its integrity.
   - Logs results for each sector.

### Logging
- Logs errors and verification results in `disk_test.log`.
- Includes timestamps and thread-specific information.

### Progress Tracking
- Displays real-time progress using a progress bar.

### Termination
- Handles Ctrl+C to stop all threads gracefully and logs the termination.

---

## Output Files
- **Test File**: `disk_test_file.bin` (or specified file name)
- **Log File**: `disk_test.log`

---

## Platform-Specific Notes

### macOS/Linux
- Uses the `statvfs` system call to determine free space.
- Requires appropriate permissions to write to the specified path.

### Windows
- Uses the `GetDiskFreeSpaceExW` API for free space calculation.
- Ensure the path is accessible with the necessary permissions.

---

## Dependencies
- **Rust Crates**:
  - `ctrlc`: Handles Ctrl+C signal gracefully.
  - `indicatif`: Provides a progress bar.
  - `libc` (macOS/Linux): For system calls.
  - `winapi` (Windows): For disk space retrieval.

---

## Error Handling
- Logs errors (e.g., read/write mismatches, seek errors) with detailed messages.
- Stops operations on critical errors while continuing other threads.



