#!/usr/bin/env python3
import argparse
import sys
import os
import platform
import subprocess
import json
import shutil
import time
import datetime
import dataclasses

try:
    import usb_tool
    USB_TOOL_AVAILABLE = True
except Exception:
    usb_tool = None
    USB_TOOL_AVAILABLE = False

def get_platform_ioengine():
    system = platform.system()
    if system == 'Linux':
        return 'libaio'
    elif system == 'Windows':
        return 'windowsaio'
    else:
        return 'posixaio' # macOS and others

def check_fio_installed():
    if shutil.which('fio') is None:
        print("Error: 'fio' is not installed or not in PATH.")
        sys.exit(1)

def get_test_size(path, percentage=90):
    """
    Calculates the test size.
    If path is a directory, uses free space.
    If path is a file, uses its current size + free space of parent.
    Requirement: 'full disk size and set aside 10%'.
    We interpret this as 90% of *available* capacity (Free + Existing File).
    """
    # Determine directory to check usage on
    if os.path.isdir(path):
        check_dir = path
        existing_size = 0
    else:
        # It's a file path (existing or not)
        check_dir = os.path.dirname(os.path.abspath(path))
        if os.path.exists(path) and os.path.isfile(path):
            existing_size = os.path.getsize(path)
        else:
            existing_size = 0

    if not os.path.exists(check_dir):
        print(f"Error: Directory {check_dir} does not exist.")
        sys.exit(1)

    usage = shutil.disk_usage(check_dir)
    # Total available capacity for our test file is the current free space + what the file already occupies
    total_available_for_test = usage.free + existing_size
    return int(total_available_for_test * (percentage / 100.0))

def format_bytes(size):
    power = 2**10
    n = size
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    count = 0
    while n > power:
        n /= power
        count += 1
    return f"{n:.2f} {power_labels.get(count, 'P')}B"

def parse_size(size_text):
    if size_text is None:
        raise ValueError("size_text is required")
    s = size_text.strip().upper()
    if not s:
        raise ValueError("size_text is empty")
    multiplier = 1
    if s.endswith('G'):
        multiplier = 1024**3
        s = s[:-1]
    elif s.endswith('M'):
        multiplier = 1024**2
        s = s[:-1]
    elif s.endswith('K'):
        multiplier = 1024
        s = s[:-1]
    try:
        return int(float(s) * multiplier)
    except ValueError as exc:
        raise ValueError(f"Invalid size: {size_text}") from exc

def _truncate(text, limit=2000):
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + " ... [truncated]"

def _extract_json_block(text):
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start:end + 1]

def _load_fio_json(stdout, stderr):
    candidates = []
    if stdout and stdout.strip():
        candidates.append(("stdout", stdout))
    if stderr and stderr.strip():
        candidates.append(("stderr", stderr))

    for _, data in candidates:
        stripped = data.strip()
        if not stripped:
            continue
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            json_block = _extract_json_block(stripped)
            if json_block:
                try:
                    return json.loads(json_block)
                except json.JSONDecodeError:
                    pass

    raise ValueError("fio did not return valid JSON on stdout or stderr")

def _escape_fio_path(path):
    if platform.system() != "Windows":
        return path
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return path[0] + "\\:" + path[2:]
    return path

def _now_ts():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _log_line(message, log_handle=None, also_print=True):
    line = f"[{_now_ts()}] {message}"
    if also_print:
        print(line)
    if log_handle:
        log_handle.write(line + "\n")
        log_handle.flush()

def _log_json(label, payload, log_handle=None):
    if not log_handle:
        return
    try:
        serialized = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        serialized = json.dumps({"error": "unserializable fio json"})
    log_handle.write(f"[{_now_ts()}] {label} {serialized}\n")
    log_handle.flush()

def _apricorn_obj_to_dict(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return {"value": str(obj)}

def _collect_apricorn_info(target_path, log_handle):
    if not USB_TOOL_AVAILABLE:
        _log_line("Apricorn probe skipped: usb_tool not installed", log_handle)
        return
    try:
        devices = usb_tool.find_apricorn_device()
    except Exception as exc:
        _log_line(f"Apricorn probe failed: {exc}", log_handle)
        return
    if not devices:
        _log_line("Apricorn device not found", log_handle)
        return

    drive, _ = os.path.splitdrive(os.path.abspath(target_path))
    drive_letter = drive.rstrip("\\").rstrip(":").upper()
    matched = devices
    if drive_letter:
        matched = [
            d for d in devices
            if getattr(d, "driveLetter", "").rstrip(":").upper() == drive_letter
        ]

    payload = {
        "target_drive": drive_letter or "N/A",
        "devices": [_apricorn_obj_to_dict(d) for d in devices],
    }
    if drive_letter:
        payload["matched_devices"] = [_apricorn_obj_to_dict(d) for d in matched]

    _log_json("APRICORN_INFO", payload, log_handle)
    if drive_letter and not matched:
        _log_line(f"Apricorn device not matched for drive {drive_letter}", log_handle)

def run_fio_job(job_config, verbose=False, allow_errors=False):
    """
    Runs fio with the given configuration (list of arguments).
    Returns the JSON output.
    """
    cmd = ['fio', '--output-format=json'] + job_config

    if verbose:
        print(f"Running command: {' '.join(cmd)}")

    # We might want to stream output if not json, but we need json for parsing.
    # For long running jobs, we might want a progress bar.
    # fio has --eta=always, but capturing json and eta is tricky.
    # We'll rely on fio's own eta to stderr if we let it inherit stdout?
    # No, we need to capture stdout for JSON.
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if allow_errors:
            error_info = {
                "returncode": result.returncode,
                "stdout": _truncate(result.stdout),
                "stderr": _truncate(result.stderr),
            }
            try:
                parsed = _load_fio_json(result.stdout, result.stderr)
                return parsed, error_info
            except (ValueError, json.JSONDecodeError):
                return None, error_info
        print(f"Error running fio: exit code {result.returncode}")
        print(f"Stdout: {_truncate(result.stdout)}")
        print(f"Stderr: {_truncate(result.stderr)}")
        sys.exit(1)

    try:
        parsed = _load_fio_json(result.stdout, result.stderr)
        if allow_errors:
            return parsed, None
        return parsed
    except (ValueError, json.JSONDecodeError) as e:
        if allow_errors:
            error_info = {
                "returncode": result.returncode,
                "stdout": _truncate(result.stdout),
                "stderr": _truncate(result.stderr),
                "parse_error": str(e),
            }
            return None, error_info
        print(f"Error parsing fio JSON output: {e}")
        print(f"Stdout (truncated): {_truncate(result.stdout)}")
        print(f"Stderr (truncated): {_truncate(result.stderr)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Disk Tester (Python/fio)")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Global arguments (can be added to parent parser)
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--path', default='disk_test.dat', help="Target file path (default: disk_test.dat)")
    parent_parser.add_argument('--direct', action='store_true', default=True, help="Use direct I/O (default: True)")
    parent_parser.add_argument('--no-direct', dest='direct', action='store_false', help="Disable direct I/O")
    parent_parser.add_argument('--size', help="Override test size (e.g., 1G, 500M). Default is 90%% of free space.")
    parent_parser.add_argument('--log', default='disk_test.log', help="Log file path (default: disk_test.log)")
    parent_parser.add_argument('--no-log', dest='log', action='store_const', const=None, help="Disable file logging")
    parent_parser.add_argument('--apricorn', action='store_true', help="Query Apricorn USB device info (best-effort)")

    # Bench Command
    parser_bench = subparsers.add_parser('bench', parents=[parent_parser], help="Run Sequential and Random (Binary) benchmarks")

    # Stress Command
    parser_stress = subparsers.add_parser('stress', parents=[parent_parser], help="Run Reliability Full Stress Test")

    # Temp Command
    parser_temp = subparsers.add_parser('temp', parents=[parent_parser], help="Run Temperature Polling Test")
    parser_temp.add_argument('--interval', type=int, default=60, help="Cycle interval in seconds (default: 60)")
    parser_temp.add_argument('--duration', type=int, default=3600, help="Total duration in seconds (default: 3600)")

    args = parser.parse_args()

    check_fio_installed()

    # Resolve Path
    target_path = os.path.abspath(args.path)
    # If path is a directory, append default filename
    if os.path.isdir(target_path):
        target_path = os.path.join(target_path, 'disk_test.dat')

    log_handle = None
    if args.log:
        log_handle = open(args.log, "a", encoding="utf-8")

    _log_line("Starting Disk Tester...", log_handle)
    _log_line(f"Command: {args.command}", log_handle)
    _log_line(f"Target: {target_path}", log_handle)
    if args.apricorn:
        _collect_apricorn_info(target_path, log_handle)
    fio_target_path = _escape_fio_path(target_path)

    # Calculate Size (90% of free space) or use override
    # Note: For 'temp' test, we might not need full size, but consistent with other tests.
    if args.size:
        # Simple parse of size suffix
        test_size_bytes = parse_size(args.size)
        _log_line(f"Test Size: {format_bytes(test_size_bytes)} (User Override)", log_handle)
    else:
        test_size_bytes = get_test_size(target_path)
        _log_line(f"Test Size: {format_bytes(test_size_bytes)} (90% of available)", log_handle)

    # Common FIO settings
    ioengine = get_platform_ioengine()
    common_args = [
        f"--filename={fio_target_path}",
        f"--ioengine={ioengine}",
        f"--direct={1 if args.direct else 0}",
        f"--size={test_size_bytes}",
        "--group_reporting",
        "--name=disk_test"
    ]

    if args.command == 'bench':
        # Sequential Read
        _log_line("Running Sequential Read (1M)", log_handle)
        job = common_args + ["--rw=read", "--bs=1M"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['read']['bw'] / 1024 # MiB/s
        iops = res['jobs'][0]['read']['iops']
        _log_line(f"Seq Read: {bw:.2f} MiB/s, {iops:.0f} IOPS", log_handle)

        # Sequential Write
        _log_line("Running Sequential Write (1M)", log_handle)
        job = common_args + ["--rw=write", "--bs=1M"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['write']['bw'] / 1024
        iops = res['jobs'][0]['write']['iops']
        _log_line(f"Seq Write: {bw:.2f} MiB/s, {iops:.0f} IOPS", log_handle)

        # Random Read (Binary)
        _log_line("Running Random Read (4k)", log_handle)
        job = common_args + ["--rw=randread", "--bs=4k"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['read']['bw'] / 1024
        iops = res['jobs'][0]['read']['iops']
        _log_line(f"Rand Read: {bw:.2f} MiB/s, {iops:.0f} IOPS", log_handle)

        # Random Write (Binary)
        _log_line("Running Random Write (4k)", log_handle)
        job = common_args + ["--rw=randwrite", "--bs=4k"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['write']['bw'] / 1024
        iops = res['jobs'][0]['write']['iops']
        _log_line(f"Rand Write: {bw:.2f} MiB/s, {iops:.0f} IOPS", log_handle)

    elif args.command == 'stress':
        _log_line("Running Reliability Full Stress Test", log_handle)
        # Reliability: Write then Verify
        # We can use rw=write with verify=crc32c
        job = common_args + [
            "--rw=write",
            "--bs=1M",
            "--verify=crc32c",
            "--do_verify=1",
            "--verify_dump=1", # Dump on mismatch
            "--verify_fatal=1" # Stop on error
        ]
        _log_line("Writing and Verifying full test area... this may take a while.", log_handle)
        # For stress test, we might want to stream output or just wait.
        # Since we use capture_output, the user won't see progress.
        # We could use a poll loop or just trust the user to wait.
        # Given "scaffold", the original tool had a progress bar.
        # For now, print start and wait.
        start_time = time.time()
        res = run_fio_job(job, verbose=True)
        duration = time.time() - start_time

        write_bw = res['jobs'][0]['write']['bw'] / 1024
        errs = res['jobs'][0]['error']
        _log_line(f"Completed in {duration:.2f}s", log_handle)
        _log_line(f"Write Speed: {write_bw:.2f} MiB/s", log_handle)
        _log_line(f"Errors: {errs}", log_handle)

        if errs == 0:
            _log_line("Reliability Test Passed: No errors detected.", log_handle)
        else:
            _log_line("Reliability Test FAILED.", log_handle)
            sys.exit(1)

    elif args.command == 'temp':
        _log_line("Running Temperature Polling Test", log_handle)
        _log_line(f"Duration: {args.duration}s, Interval: {args.interval}s", log_handle)
        _log_line("Mode: Periodic Random/Sequential bursts to heat disk without cache exhaust.", log_handle)

        end_time = time.time() + args.duration

        while time.time() < end_time:
            cycle_start = time.time()
            _log_line("Starting Load Burst", log_handle)

            # Run short burst: 50% Random, 50% Sequential
        

            # We need to override size to be time based, or small enough.
            # Use --time_based --runtime=5

            burst_args = [
                f"--filename={fio_target_path}",
                f"--ioengine={ioengine}",
                f"--direct={1 if args.direct else 0}",
                f"--size={test_size_bytes}", # Still define region
                "--group_reporting",
                "--name=temp_burst",
                "--time_based",
                "--runtime=5"
            ]

            # Seq Write Burst
            _log_line("Sequential Write Burst (5s)", log_handle)
            res, err = run_fio_job(
                burst_args + ["--rw=write", "--bs=1M"],
                allow_errors=True
            )
            if res:
                _log_json("FIO_JSON seq_write", res, log_handle)
            if err:
                _log_json("FIO_ERROR seq_write", err, log_handle)

            # Random Write Burst
            _log_line("Random Write Burst (5s)", log_handle)
            res, err = run_fio_job(
                burst_args + ["--rw=randwrite", "--bs=4k"],
                allow_errors=True
            )
            if res:
                _log_json("FIO_JSON rand_write", res, log_handle)
            if err:
                _log_json("FIO_ERROR rand_write", err, log_handle)

            # Wait for remainder of interval
            elapsed = time.time() - cycle_start
            sleep_time = max(0, args.interval - elapsed)
            _log_line(f"Sleeping for {sleep_time:.2f}s", log_handle)
            time.sleep(sleep_time)

    
    _log_line(f"Test Complete. File '{target_path}' preserved for future runs.", log_handle)
    if log_handle:
        log_handle.close()

if __name__ == "__main__":
    main()
