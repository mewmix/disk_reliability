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
import re

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

def get_fio_version():
    try:
        result = subprocess.run(
            ["fio", "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        return "unknown"
    output = (result.stdout or result.stderr or "").strip()
    return output or "unknown"

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

def _log_fio_summary(label, fio_json, log_handle=None):
    if not fio_json:
        return
    try:
        job = fio_json["jobs"][0]
    except (KeyError, IndexError, TypeError):
        return
    metrics = {}
    if "read" in job:
        metrics["read"] = job["read"]
    if "write" in job:
        metrics["write"] = job["write"]
    if not metrics:
        return
    for op, data in metrics.items():
        bw_mib = data.get("bw", 0) / 1024
        iops = data.get("iops", 0)
        if bw_mib == 0 and iops == 0:
            continue
        clat_ns = data.get("clat_ns", {}).get("mean")
        clat_ms = (clat_ns / 1_000_000) if clat_ns else None
        if clat_ms is None:
            _log_line(f"{label} {op}: {bw_mib:.2f} MiB/s, {iops:.0f} IOPS", log_handle)
        else:
            _log_line(
                f"{label} {op}: {bw_mib:.2f} MiB/s, {iops:.0f} IOPS, clat_avg={clat_ms:.2f} ms",
                log_handle,
            )

def _sanitize_filename_component(value):
    if value is None:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value)).strip("_")
    return cleaned

def _timestamp_for_filename():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def _resolve_target_path(path):
    normalized = os.path.abspath(path)
    drive, tail = os.path.splitdrive(normalized)
    if os.path.isdir(normalized):
        return os.path.join(normalized, "disk_test.dat")
    if drive and tail in ("", "\\", "/"):
        return os.path.join(drive + "\\", "disk_test.dat")
    if normalized.endswith(":"):
        return normalized + "\\disk_test.dat"
    return normalized

def _ensure_file_size(path, size_bytes, log_handle=None):
    try:
        if os.path.isdir(path):
            path = os.path.join(path, "disk_test.dat")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "ab"):
            pass
        current = os.path.getsize(path)
        if current < size_bytes:
            with open(path, "r+b") as handle:
                handle.truncate(size_bytes)
            _log_line(
                f"Preallocated temp file to {format_bytes(size_bytes)}",
                log_handle,
            )
    except Exception as exc:
        _log_line(f"Temp file preallocation failed: {exc}", log_handle)

def _is_transient_io_error(err):
    if not err:
        return False
    stderr = (err.get("stderr") or "").lower()
    return "resource temporarily unavailable" in stderr or "error=11" in stderr

def _run_temp_burst(label, category, burst_args, rw, bs, log_handle):
    _log_line(f"{label} Burst (5s)", log_handle)
    res, err = run_fio_job(
        burst_args + [f"--rw={rw}", f"--bs={bs}"],
        allow_errors=True
    )
    if err and _is_transient_io_error(err):
        _log_line(
            f"{label} burst hit transient I/O error; retrying with sync engine",
            log_handle,
        )
        fallback_args = [
            arg for arg in burst_args
            if not arg.startswith("--ioengine=") and not arg.startswith("--direct=")
        ]
        fallback_args += ["--ioengine=sync", "--direct=0"]
        res, err = run_fio_job(
            fallback_args + [f"--rw={rw}", f"--bs={bs}"],
            allow_errors=True
        )

    if res:
        _log_json(f"FIO_JSON {rw}", res, log_handle)
        _log_fio_summary(category, res, log_handle)
    if err:
        _log_json(f"FIO_ERROR {rw}", err, log_handle)
    return res, err

def _prompt_failure_action():
    while True:
        choice = input("Failure detected. [R]etry temp test or [E]xit? ").strip().lower()
        if choice in ("r", "retry"):
            return "retry"
        if choice in ("e", "exit"):
            return "exit"

def _apricorn_obj_to_dict(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return {"value": str(obj)}

def _extract_apricorn_serial(device):
    if device is None:
        return None
    for attr in ("serial", "serialNumber", "serial_number", "serialNo", "serial_no"):
        value = getattr(device, attr, None)
        if value:
            return str(value)
    data = _apricorn_obj_to_dict(device)
    for key, value in data.items():
        if "serial" in str(key).lower() and value:
            return str(value)
    return None

def _extract_apricorn_firmware(device):
    if device is None:
        return None
    for attr in ("firmware", "firmwareVersion", "firmware_version", "firmwareRev", "firmware_rev"):
        value = getattr(device, attr, None)
        if value:
            return str(value)
    data = _apricorn_obj_to_dict(device)
    for key, value in data.items():
        if "firmware" in str(key).lower() and value:
            return str(value)
    return None

def _extract_apricorn_model(device):
    if device is None:
        return None
    for attr in ("model", "modelNumber", "model_number", "product", "productName"):
        value = getattr(device, attr, None)
        if value:
            return str(value)
    data = _apricorn_obj_to_dict(device)
    for key, value in data.items():
        if "model" in str(key).lower() and value:
            return str(value)
    return None

def _is_unknown_value(value):
    if value is None:
        return True
    text = str(value).strip()
    return not text or text.lower() in ("n/a", "na", "none", "unknown")

def _probe_apricorn(target_path):
    if not USB_TOOL_AVAILABLE:
        return None
    try:
        devices = usb_tool.find_apricorn_device()
    except Exception as exc:
        return {"status": "error", "message": f"Apricorn probe failed: {exc}"}
    if not devices:
        return {"status": "not_found", "message": "Apricorn device not found"}

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

    serial = None
    if matched:
        serial = _extract_apricorn_serial(matched[0])
    if not serial:
        serial = _extract_apricorn_serial(devices[0])

    return {
        "status": "ok",
        "payload": payload,
        "drive_letter": drive_letter,
        "matched": matched,
        "serial": serial,
    }

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

    # Bench Command
    parser_bench = subparsers.add_parser('bench', parents=[parent_parser], help="Run Sequential and Random (Binary) benchmarks")

    # Stress Command
    parser_stress = subparsers.add_parser('stress', parents=[parent_parser], help="Run Reliability Full Stress Test")

    # Temp Command
    parser_temp = subparsers.add_parser('temp', parents=[parent_parser], help="Run Temperature Polling Test")
    parser_temp.add_argument('--interval', type=int, default=60, help="Cycle interval in seconds (default: 60)")
    parser_temp.add_argument('--duration', type=int, default=0, help="Total duration in seconds (0 = until failure)")

    args = parser.parse_args()

    check_fio_installed()

    # Resolve Path
    target_path = _resolve_target_path(args.path)

    apricorn_result = _probe_apricorn(target_path)

    log_handle = None
    log_path = args.log
    if log_path and apricorn_result and apricorn_result.get("status") == "ok":
        serial = _sanitize_filename_component(apricorn_result.get("serial"))
        if serial:
            base, ext = os.path.splitext(log_path)
            log_path = f"{base}_{serial}_{_timestamp_for_filename()}{ext}"
    if log_path:
        log_handle = open(log_path, "a", encoding="utf-8")

    _log_line(f"Starting {get_fio_version()}", log_handle)
    _log_line(
        f"Platform: {platform.system()} {platform.release()} ({platform.machine()})",
        log_handle,
    )
    _log_line(f"Python: {sys.version.split()[0]}", log_handle)
    _log_line(f"Target: {target_path}", log_handle)
    try:
        capacity_dir = target_path if os.path.isdir(target_path) else os.path.dirname(target_path)
        if capacity_dir and os.path.exists(capacity_dir):
            usage = shutil.disk_usage(capacity_dir)
            _log_line(
                f"Capacity: total={format_bytes(usage.total)}, free={format_bytes(usage.free)}",
                log_handle,
            )
    except Exception as exc:
        _log_line(f"Capacity probe failed: {exc}", log_handle)
    if apricorn_result:
        status = apricorn_result.get("status")
        if status == "error":
            _log_line(apricorn_result.get("message", "Apricorn probe failed"), log_handle)
        elif status == "not_found":
            _log_line(apricorn_result.get("message", "Apricorn device not found"), log_handle)
        elif status == "ok":
            device = None
            matched = apricorn_result.get("matched") or []
            if matched:
                device = matched[0]
            else:
                devices = apricorn_result.get("payload", {}).get("devices") or []
                if devices:
                    device = devices[0]
            serial = _extract_apricorn_serial(device)
            firmware = _extract_apricorn_firmware(device)
            model = _extract_apricorn_model(device)
            if not _is_unknown_value(serial):
                _log_line(f"Apricorn DUT Serial = {serial}", log_handle)
            if not _is_unknown_value(firmware):
                _log_line(f"Apricorn DUT Firmware = {firmware}", log_handle)
            if not _is_unknown_value(model):
                _log_line(f"Apricorn DUT Model = {model}", log_handle)
            _log_json("APRICORN_INFO", apricorn_result.get("payload"), log_handle)
            drive_letter = apricorn_result.get("drive_letter")
            if drive_letter and not matched:
                _log_line(f"Apricorn device not matched for drive {drive_letter}", log_handle)
    fio_target_path = _escape_fio_path(target_path)

    # Calculate Size (90% of free space) or use override.
    # For 'temp' test, avoid reserving most of the device by default.
    if args.size:
        test_size_bytes = parse_size(args.size)
        if args.command == "temp":
            _log_line(
                f"Test Size: {format_bytes(test_size_bytes)} (User Override, address range only)",
                log_handle,
            )
        else:
            _log_line(f"Test Size: {format_bytes(test_size_bytes)} (User Override)", log_handle)
    else:
        if args.command == "temp":
            if os.path.exists(target_path) and os.path.isfile(target_path):
                test_size_bytes = os.path.getsize(target_path)
                if test_size_bytes <= 0:
                    test_size_bytes = 1024**3
            else:
                test_size_bytes = 1024**3
            _log_line(
                f"Test Size: {format_bytes(test_size_bytes)}",
                log_handle,
            )
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
        if args.duration:
            _log_line(f"Duration: {args.duration}s, Interval: {args.interval}s", log_handle)
        else:
            _log_line(f"Duration: until failure, Interval: {args.interval}s", log_handle)
        _log_line("Mode: Continuous Random/Sequential read/write bursts.", log_handle)

        _ensure_file_size(target_path, test_size_bytes, log_handle)

        end_time = time.time() + args.duration if args.duration else None

        while end_time is None or time.time() < end_time:
            cycle_start = time.time()
            _log_line("Starting Load Burst", log_handle)

            # Run short burst: sequential + random, read + write.

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
            res, err = _run_temp_burst("Sequential Write", "SEQUENTIAL", burst_args, "write", "1M", log_handle)
            if err:
                _log_line("Failure detected during seq_write.", log_handle)
                action = _prompt_failure_action()
                if action == "retry":
                    continue
                break

            # Seq Read Burst
            res, err = _run_temp_burst("Sequential Read", "SEQUENTIAL", burst_args, "read", "1M", log_handle)
            if err:
                _log_line("Failure detected during seq_read.", log_handle)
                action = _prompt_failure_action()
                if action == "retry":
                    continue
                break

            # Random Write Burst
            res, err = _run_temp_burst("Random Write", "RANDOM", burst_args, "randwrite", "4k", log_handle)
            if err:
                _log_line("Failure detected during rand_write.", log_handle)
                action = _prompt_failure_action()
                if action == "retry":
                    continue
                break

            # Random Read Burst
            res, err = _run_temp_burst("Random Read", "RANDOM", burst_args, "randread", "4k", log_handle)
            if err:
                _log_line("Failure detected during rand_read.", log_handle)
                action = _prompt_failure_action()
                if action == "retry":
                    continue
                break

            # No idle sleep; run continuously to keep the drive busy.

    
    _log_line("Test Complete.", log_handle)
    if log_handle:
        log_handle.close()

if __name__ == "__main__":
    main()
