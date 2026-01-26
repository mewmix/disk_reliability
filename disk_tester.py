#!/usr/bin/env python3
import argparse
import sys
import os
import platform
import subprocess
import json
import shutil
import time

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

def run_fio_job(job_config, verbose=False):
    """
    Runs fio with the given configuration (list of arguments).
    Returns the JSON output.
    """
    cmd = ['fio', '--output-format=json'] + job_config

    if verbose:
        print(f"Running command: {' '.join(cmd)}")

    try:
        # We might want to stream output if not json, but we need json for parsing.
        # For long running jobs, we might want a progress bar.
        # fio has --eta=always, but capturing json and eta is tricky.
        # We'll rely on fio's own eta to stderr if we let it inherit stdout?
        # No, we need to capture stdout for JSON.
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error running fio: {e}")
        print(f"Stderr: {e.stderr}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing fio JSON output: {e}")
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

    print(f"Target: {target_path}")

    # Calculate Size (90% of free space) or use override
    # Note: For 'temp' test, we might not need full size, but consistent with other tests.
    if args.size:
        # Simple parse of size suffix
        s = args.size.upper()
        if s.endswith('G'):
            test_size_bytes = int(float(s[:-1]) * 1024**3)
        elif s.endswith('M'):
            test_size_bytes = int(float(s[:-1]) * 1024**2)
        elif s.endswith('K'):
            test_size_bytes = int(float(s[:-1]) * 1024)
        else:
            test_size_bytes = int(s)
        print(f"Test Size: {format_bytes(test_size_bytes)} (User Override)")
    else:
        test_size_bytes = get_test_size(target_path)
        print(f"Test Size: {format_bytes(test_size_bytes)} (90% of available)")

    # Common FIO settings
    ioengine = get_platform_ioengine()
    common_args = [
        f"--filename={target_path}",
        f"--ioengine={ioengine}",
        f"--direct={1 if args.direct else 0}",
        f"--size={test_size_bytes}",
        "--group_reporting",
        "--name=disk_test"
    ]

    if args.command == 'bench':
        # Sequential Read
        print("\n--- Running Sequential Read (1M) ---")
        job = common_args + ["--rw=read", "--bs=1M"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['read']['bw'] / 1024 # MiB/s
        iops = res['jobs'][0]['read']['iops']
        print(f"Seq Read: {bw:.2f} MiB/s, {iops:.0f} IOPS")

        # Sequential Write
        print("\n--- Running Sequential Write (1M) ---")
        job = common_args + ["--rw=write", "--bs=1M"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['write']['bw'] / 1024
        iops = res['jobs'][0]['write']['iops']
        print(f"Seq Write: {bw:.2f} MiB/s, {iops:.0f} IOPS")

        # Random Read (Binary)
        print("\n--- Running Random Read (4k) ---")
        job = common_args + ["--rw=randread", "--bs=4k"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['read']['bw'] / 1024
        iops = res['jobs'][0]['read']['iops']
        print(f"Rand Read: {bw:.2f} MiB/s, {iops:.0f} IOPS")

        # Random Write (Binary)
        print("\n--- Running Random Write (4k) ---")
        job = common_args + ["--rw=randwrite", "--bs=4k"]
        res = run_fio_job(job)
        bw = res['jobs'][0]['write']['bw'] / 1024
        iops = res['jobs'][0]['write']['iops']
        print(f"Rand Write: {bw:.2f} MiB/s, {iops:.0f} IOPS")

    elif args.command == 'stress':
        print("\n--- Running Reliability Full Stress Test ---")
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
        print("Writing and Verifying full test area... this may take a while.")
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
        print(f"\nCompleted in {duration:.2f}s")
        print(f"Write Speed: {write_bw:.2f} MiB/s")
        print(f"Errors: {errs}")

        if errs == 0:
            print("Reliability Test Passed: No errors detected.")
        else:
            print("Reliability Test FAILED.")
            sys.exit(1)

    elif args.command == 'temp':
        print("\n--- Running Temperature Polling Test ---")
        print(f"Duration: {args.duration}s, Interval: {args.interval}s")
        print("Mode: Periodic Random/Sequential bursts to heat disk without cache exhaust.")

        end_time = time.time() + args.duration

        while time.time() < end_time:
            cycle_start = time.time()
            print(f"\n[Time: {time.strftime('%H:%M:%S')}] Starting Load Burst...")

            # Run short burst: 50% Random, 50% Sequential?
            # User said "random and sequential workloads".
            # We'll do a mixed workload or split.
            # Let's do 5 seconds of Seq Write, 5 seconds of Rand Write.

            # We need to override size to be time based, or small enough.
            # Use --time_based --runtime=5

            burst_args = [
                f"--filename={target_path}",
                f"--ioengine={ioengine}",
                f"--direct={1 if args.direct else 0}",
                f"--size={test_size_bytes}", # Still define region
                "--group_reporting",
                "--name=temp_burst",
                "--time_based",
                "--runtime=5"
            ]

            # Seq Write Burst
            print("  > Sequential Write Burst (5s)...")
            run_fio_job(burst_args + ["--rw=write", "--bs=1M"])

            # Random Write Burst
            print("  > Random Write Burst (5s)...")
            run_fio_job(burst_args + ["--rw=randwrite", "--bs=4k"])

            # Wait for remainder of interval
            elapsed = time.time() - cycle_start
            sleep_time = max(0, args.interval - elapsed)
            print(f"  > Sleeping for {sleep_time:.2f}s (Poll temp now)...")
            time.sleep(sleep_time)

    # Cleanup (Optional? Usually testers leave the file, or clean it up. The Rust tool had a --passes option that deleted it)
    # I will leave the file for now as re-allocating 90% of disk takes time.
    print(f"\nTest Complete. File '{target_path}' preserved for future runs.")

if __name__ == "__main__":
    main()
