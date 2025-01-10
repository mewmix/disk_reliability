//! src/main.rs
//! A cross-platform disk reliability testing tool in Rust.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Instant;
use std::env;

// Add the ctrlc crate to handle Ctrl+C gracefully
use ctrlc;

// -- For a progress bar
use indicatif::{ProgressBar, ProgressStyle};

/// Default constants
const DEFAULT_BLOCK_SIZE: usize = 4096;            // 4 KiB
const DEFAULT_TEST_THREADS: usize = 4;             // concurrency
const TEST_FILE_NAME: &str = "disk_test_file.bin"; // default file name

// A global atomic flag to signal the threads to stop if there's an interrupt
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

fn main() -> io::Result<()> {
    // Set up a Ctrl+C handler to ensure we clean up gracefully
    setup_signal_handler();

    // Parse CLI arguments
    let args: Vec<String> = env::args().collect();

    // Option: path to the file or directory
    let path = get_arg_value(&args, "--path").unwrap_or_else(|| TEST_FILE_NAME.to_string());
    let path = Path::new(&path);

    // Number of test threads
    let num_threads = get_arg_value(&args, "--threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TEST_THREADS);

    // Block size
    let block_size = get_arg_value(&args, "--block-size")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_BLOCK_SIZE);

    // Start sector
    let start_sector = get_arg_value(&args, "--start-sector")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    // End sector (optional)
    let end_sector = get_arg_value(&args, "--end-sector")
        .and_then(|v| v.parse::<u64>().ok());

    // Data pattern (random vs. sequential)
    let use_random = args.contains(&"--random".to_string());

    // Print out settings
    println!("Disk Tester Configuration:");
    println!("  File path:      {}", path.display());
    println!("  Threads:        {}", num_threads);
    println!("  Block size:     {} bytes", block_size);
    println!("  Start sector:   {}", start_sector);
    if let Some(es) = end_sector {
        println!("  End sector:     {}", es);
    }
    println!("  Data pattern:   {}", if use_random { "Random" } else { "Sequential" });

    // Get free space (in bytes)
    let free_space = get_free_space(path)?;
    println!("  Free space:     {} bytes available", free_space);

    // Determine our final file path
    let file_path = if path.is_dir() {
        // If `path` is a directory, append the test file name
        path.join(TEST_FILE_NAME)
    } else {
        // Otherwise, assume it's a file
        path.to_path_buf()
    };

    // Open or create the test file
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true) // create if not exists
        .open(&file_path)?;

    // Decide how many bytes to test
    let total_bytes = if let Some(es) = end_sector {
        let sectors_count = es.saturating_sub(start_sector);
        (sectors_count as usize) * block_size
    } else {
        free_space as usize
    };

    println!("  Total bytes to test: {}", total_bytes);

    // Allocate the test file size (often sparse on many OSes)
    file.set_len(total_bytes as u64)?;

    // How many blocks / chunks to write-read-verify
    let total_chunks = total_bytes / block_size;

    // Share file handle via Arc<Mutex<...>>
    let file_arc = Arc::new(Mutex::new(file));

    // ------------------------------------------------------------------------
    // NEW: Open or create a log file to record each sector's verification
    // ------------------------------------------------------------------------
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("disk_test.log")?;

    // We'll share this log file across threads
    let log_file_arc = Arc::new(Mutex::new(log_file));
    {
        // Write a small header so we know a new run started
        let mut lf = log_file_arc.lock().unwrap();
        writeln!(lf, "==== New disk test run started ====").ok();
        lf.flush().ok();
    }

    // A progress bar to show overall progress
    let pb = ProgressBar::new(total_chunks as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({eta})"
        )
        .unwrap(),
    );

    // Start timing
    let start_time = Instant::now();

    // Spawn threads
    let mut handles = Vec::with_capacity(num_threads);
    for thread_idx in 0..num_threads {
        // Clone references for move into thread
        let file_clone = Arc::clone(&file_arc);
        let log_file_clone = Arc::clone(&log_file_arc);
        let pb_clone = pb.clone();

        let handle = thread::spawn(move || {
            let mut buffer = vec![0u8; block_size];
            let mut read_buffer = vec![0u8; block_size];

            let mut chunk_idx = thread_idx;
            while chunk_idx < total_chunks && !STOP_REQUESTED.load(Ordering::SeqCst) {
                // Sector offset
                let offset_sector = start_sector + chunk_idx as u64;
                let offset_bytes = offset_sector * block_size as u64;

                // Generate data
                if use_random {
                    // pseudo-random pattern
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        *byte = ((chunk_idx + i) % 256) as u8;
                    }
                } else {
                    // sequential pattern
                    for (i, byte) in buffer.iter_mut().enumerate() {
                        *byte = (i % 256) as u8;
                    }
                }

                // Lock and write/read
                {
                    let mut file = file_clone.lock().unwrap();

                    // Write
                    if file.seek(SeekFrom::Start(offset_bytes)).is_ok() {
                        if let Err(e) = file.write_all(&buffer) {
                            eprintln!("Error writing at sector {}: {}", offset_sector, e);
                            // Log the error in the log file
                            let mut lf = log_file_clone.lock().unwrap();
                            writeln!(lf, "[THREAD {}] Error writing at sector {}: {}", 
                                thread_idx, offset_sector, e).ok();
                            lf.flush().ok();
                            break;
                        }
                    } else {
                        eprintln!("Seek error before writing at sector {}", offset_sector);
                        let mut lf = log_file_clone.lock().unwrap();
                        writeln!(lf, "[THREAD {}] Seek error before writing sector {}", 
                            thread_idx, offset_sector).ok();
                        lf.flush().ok();
                        break;
                    }

                    // Read
                    if file.seek(SeekFrom::Start(offset_bytes)).is_ok() {
                        if let Err(e) = file.read_exact(&mut read_buffer) {
                            eprintln!("Error reading at sector {}: {}", offset_sector, e);
                            // Log the error in the log file
                            let mut lf = log_file_clone.lock().unwrap();
                            writeln!(lf, "[THREAD {}] Error reading at sector {}: {}", 
                                thread_idx, offset_sector, e).ok();
                            lf.flush().ok();
                            break;
                        }
                    } else {
                        eprintln!("Seek error before reading at sector {}", offset_sector);
                        let mut lf = log_file_clone.lock().unwrap();
                        writeln!(lf, "[THREAD {}] Seek error before reading sector {}", 
                            thread_idx, offset_sector).ok();
                        lf.flush().ok();
                        break;
                    }
                } // lock released

                // Verify
                if buffer != read_buffer {
                    eprintln!("Data mismatch at sector {}!", offset_sector);
                    // Log the mismatch in the log file
                    let mut lf = log_file_clone.lock().unwrap();
                    writeln!(lf, "[THREAD {}] Data mismatch at sector {}!", 
                        thread_idx, offset_sector).ok();
                    lf.flush().ok();
                } else {
                    // Log each successful sector
                    let mut lf = log_file_clone.lock().unwrap();
                    writeln!(lf, "[THREAD {}] Sector {} verified OK", 
                        thread_idx, offset_sector).ok();
                    lf.flush().ok();
                }

                // Update progress
                pb_clone.inc(1);

                // Next chunk for this thread (round-robin stepping)
                chunk_idx += num_threads;
            }
        });

        handles.push(handle);
    }

    // Wait for all threads
    for handle in handles {
        if let Err(e) = handle.join() {
            eprintln!("Thread panicked: {:?}", e);
            // We can also log this panic
            let mut lf = log_file_arc.lock().unwrap();
            writeln!(lf, "A thread panicked: {:?}", e).ok();
            lf.flush().ok();
        }
    }

    // Finish progress bar
    pb.finish_and_clear();

    let duration = start_time.elapsed();
    println!("Disk test completed in {:?}", duration);

    // We can also log the completion time
    {
        let mut lf = log_file_arc.lock().unwrap();
        writeln!(lf, "Disk test completed in {:?}", duration).ok();
        lf.flush().ok();
    }

    Ok(())
}

/// Handle Ctrl+C so we stop gracefully.
fn setup_signal_handler() {
    // Using the ctrlc crate
    ctrlc::set_handler(move || {
        eprintln!("Received Ctrl+C! Requesting all threads to stop...");
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");
}

/// Retrieve a CLI argument value by key.
/// e.g. `--threads 8` -> get_arg_value(args, "--threads") => Some("8".into())
fn get_arg_value(args: &[String], key: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|x| x == key) {
        return args.get(pos + 1).cloned();
    }
    None
}

// =============================================================================
// APPROACH B: Minimal, purely in std, using conditional compilation
// =============================================================================

#[cfg(target_family = "unix")]
fn get_free_space(path: &std::path::Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::mem;
    use std::os::raw::c_int;
    use std::os::unix::ffi::OsStrExt;
    use libc; // bring the `libc` crate into scope

    // We'll call statvfs
    extern "C" {
        fn statvfs(path: *const i8, buf: *mut libc::statvfs) -> c_int;
    }

    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut stat: libc::statvfs = unsafe { mem::zeroed() };

    let ret = unsafe { statvfs(c_path.as_ptr(), &mut stat as *mut _) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    // Available blocks * block size
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(target_family = "windows")]
fn get_free_space(path: &std::path::Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt; // For encode_wide()
    use winapi::shared::minwindef::BOOL;
    use winapi::um::fileapi::GetDiskFreeSpaceExW; // Correct import for GetDiskFreeSpaceExW
    use winapi::um::winnt::ULARGE_INTEGER;         // Correct import for ULARGE_INTEGER

    // Convert path to wide string
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if !wide.is_empty() && wide[wide.len() - 1] != 0 {
        wide.push(0);
    }

    let mut free_bytes_available: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    let mut total_number_of_bytes: ULARGE_INTEGER = unsafe { std::mem::zeroed() };
    let mut total_number_of_free_bytes: ULARGE_INTEGER = unsafe { std::mem::zeroed() };

    let res: BOOL = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes_available,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    };
    if res == 0 {
        return Err(io::Error::last_os_error());
    }

    // Convert ULARGE_INTEGER to u64
    Ok(unsafe { *(&free_bytes_available as *const _ as *const u64) })
}
