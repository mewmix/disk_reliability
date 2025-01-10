//! src/main.rs
//! A cross-platform disk reliability testing tool in Rust.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use std::env;

// -- For a progress bar
use indicatif::{ProgressBar, ProgressStyle};

/// Default constants
const DEFAULT_BLOCK_SIZE: usize = 4096;            // 4 KiB
const DEFAULT_TEST_THREADS: usize = 4;             // concurrency
const TEST_FILE_NAME: &str = "disk_test_file.bin"; // default file name

fn main() -> io::Result<()> {
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

    // A progress bar to show overall progress
    let pb = ProgressBar::new(total_chunks as u64);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} ({eta})"
        ).unwrap()
    );

    // Start timing
    let start_time = Instant::now();

    // Spawn threads
    let mut handles = Vec::with_capacity(num_threads);
    for thread_idx in 0..num_threads {
        // Clone references for move into thread
        let file_clone = Arc::clone(&file_arc);
        let pb_clone = pb.clone();
        
        let handle = thread::spawn(move || {
            let mut buffer = vec![0u8; block_size];
            let mut read_buffer = vec![0u8; block_size];

            let mut chunk_idx = thread_idx;
            while chunk_idx < total_chunks {
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
                            break;
                        }
                    } else {
                        eprintln!("Seek error before writing at sector {}", offset_sector);
                        break;
                    }

                    // Read
                    if file.seek(SeekFrom::Start(offset_bytes)).is_ok() {
                        if let Err(e) = file.read_exact(&mut read_buffer) {
                            eprintln!("Error reading at sector {}: {}", offset_sector, e);
                            break;
                        }
                    } else {
                        eprintln!("Seek error before reading at sector {}", offset_sector);
                        break;
                    }
                } // lock released

                // Verify
                if buffer != read_buffer {
                    eprintln!("Data mismatch at sector {}!", offset_sector);
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
        }
    }

    // Finish progress bar
    pb.finish_and_clear();

    let duration = start_time.elapsed();
    println!("Disk test completed in {:?}", duration);

    Ok(())
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
    use winapi::um::winnt::ULARGE_INTEGER;       // Correct import for ULARGE_INTEGER

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

