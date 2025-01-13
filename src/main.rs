//! src/main.rs
//! Optimized Disk Reliability Testing Tool with Optional Resumption,
//! Dynamic Unit Display, and Small Log Files

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Instant;
use std::env;

// serde
use serde_json;

// For Ctrl+C
use ctrlc;

// For progress bar
use indicatif::{ProgressBar, ProgressStyle};

/// Default constants
const DEFAULT_BLOCK_SIZE: usize = 4096;            // 4 KiB
const DEFAULT_TEST_THREADS: usize = 4;             // concurrency
const TEST_FILE_NAME: &str = "disk_test_file.bin"; // default file name

/// Global flags
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false); // For Ctrl+C handling
static HAS_FATAL_ERROR: AtomicBool = AtomicBool::new(false); // For fatal errors

/// Struct to hold error counts
#[derive(Default)]
struct ErrorCounters {
    write_errors: usize,
    read_errors: usize,
    mismatches: usize,
}

/// If `--meta` is given, we read/write this struct in JSON for resume support.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct TestMeta {
    next_sector: u64, // The next sector to test
}

/// Entry point
fn main() -> io::Result<()> {
    setup_signal_handler();

    // Parse CLI arguments
    let args: Vec<String> = env::args().collect();
    let path_str = get_arg_value(&args, "--path").unwrap_or_else(|| TEST_FILE_NAME.to_string());
    let path = Path::new(&path_str);

    let num_threads = get_arg_value(&args, "--threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TEST_THREADS);

    let block_size = get_arg_value(&args, "--block-size")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_BLOCK_SIZE);

    let start_sector = get_arg_value(&args, "--start-sector")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let end_sector = get_arg_value(&args, "--end-sector")
        .and_then(|v| v.parse::<u64>().ok());

    // Optional metadata file for resume
    let meta_path = get_arg_value(&args, "--meta").map(PathBuf::from);

    // Data pattern
    let use_random = args.contains(&"--random".to_string());

    // Print out settings
    println!("Disk Tester Configuration:");
    println!("  File path:       {}", path.display());
    println!("  Threads:         {}", num_threads);
    println!("  Block size:      {} bytes", block_size);
    println!("  Start sector:    {}", start_sector);
    if let Some(es) = end_sector {
        println!("  End sector:      {}", es);
    }
    println!("  Data pattern:    {}", if use_random { "Pseudo-Random" } else { "Sequential" });

    // Determine if resume is requested
    let mut resume_data = TestMeta::default();
    if let Some(ref meta_file) = meta_path {
        if meta_file.exists() {
            // Attempt to load existing metadata
            if let Ok(meta) = load_metadata(meta_file) {
                println!("Resuming from metadata: next_sector={}", meta.next_sector);
                resume_data = meta;
            } else {
                println!("Metadata file found but invalid. Starting fresh...");
            }
        }
    }

    // Calculate free space
    let free_space = get_free_space(path)?;
    // Determine file path
    let file_path = if path.is_dir() {
        path.join(TEST_FILE_NAME)
    } else {
        path.to_path_buf()
    };

    // Calculate total test bytes
    let mut total_bytes = if let Some(es) = end_sector {
        let sectors_count = es.saturating_sub(start_sector);
        (sectors_count as usize) * block_size
    } else {
        free_space as usize
    };

    // Safety margin (optional)
    const SAFETY_FACTOR: f64 = 0.10;
    let required_space_with_safety = (total_bytes as f64) * (1.0 + SAFETY_FACTOR);
    if required_space_with_safety > free_space as f64 {
        total_bytes = (free_space as f64 / (1.0 + SAFETY_FACTOR)) as usize;
    }

    // Dynamic display of total bytes
    let (display_size, display_unit) = format_bytes(total_bytes as u64);
    println!("  Total test size: {:.2} {}", display_size, display_unit);

    // Open or create test file
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&file_path)?;
    // Preallocate space (sparse on many OSes)
    file.set_len(total_bytes as u64)?;

    // Determine total chunks
    let total_chunks = total_bytes / block_size;
    // If resuming, shift our effective start sector
    let effective_start_sector = start_sector.max(resume_data.next_sector);

    // Create log file
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("disk_test.log")?;

    // Wrap these with Arc<Mutex<...>>
    let file_arc = Arc::new(Mutex::new(file));
    let log_file_arc = Arc::new(Mutex::new(log_file));
    let counters = Arc::new(Mutex::new(ErrorCounters::default()));

    // Set up progress bar
    let pb = ProgressBar::new(total_chunks as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap(),
    );

    let start_time = Instant::now();
    let mut handles = Vec::with_capacity(num_threads);

    // Spawn threads
    for thread_idx in 0..num_threads {
        let file_clone = Arc::clone(&file_arc);
        let log_file_clone = Arc::clone(&log_file_arc);
        let counters_clone = Arc::clone(&counters);
        let pb_clone = pb.clone();

        // Copy these for the thread
        let local_start_sector = effective_start_sector;
        let local_block_size = block_size;
        let local_total_chunks = total_chunks;
        let meta_path_clone = meta_path.clone();

        let handle = thread::spawn(move || {
            let mut buffer = vec![0u8; local_block_size];
            let mut read_buffer = vec![0u8; local_block_size];

            let mut chunk_idx = thread_idx;
            while chunk_idx < local_total_chunks && !STOP_REQUESTED.load(Ordering::SeqCst) {
                // If any thread encountered a fatal error, stop
                if HAS_FATAL_ERROR.load(Ordering::SeqCst) {
                    break;
                }

                let offset_sector = local_start_sector + chunk_idx as u64;
                let offset_bytes = offset_sector * (local_block_size as u64);

                // Prepare data pattern
                if use_random {
                    // A simple pseudo-random pattern
                    for (i, b) in buffer.iter_mut().enumerate() {
                        // e.g. (offset + i) % 256
                        *b = ((offset_sector as usize + i) % 256) as u8;
                    }
                } else {
                    // Sequential pattern
                    for (i, b) in buffer.iter_mut().enumerate() {
                        *b = i as u8; 
                    }
                }

                // Acquire file lock
                {
                    let mut file = file_clone.lock().unwrap();

                    // Attempt write
                    if let Err(e) = file.seek(SeekFrom::Start(offset_bytes))
                        .and_then(|_| file.write_all(&buffer)) 
                    {
                        log_error(&log_file_clone, thread_idx, offset_sector, "Write Error", &e);
                        let mut c = counters_clone.lock().unwrap();
                        c.write_errors += 1;
                        HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                        break;
                    }

                    // Attempt read
                    if let Err(e) = file.seek(SeekFrom::Start(offset_bytes))
                        .and_then(|_| file.read_exact(&mut read_buffer))
                    {
                        log_error(&log_file_clone, thread_idx, offset_sector, "Read Error", &e);
                        let mut c = counters_clone.lock().unwrap();
                        c.read_errors += 1;
                        HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                        break;
                    }
                } // file lock released

                // Verify
                if buffer != read_buffer {
                    log_simple(&log_file_clone, format!(
                        "[THREAD {}] Mismatch at sector {}!",
                        thread_idx, offset_sector
                    ));
                    let mut c = counters_clone.lock().unwrap();
                    c.mismatches += 1;
                }

                // Update progress
                pb_clone.inc(1);

                // If resuming is enabled, update meta on every iteration
                if let Some(ref meta_p) = meta_path_clone {
                    let meta = TestMeta {
                        next_sector: offset_sector + 1,
                    };
                    let _ = save_metadata(meta_p, &meta);
                }

                chunk_idx += num_threads;
            }
        });

        handles.push(handle);
    }

    // Wait for threads
    for handle in handles {
        if let Err(e) = handle.join() {
            let mut lf = log_file_arc.lock().unwrap();
            writeln!(lf, "A thread panicked: {:?}", e).ok();
            lf.flush().ok();
        }
    }

    pb.finish_and_clear();
    let duration = start_time.elapsed();

    println!("Test completed in {:?}", duration);

    // Summarize
    let c = counters.lock().unwrap();
    println!("Errors Summary:");
    println!("  Write errors:  {}", c.write_errors);
    println!("  Read errors:   {}", c.read_errors);
    println!("  Mismatches:    {}", c.mismatches);

    // We can log the final result
    {
        let mut lf = log_file_arc.lock().unwrap();
        writeln!(lf, "Test completed in {:?}", duration).ok();
        writeln!(lf, "Write errors: {}", c.write_errors).ok();
        writeln!(lf, "Read errors: {}", c.read_errors).ok();
        writeln!(lf, "Mismatches: {}", c.mismatches).ok();
        lf.flush().ok();
    }

    Ok(())
}

/// Minimal function to handle Ctrl+C.
fn setup_signal_handler() {
    ctrlc::set_handler(move || {
        eprintln!("Received Ctrl+C; stopping threads...");
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");
}

/// Retrieve a CLI argument value by key.
/// e.g. `--threads 8` -> get_arg_value(args, "--threads") => Some("8")
fn get_arg_value(args: &[String], key: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|x| x == key) {
        return args.get(pos + 1).cloned();
    }
    None
}

/// Dynamically format bytes into KiB, MiB, GiB, or TiB.
fn format_bytes(bytes: u64) -> (f64, &'static str) {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    match bytes {
        b if b < 1024 => (b as f64, "Bytes"),
        b if b < (1024 * 1024) => (b as f64 / KIB, "KiB"),
        b if b < (1024 * 1024 * 1024) => (b as f64 / MIB, "MiB"),
        b if b < (1024_u64.pow(4)) => (b as f64 / GIB, "GiB"),
        _ => (bytes as f64 / TIB, "TiB"),
    }
}

/// Write an error message to the log file, specifying the thread, sector, and error details.
fn log_error(
    log_file_arc: &Arc<Mutex<File>>,
    thread_idx: usize,
    sector: u64,
    category: &str,
    err: &io::Error
) {
    eprintln!("[THREAD {}] {} at sector {}: {}", thread_idx, category, sector, err);
    let mut lf = log_file_arc.lock().unwrap();
    writeln!(lf, "[THREAD {}] {} at sector {}: {}", thread_idx, category, sector, err).ok();
    lf.flush().ok();
}

/// Write a simple message to the log file.
fn log_simple(log_file_arc: &Arc<Mutex<File>>, message: String) {
    eprintln!("{}", &message);
    let mut lf = log_file_arc.lock().unwrap();
    writeln!(lf, "{}", message).ok();
    lf.flush().ok();
}

/// Load metadata JSON from path
fn load_metadata(path: &Path) -> io::Result<TestMeta> {
    let f = File::open(path)?;
    let meta: TestMeta = serde_json::from_reader(f)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid metadata"))?;
    Ok(meta)
}

/// Save metadata JSON to path
fn save_metadata(path: &Path, meta: &TestMeta) -> io::Result<()> {
    let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(path)?;
    let json_str = serde_json::to_string_pretty(meta)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Serialization error"))?;
    f.write_all(json_str.as_bytes())?;
    f.sync_all()?;
    Ok(())
}

#[cfg(target_family = "unix")]
fn get_free_space(path: &std::path::Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::mem;
    use std::os::raw::c_int;
    use std::os::unix::ffi::OsStrExt;
    use libc;

    extern "C" {
        fn statvfs(path: *const i8, buf: *mut libc::statvfs) -> c_int;
    }

    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut stat: libc::statvfs = unsafe { mem::zeroed() };

    let ret = unsafe { statvfs(c_path.as_ptr(), &mut stat as *mut _) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(target_family = "windows")]
fn get_free_space(path: &std::path::Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::minwindef::BOOL;
    use winapi::um::fileapi::GetDiskFreeSpaceExW;
    use winapi::um::winnt::ULARGE_INTEGER;

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

    Ok(unsafe { *(&free_bytes_available as *const _ as *const u64) })
}
