//! src/main.rs be751cf

use std::cmp;
use std::env;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Instant;

// Ctrl+C
use ctrlc;

// Progress bar
use indicatif::{ProgressBar, ProgressStyle};

/// Default constants
const DEFAULT_BLOCK_SIZE: usize = 4096;            // 4 KiB
const DEFAULT_TEST_THREADS: usize = 4;             // concurrency
const TEST_FILE_NAME: &str = "disk_test_file.bin"; // default file name
const SAFETY_FACTOR: f64 = 0.10;                   // 10% margin for free space

/// Global flags
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);  // For Ctrl+C
static HAS_FATAL_ERROR: AtomicBool = AtomicBool::new(false); // For catastrophic errors

/// Tracks error counts for the reliability test
#[derive(Default)]
struct ErrorCounters {
    write_errors: AtomicUsize,
    read_errors: AtomicUsize,
    mismatches: AtomicUsize,
}

impl ErrorCounters {
    fn new() -> Self {
        Self {
            write_errors: AtomicUsize::new(0),
            read_errors: AtomicUsize::new(0),
            mismatches: AtomicUsize::new(0),
        }
    }

    fn increment_write_errors(&self) {
        self.write_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_read_errors(&self) {
        self.read_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_mismatches(&self) {
        self.mismatches.fetch_add(1, Ordering::Relaxed);
    }
}

/// Data-type enum for writing
#[derive(Debug)]
enum DataType {
    Hex,
    Text,
    Binary,
    File(Vec<u8>), // loaded from --data-file
}

impl DataType {
    /// Fills a single block (size = `block_size`) based on the chosen data pattern.
    /// The offset (`offset_sector`) ensures varied patterns across different sectors.
    fn fill_block(&self, block_size: usize, offset_sector: u64) -> Vec<u8> {
        match self {
            DataType::Hex => {
                // Cycle through b"0123456789ABCDEF"
                let mut block = vec![0u8; block_size];
                let pattern = b"0123456789ABCDEF";
                for i in 0..block_size {
                    let idx = ((offset_sector as usize * 7) + i) % pattern.len();
                    block[i] = pattern[idx];
                }
                block
            }
            DataType::Text => {
                // Repeated ASCII text sample
                let sample = b"Lorem ipsum dolor sit amet. ";
                let mut block = vec![0u8; block_size];
                for i in 0..block_size {
                    let idx = (offset_sector as usize + i) % sample.len();
                    block[i] = sample[idx];
                }
                block
            }
            DataType::Binary => {
                // Pseudo-random numeric pattern
                let mut block = vec![0u8; block_size];
                for (i, b) in block.iter_mut().enumerate() {
                    *b = ((offset_sector as usize + i) % 256) as u8;
                }
                block
            }
            DataType::File(buf) => {
                // Repeat/truncate the loaded file data
                let mut block = vec![0u8; block_size];
                for i in 0..block_size {
                    let idx = (offset_sector as usize * block_size + i) % buf.len();
                    block[i] = buf[idx];
                }
                block
            }
        }
    }
}

/// Setup graceful Ctrl+C
fn setup_signal_handler() {
    ctrlc::set_handler(move || {
        eprintln!("Received Ctrl+C; stopping...");
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");
}

/// Retrieve CLI argument by key
fn get_arg_value(args: &[String], key: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|x| x == key) {
        args.get(pos + 1).cloned()
    } else {
        None
    }
}

/// Log an error (both stderr and file)
fn log_error(
    log_file_arc: &Arc<Mutex<File>>,
    thread_idx: usize,
    sector: u64,
    category: &str,
    err: &io::Error,
) {
    eprintln!("[THREAD {}] {} at sector {}: {}", thread_idx, category, sector, err);
    if let Ok(mut lf) = log_file_arc.lock() {
        writeln!(lf, "[THREAD {}] {} at sector {}: {}", thread_idx, category, sector, err).ok();
        lf.flush().ok();
    }
}

/// Log a simple message (both stderr and file)
fn log_simple<S: AsRef<str>>(log_file_arc: &Arc<Mutex<File>>, message: S) {
    eprintln!("{}", message.as_ref());
    if let Ok(mut lf) = log_file_arc.lock() {
        writeln!(lf, "{}", message.as_ref()).ok();
        lf.flush().ok();
    }
}

/// Cross-platform method to retrieve free disk space in bytes
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

/// Single-Sector Read (--read-sector)
fn single_sector_read(
    log_file_arc: &Arc<Mutex<File>>,
    file_path: &Path,
    sector: u64,
    block_size: usize,
) -> io::Result<()> {
    log_simple(log_file_arc, format!("Single-Sector Read @ sector {}", sector));

    let mut file = OpenOptions::new().read(true).open(file_path)?;
    let offset = sector * block_size as u64;

    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; block_size];

    if let Err(e) = file.read_exact(&mut buffer) {
        log_simple(log_file_arc, format!("Read Error @ sector {}: {}", sector, e));
        return Err(e);
    }

    // Hex dump of the entire block for verification/inspection
    let hex_dump = buffer
        .chunks(16)
        .map(|chunk| {
            chunk
                .iter()
                .map(|byte| format!("{:02X}", byte))
                .collect::<Vec<String>>()
                .join(" ")
        })
        .collect::<Vec<String>>()
        .join("\n");

    log_simple(
        log_file_arc,
        format!(
            "Read {} bytes @ sector {}.\nHex Dump:\n{}",
            block_size, sector, hex_dump
        ),
    );

    Ok(())
}

/// Range Read (--range-read)
fn range_read(
    log_file_arc: &Arc<Mutex<File>>,
    file_path: &Path,
    start_sector: u64,
    end_sector: u64,
    block_size: usize,
) -> io::Result<()> {
    if end_sector <= start_sector {
        eprintln!("Invalid range: end_sector <= start_sector.");
        std::process::exit(1);
    }
    log_simple(
        log_file_arc,
        format!("Performing range read from sector {} to {}", start_sector, end_sector),
    );

    let mut file = OpenOptions::new().read(true).open(file_path)?;
    for sector in start_sector..end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }
        let offset = sector * block_size as u64;
        file.seek(SeekFrom::Start(offset))?;
        let mut buffer = vec![0u8; block_size];
        if let Err(e) = file.read_exact(&mut buffer) {
            log_simple(log_file_arc, format!("Read Error @ sector {}: {}", sector, e));
            return Err(e);
        }
        // For large ranges, log only the first few bytes
        let preview_len = cmp::min(16, buffer.len());
        let preview = &buffer[..preview_len];
        log_simple(
            log_file_arc,
            format!(
                "[Sector {}] First {} bytes in hex: {:02X?}",
                sector, preview_len, preview
            ),
        );
    }

    Ok(())
}

/// Range Write (--range-write)
fn range_write(
    log_file_arc: &Arc<Mutex<File>>,
    file_path: &Path,
    start_sector: u64,
    end_sector: u64,
    block_size: usize,
    data_type: &DataType,
) -> io::Result<()> {
    if end_sector <= start_sector {
        eprintln!("Invalid range: end_sector <= start_sector.");
        std::process::exit(1);
    }
    log_simple(
        log_file_arc,
        format!("Performing range write from sector {} to {}", start_sector, end_sector),
    );

    let mut file = OpenOptions::new().read(true).write(true).create(true).open(file_path)?;
    for sector in start_sector..end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            break;
        }

        let buffer = data_type.fill_block(block_size, sector);
        let offset = sector * block_size as u64;

        // Single seek + write is more efficient than multiple small writes
        file.seek(SeekFrom::Start(offset))?;
        if let Err(e) = file.write_all(&buffer) {
            log_simple(log_file_arc, format!("Write Error @ sector {}: {}", sector, e));
            return Err(e);
        }
    }

    Ok(())
}

/// Full-disk concurrency test (optimized reliability test)
fn full_reliability_test(
    file_path: &Path,
    log_file_arc: &Arc<Mutex<File>>,
    counters_arc: &Arc<ErrorCounters>,
    block_size: usize,
    num_threads: usize,
    data_type: DataType,
    batch_size: usize,
) -> io::Result<()> {
    // Validate block_size
    if block_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "block_size cannot be zero",
        ));
    }

    // 1) Determine available space
    let parent_dir = file_path.parent().unwrap_or(Path::new("."));
    let free_space = get_free_space(parent_dir)?;

    // 2) Apply safety factor
    let mut total_bytes = free_space as usize;
    let required_space_with_safety = (total_bytes as f64) * (1.0 + SAFETY_FACTOR);
    if required_space_with_safety > free_space as f64 {
        total_bytes = (free_space as f64 / (1.0 + SAFETY_FACTOR)) as usize;
    }

    // Log final test size
    let (ds, du) = format_bytes(total_bytes as u64);
    log_simple(
        log_file_arc,
        format!("Full test size: {:.2} {}", ds, du),
    );

    // Pre-allocate test file for performance
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_path)?;
    f.set_len(total_bytes as u64)?;

    // Compute total sectors
    let total_sectors = total_bytes / block_size;
    let end_sector = total_sectors as u64;

    log_simple(
        log_file_arc,
        format!("Full reliability test => total sectors: {}", total_sectors),
    );

    // Time the concurrency test
    let start_time = Instant::now();

    // Progress bar
    let pb = ProgressBar::new(end_sector);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap(),
    );
    let pb_arc = Arc::new(pb);

    // For concurrency, split the workload across threads
    let sectors_per_thread = total_sectors / num_threads;
    let remaining_sectors = total_sectors % num_threads;
    let mut handles = Vec::with_capacity(num_threads);

    // Keep the data_type behind an Arc to avoid cloning large buffers per thread
    let data_type_arc = Arc::new(data_type);

    for thread_idx in 0..num_threads {
        let log_clone = Arc::clone(log_file_arc);
        let counters_clone = Arc::clone(counters_arc);
        let pb_clone = Arc::clone(&pb_arc);
        let dt_clone = Arc::clone(&data_type_arc);

        // Each thread calculates its sector range
        let start_sector = thread_idx * sectors_per_thread + cmp::min(thread_idx, remaining_sectors);
        let mut end_sector_thread = start_sector + sectors_per_thread;
        if thread_idx < remaining_sectors {
            end_sector_thread += 1;
        }

        // Convert to u64 for easier arithmetic below
        let start_sector_u64 = start_sector as u64;
        let end_sector_u64 = end_sector_thread as u64;

        // Open separate file handle in each thread
        let thread_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path)
            .expect("Failed to open file in thread");

        let handle = thread::spawn(move || {
            let mut file_guard = thread_file;

            // Reuse large buffers for batched I/O
            let mut write_buf = vec![0u8; batch_size * block_size];
            let mut read_buf = vec![0u8; batch_size * block_size];

            let mut sector = start_sector_u64;
            while sector < end_sector_u64 {
                if STOP_REQUESTED.load(Ordering::SeqCst) || HAS_FATAL_ERROR.load(Ordering::SeqCst) {
                    break;
                }

                // Determine how many sectors to process in this batch
                let batch_end = cmp::min(sector + batch_size as u64, end_sector_u64);
                let current_batch_size = (batch_end - sector) as usize;

                // Fill the write buffer for these sectors
				for i in 0..current_batch_size {
					let offset_sector = sector + i as u64;
					let block_data = dt_clone.fill_block(block_size, offset_sector);
					write_buf[i * block_size..(i + 1) * block_size]
						.copy_from_slice(&block_data);
				}


                let offset_bytes = sector * block_size as u64;

                // Single seek for the entire batch write
                if let Err(e) = file_guard
                    .seek(SeekFrom::Start(offset_bytes))
                    .and_then(|_| file_guard.write_all(&write_buf[..current_batch_size * block_size]))
                {
                    log_error(&log_clone, thread_idx, sector, "Write Error", &e);
                    counters_clone.increment_write_errors();
                    HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                    break;
                }

                // Single seek for the entire batch read
                if let Err(e) = file_guard
                    .seek(SeekFrom::Start(offset_bytes))
                    .and_then(|_| file_guard.read_exact(&mut read_buf[..current_batch_size * block_size]))
                {
                    log_error(&log_clone, thread_idx, sector, "Read Error", &e);
                    counters_clone.increment_read_errors();
                    HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                    break;
                }

                // Verify
                if &write_buf[..current_batch_size * block_size]
                    != &read_buf[..current_batch_size * block_size]
                {
                    counters_clone.increment_mismatches();
                    // Could log mismatches here if desired
                }

                // Update progress bar
                pb_clone.inc(current_batch_size as u64);

                sector += current_batch_size as u64;
            }
        });

        handles.push(handle);
    }

    // Join all threads
    for h in handles {
        if let Err(e) = h.join() {
            let mut lf = log_file_arc.lock().unwrap();
            writeln!(lf, "A thread panicked: {:?}", e).ok();
            lf.flush().ok();
        }
    }

    pb_arc.finish_and_clear();
    let duration = start_time.elapsed();
    log_simple(
        log_file_arc,
        format!("Full reliability test completed in {duration:?}"),
    );

    // Return an error if any fatal I/O issues occurred
    if HAS_FATAL_ERROR.load(Ordering::SeqCst) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Fatal errors occurred during the test",
        ));
    }

    Ok(())
}

/// Dynamically format bytes into KiB, MiB, GiB, or TiB
fn format_bytes(bytes: u64) -> (f64, &'static str) {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    match bytes {
        b if b < 1024 => (b as f64, "Bytes"),
        b if b < 1024 * 1024 => (b as f64 / KIB, "KiB"),
        b if b < 1024 * 1024 * 1024 => (b as f64 / MIB, "MiB"),
        b if b < 1024_u64.pow(4) => (b as f64 / GIB, "GiB"),
        _ => (bytes as f64 / TIB, "TiB"),
    }
}

/// Main entry
fn main() -> io::Result<()> {
    // Setup Ctrl+C
    setup_signal_handler();

    let args: Vec<String> = env::args().collect();

    // Single-Sector Read vs. Range Read vs. Range Write vs. Full test
    let read_sector = get_arg_value(&args, "--read-sector").and_then(|v| v.parse::<u64>().ok());
    let range_read_start = get_arg_value(&args, "--range-read");
    let range_write_start = get_arg_value(&args, "--range-write");

    let data_type_str = get_arg_value(&args, "--data-type");
    let data_file_str = get_arg_value(&args, "--data-file");

    let start_sector = range_read_start
        .as_ref()
        .or_else(|| range_write_start.as_ref())
        .and_then(|v| v.parse::<u64>().ok());

    // Attempt to parse end_sector for range ops
    let end_sector = start_sector.and_then(|_| {
        if let Some(pos) = args.iter().position(|x| x == "--range-read" || x == "--range-write") {
            args.get(pos + 2)?.parse::<u64>().ok()
        } else {
            None
        }
    });

    let num_threads = get_arg_value(&args, "--threads")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_TEST_THREADS);

    let block_size = get_arg_value(&args, "--block-size")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_BLOCK_SIZE);

    let batch_size = get_arg_value(&args, "--batch-size")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1); // Default to batch size of 1 if not specified

    // Derive the data type (hex, text, binary, or file)
    let data_type = if let Some(ref dt) = data_type_str {
        match dt.as_str() {
            "hex" => DataType::Hex,
            "text" => DataType::Text,
            "binary" => DataType::Binary,
            "file" => {
                if let Some(ref file_path) = data_file_str {
                    let mut buf = Vec::new();
                    File::open(file_path)?.read_to_end(&mut buf)?;
                    DataType::File(buf)
                } else {
                    eprintln!("Error: --data-type file requires --data-file <path>");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("Error: unrecognized --data-type value: {}", dt);
                std::process::exit(1);
            }
        }
    } else {
        // Default pattern if none specified
        DataType::Binary
    };

    // Prepare main file path
    let path_str = get_arg_value(&args, "--path").unwrap_or_else(|| TEST_FILE_NAME.to_string());
    let path = Path::new(&path_str);
    let file_path = if path.is_dir() {
        path.join(TEST_FILE_NAME)
    } else {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    eprintln!("Failed to create directory '{}': {}", parent.display(), e);
                    e
                })?;
            }
        }
        path.to_path_buf()
    };

    // Log the resolved file path
    println!("Resolved file path: {}", file_path.display());

    // Open or create a log file
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("disk_test.log")
        .map_err(|e| {
            eprintln!("Failed to open log file 'disk_test.log': {}", e);
            e
        })?;
    let log_file_arc = Arc::new(Mutex::new(log_file));

    // 1) Single-Sector Read
    if let Some(sector) = read_sector {
        single_sector_read(&log_file_arc, &file_path, sector, block_size)?;
        log_simple(&log_file_arc, "Single-sector read complete.");
        return Ok(());
    }

    // 2) Range Read
    if range_read_start.is_some() && data_type_str.is_none() {
        // If user wants just a range read, they usually don't pass --data-type
        let s = start_sector.expect("Invalid start sector for range-read");
        let e = end_sector.expect("Invalid end sector for range-read");
        range_read(&log_file_arc, &file_path, s, e, block_size)?;
        log_simple(&log_file_arc, "Range read complete.");
        return Ok(());
    }

    // 3) Range Write
    if range_write_start.is_some() {
        let s = start_sector.expect("Invalid start sector for range-write");
        let e = end_sector.expect("Invalid end sector for range-write");
        range_write(&log_file_arc, &file_path, s, e, block_size, &data_type)?;
        log_simple(&log_file_arc, "Range write complete.");
        return Ok(());
    }

    // 4) Full reliability test (default)
    log_simple(
        &log_file_arc,
        "No single-sector or range mode selected. Running full reliability test...",
    );

    // Track errors across all threads
    let counters_arc = Arc::new(ErrorCounters::default());

    // Run the multi-threaded reliability test
    full_reliability_test(
        &file_path,
        &log_file_arc,
        &counters_arc,
        block_size,
        num_threads,
        data_type,
        batch_size,
    )?;

    // Summarize final results
    let c = counters_arc;
    let total_errors = c.write_errors.load(Ordering::Relaxed)
        + c.read_errors.load(Ordering::Relaxed)
        + c.mismatches.load(Ordering::Relaxed);
    log_simple(
        &log_file_arc,
        format!(
            "Final Reliability Summary: Write Errors={}, Read Errors={}, Mismatches={}, Total={}",
            c.write_errors.load(Ordering::Relaxed),
            c.read_errors.load(Ordering::Relaxed),
            c.mismatches.load(Ordering::Relaxed),
            total_errors
        ),
    );

    Ok(())
}
