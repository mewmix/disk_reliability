//! src/main.rs

use anyhow::{anyhow, Result}; // Imported `anyhow` macro and `Result`
use hostname;
use std::cmp;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Instant;

use ctrlc;
use indicatif::{ProgressBar, ProgressStyle};

// --------------------------------- DiskBenchmark Trait ---------------------------------
// This trait lets us open/create files with O_DIRECT or no-cache, etc.
pub trait DiskBenchmark {
    fn create_for_benchmarking(path: &Path, disable_cache: bool) -> Result<File>;
    fn open_for_benchmarking(path: &Path, disable_cache: bool, write_access: bool) -> Result<File>;
    fn set_nocache(&self) -> Result<()>;
}

#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "macos")]
impl DiskBenchmark for File {
    fn create_for_benchmarking(path: &Path, disable_cache: bool) -> Result<File> {
        // Low-level open
        let file = unsafe {
            let oflags = libc::O_CREAT | libc::O_RDWR;
            let fd = libc::open(
                path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                oflags,
                0o644,
            );
            if fd == -1 {
                return Err(io::Error::last_os_error().into());
            }
            File::from_raw_fd(fd)
        };

        if disable_cache {
            file.set_nocache()?;
        }
        Ok(file)
    }

    fn open_for_benchmarking(path: &Path, disable_cache: bool, write_access: bool) -> Result<File> {
        let file = unsafe {
            let mut oflags = if write_access { libc::O_RDWR } else { libc::O_RDONLY };
            let fd = libc::open(
                path.as_os_str().as_bytes().as_ptr() as *const i8,
                oflags,
                0o644,
            );
            if fd == -1 {
                return Err(io::Error::last_os_error().into());
            }
            File::from_raw_fd(fd)
        };

        if disable_cache {
            file.set_nocache()?;
        }
        Ok(file)
    }

    fn set_nocache(&self) -> Result<()> {
        let fd = self.as_raw_fd();
        unsafe {
            // F_NOCACHE
            let r = libc::fcntl(fd, libc::F_NOCACHE, 1);
            if r == -1 {
                return Err(io::Error::last_os_error().into());
            }
            // F_GLOBAL_NOCACHE
            let r = libc::fcntl(fd, libc::F_GLOBAL_NOCACHE, 1);
            if r == -1 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "linux")]
impl DiskBenchmark for File {
    fn create_for_benchmarking(path: &Path, disable_cache: bool) -> Result<File> {
        let file = unsafe {
            let mut oflags = libc::O_CREAT | libc::O_RDWR;
            if disable_cache {
                oflags |= libc::O_DIRECT;
            }
            let fd = libc::open(
                path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                oflags,
                0o644,
            );
            if fd == -1 {
                return Err(io::Error::last_os_error().into());
            }
            File::from_raw_fd(fd)
        };
        // On Linux with O_DIRECT, there's not much more to do for "nocache".
        Ok(file)
    }

    fn open_for_benchmarking(path: &Path, disable_cache: bool, write_access: bool) -> Result<File> {
        let file = unsafe {
            let mut oflags = if write_access { libc::O_RDWR } else { libc::O_RDONLY };
            if disable_cache {
                oflags |= libc::O_DIRECT;
            }
            let fd = libc::open(
                path.as_os_str().as_bytes().as_ptr() as *const libc::c_char,
                oflags,
                0o644,
            );
            if fd == -1 {
                return Err(io::Error::last_os_error().into());
            }
            File::from_raw_fd(fd)
        };
        Ok(file)
    }

    fn set_nocache(&self) -> Result<()> {
        // Possibly use fadvise here, but we do nothing for this example.
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl DiskBenchmark for File {
    fn create_for_benchmarking(path: &Path, _disable_cache: bool) -> Result<File> {
        // For no-cache, you'd want FILE_FLAG_NO_BUFFERING via winapi, but let's keep it simple here
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;
        Ok(file)
    }

    fn open_for_benchmarking(path: &Path, _disable_cache: bool, write_access: bool) -> Result<File> {
        let file = if write_access {
            File::options().read(true).write(true).open(path)?
        } else {
            File::options().read(true).open(path)?
        };
        Ok(file)
    }

    fn set_nocache(&self) -> Result<()> {
        // Stub on Windows
        Ok(())
    }
}

// ------------------------------- Original Constants & Structures -------------------------------
const DEFAULT_BLOCK_SIZE: usize = 4096;
const DEFAULT_TEST_THREADS: usize = 4;
const TEST_FILE_NAME: &str = "disk_test_file.bin";
const SAFETY_FACTOR: f64 = 0.10;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static HAS_FATAL_ERROR: AtomicBool = AtomicBool::new(false);

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
    File(Vec<u8>),
    /// Deterministic random pattern for verification
    Random(u64),
}

impl DataType {
    fn fill_block(&self, block_size: usize, offset_sector: u64) -> Vec<u8> {
        match self {
            DataType::Hex => {
                let mut block = vec![0u8; block_size];
                let pattern = b"0123456789ABCDEF";
                for i in 0..block_size {
                    let idx = ((offset_sector as usize * 7) + i) % pattern.len();
                    block[i] = pattern[idx];
                }
                block
            }
            DataType::Text => {
                let sample = b"Lorem ipsum dolor sit amet. ";
                let mut block = vec![0u8; block_size];
                for i in 0..block_size {
                    let idx = (offset_sector as usize + i) % sample.len();
                    block[i] = sample[idx];
                }
                block
            }
            DataType::Binary => {
                let mut block = vec![0u8; block_size];
                for (i, b) in block.iter_mut().enumerate() {
                    *b = ((offset_sector as usize + i) % 256) as u8;
                }
                block
            }
            DataType::File(buf) => {
                let mut block = vec![0u8; block_size];
                for i in 0..block_size {
                    let idx = (offset_sector as usize * block_size + i) % buf.len();
                    block[i] = buf[idx];
                }
                block
            }
            DataType::Random(seed) => {
                // Simple linear congruential generator
                let combined_seed = seed ^ offset_sector;
                let mut rng_state = combined_seed;
                const A: u64 = 6364136223846793005;
                const C: u64 = 1;
                const M: u64 = 1 << 32;

                let mut block = vec![0u8; block_size];
                for i in 0..block_size {
                    rng_state = (A.wrapping_mul(rng_state).wrapping_add(C)) % M;
                    block[i] = (rng_state & 0xFF) as u8;
                }
                block
            }
        }
    }
}

// ------------------------------ Setup & Logging Helpers --------------------------------
fn setup_signal_handler() {
    ctrlc::set_handler(move || {
        eprintln!("Received Ctrl+C; initiating graceful shutdown...");
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");
}

fn get_arg_value(args: &[String], key: &str) -> Option<String> {
    if let Some(pos) = args.iter().position(|x| x == key) {
        args.get(pos + 1).cloned()
    } else {
        None
    }
}

fn current_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format!("T+{:.3}s", since_epoch.as_secs_f64())
}

fn log_error(
    log_file_arc: &Arc<Mutex<File>>,
    thread_idx: usize,
    sector: u64,
    category: &str,
    err: &io::Error,
    expected: Option<&[u8]>,
    actual: Option<&[u8]>,
    path: Option<PathBuf>,
) {
    let ts = current_timestamp();
    let mut error_message = format!(
        "[{}] [THREAD {}] {} at sector {}: {}\n",
        ts, thread_idx, category, sector, err
    );
    if let Some(p) = path {
        error_message.push_str(&format!("Path: {}\n", p.display()));
    }
    if let (Some(exp), Some(act)) = (expected, actual) {
        error_message.push_str(&format!(
            "Expected: {:02X?}\nActual:   {:02X?}\n",
            exp, act
        ));
    }

    eprintln!("{}", error_message);
    if let Ok(mut lf) = log_file_arc.lock() {
        writeln!(lf, "{}", error_message).ok();
        lf.flush().ok();
    }
}

fn log_simple<S: AsRef<str>>(log_file_arc: &Arc<Mutex<File>>, message: S) {
    let ts = current_timestamp();
    let msg = format!("[{}] {}", ts, message.as_ref());
    eprintln!("{}", msg);
    if let Ok(mut lf) = log_file_arc.lock() {
        writeln!(lf, "{}", msg).ok();
        lf.flush().ok();
    }
}

// ------------------------- Disk Space / Host Info Helpers ------------------------
#[cfg(target_family = "unix")]
fn get_free_space(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::mem;
    use libc;

    let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
    let mut stat: libc::statvfs = unsafe { mem::zeroed() };

    let ret = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat as *mut _) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(target_family = "windows")]
fn get_free_space(path: &Path) -> io::Result<u64> {
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

fn get_host_info() -> io::Result<String> {
    let hostname = hostname::get()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        .into_string()
        .unwrap_or_else(|_| "Unknown".to_string());
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    Ok(format!("Host: {}, OS: {}, Architecture: {}", hostname, os, arch))
}

fn get_disk_info(path: &Path) -> io::Result<String> {
    let free_space = get_free_space(path)?;
    let (formatted_free, unit) = format_bytes(free_space);
    Ok(format!("Disk Free Space: {:.2} {}", formatted_free, unit))
}

// --------------------------- Single Sector / Range R/W ---------------------------
fn single_sector_read(
    log_file_arc: &Arc<Mutex<File>>,
    file_path: &Path,
    sector: u64,
    block_size: usize,
) -> Result<()> {
    log_simple(log_file_arc, format!("Initiating Single-Sector Read @ sector {}", sector));

    // For simplicity, regular open here. You could use DiskBenchmark if you prefer direct I/O.
    let mut file = OpenOptions::new().read(true).open(file_path)?;
    let offset = sector * block_size as u64;
    file.seek(SeekFrom::Start(offset))?;

    let mut buffer = vec![0u8; block_size];
    if let Err(e) = file.read_exact(&mut buffer) {
        log_error(
            log_file_arc,
            0,
            sector,
            "Read Error",
            &e,
            None,
            None,
            // CHANGE 1: Use actual file path instead of parent()
            Some(file_path.to_path_buf()),
        );
        return Err(anyhow!(e));
    }

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
            "Successfully read {} bytes @ sector {}.\nHex Dump:\n{}",
            block_size, sector, hex_dump
        ),
    );
    Ok(())
}

fn range_read(
    log_file_arc: &Arc<Mutex<File>>,
    file_path: &Path,
    start_sector: u64,
    end_sector: u64,
    block_size: usize,
) -> Result<()> {
    if end_sector <= start_sector {
        eprintln!("Invalid range: end_sector <= start_sector.");
        std::process::exit(1);
    }
    log_simple(
        log_file_arc,
        format!("Starting Range Read from sector {} to {}", start_sector, end_sector),
    );

    let mut file = OpenOptions::new().read(true).open(file_path)?;
    for sector in start_sector..end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            log_simple(log_file_arc, "Range read interrupted by user.");
            break;
        }
        let offset = sector * block_size as u64;
        file.seek(SeekFrom::Start(offset))?;

        let mut buffer = vec![0u8; block_size];
        if let Err(e) = file.read_exact(&mut buffer) {
            log_error(
                log_file_arc,
                0,
                sector,
                "Read Error",
                &e,
                None,
                None,
                // CHANGE 2: Use actual path
                Some(file_path.to_path_buf()),
            );
            continue;
        }
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

    log_simple(log_file_arc, "Range read operation completed successfully.");
    Ok(())
}

fn range_write(
    log_file_arc: &Arc<Mutex<File>>,
    file_path: &Path,
    start_sector: u64,
    end_sector: u64,
    block_size: usize,
    data_type: &DataType,
) -> Result<()> {
    if end_sector <= start_sector {
        eprintln!("Invalid range: end_sector <= start_sector.");
        std::process::exit(1);
    }
    log_simple(
        log_file_arc,
        format!("Starting Range Write from sector {} to {}", start_sector, end_sector),
    );

    let mut file = OpenOptions::new().read(true).write(true).create(true).open(file_path)?;
    for sector in start_sector..end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            log_simple(log_file_arc, "Range write interrupted by user.");
            break;
        }
        let buffer = data_type.fill_block(block_size, sector);
        let offset = sector * block_size as u64;

        if let Err(e) = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(&buffer))
        {
            log_error(
                log_file_arc,
                0,
                sector,
                "Write Error",
                &e,
                Some(&buffer),
                None,
                // CHANGE 3: Use actual path
                Some(file_path.to_path_buf()),
            );
            return Err(anyhow!(e));
        }
    }

    log_simple(log_file_arc, "Range write operation completed successfully.");
    Ok(())
}

// --------------------------------- Mmap Helper (Optional) ----------------------------
#[cfg(feature = "mmap")]
fn mmap_file_for_test(file: &File, size: usize) -> Result<memmap2::MmapMut> {
    use memmap2::{MmapMut, MmapOptions};
    let mmap = unsafe { MmapOptions::new().len(size).map_mut(file)? };
    Ok(mmap)
}

// --------------------------- Full Reliability Test (Concurrent) -----------------------
fn full_reliability_test(
    file_path: &Path,
    log_file_arc: &Arc<Mutex<File>>,
    counters_arc: &Arc<ErrorCounters>,
    block_size: usize,
    num_threads: usize,
    data_type: DataType,
    batch_size: usize,
    no_write: bool,
    disable_cache: bool,
    use_mmap: bool,
) -> Result<()> {
    if block_size == 0 {
        return Err(anyhow!("block_size cannot be zero"));
    }

    // Determine free space & apply safety factor
    let parent_dir = file_path.parent().unwrap_or_else(|| Path::new("."));
    let free_space = get_free_space(parent_dir)?;
    let mut total_bytes = free_space as usize;
    let required_space_with_safety = (total_bytes as f64) * (1.0 + SAFETY_FACTOR);
    if required_space_with_safety > free_space as f64 {
        total_bytes = (free_space as f64 / (1.0 + SAFETY_FACTOR)) as usize;
    }

    let (ds, du) = format_bytes(total_bytes as u64);
    log_simple(log_file_arc, format!("Total Test Size: {:.2} {}", ds, du));

    // Create (or overwrite) the test file, possibly with direct I/O
    let file_for_create = File::create_for_benchmarking(file_path, disable_cache)?;
    file_for_create.set_len(total_bytes as u64)?;
    // CHANGE 4: On Windows, force a flush so the OS truly reserves the space:
    #[cfg(target_os = "windows")]
    {
        file_for_create.sync_all()?;
    }

    // Calculate total sectors
    let total_sectors = total_bytes / block_size;
    let end_sector = total_sectors as u64;
    log_simple(log_file_arc, format!("Total Sectors for Test: {}", total_sectors));

    let start_time = Instant::now();
    let pb = ProgressBar::new(end_sector);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap(),
    );
    let pb_arc = Arc::new(pb);

    let sectors_per_thread = total_sectors / num_threads;
    let remaining_sectors = total_sectors % num_threads;

    let data_type_arc = Arc::new(data_type);
    let mut handles = Vec::with_capacity(num_threads);

    let file_path_owned = file_path.to_path_buf();

    for thread_idx in 0..num_threads {
        let log_clone = Arc::clone(log_file_arc);
        let counters_clone = Arc::clone(counters_arc);
        let pb_clone = Arc::clone(&pb_arc);
        let dt_clone = Arc::clone(&data_type_arc);

        let start_sector_idx = thread_idx * sectors_per_thread + cmp::min(thread_idx, remaining_sectors);
        let mut end_sector_thread = start_sector_idx + sectors_per_thread;
        if thread_idx < remaining_sectors {
            end_sector_thread += 1;
        }

        let start_sector_u64 = start_sector_idx as u64;
        let end_sector_u64 = end_sector_thread as u64;
        let path_clone = file_path_owned.clone();

        let handle = thread::spawn(move || {
            // Open file in either read-only or read-write mode based on --no-write
            // Also with or without direct I/O
            let file_result = File::open_for_benchmarking(&path_clone, disable_cache, !no_write);
            let mut file_guard = match file_result {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Thread {}: Fatal error opening file: {}", thread_idx, e);
                    HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                    return;
                }
            };

            #[cfg(feature = "mmap")]
            let maybe_mmap = if use_mmap && !no_write {
                match mmap_file_for_test(&file_guard, (end_sector_u64 * block_size as u64) as usize) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        eprintln!("Thread {}: Mmap error: {}", thread_idx, e);
                        HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            } else {
                None
            };

            let mut write_buf = vec![0u8; batch_size * block_size];
            let mut read_buf = vec![0u8; batch_size * block_size];

            let mut sector = start_sector_u64;
            while sector < end_sector_u64 {
                if STOP_REQUESTED.load(Ordering::SeqCst) || HAS_FATAL_ERROR.load(Ordering::SeqCst) {
                    break;
                }

                let batch_end = cmp::min(sector + batch_size as u64, end_sector_u64);
                let current_batch_size = (batch_end - sector) as usize;

                // Fill our "to-be-written" buffer with known pattern
                for i in 0..current_batch_size {
                    let offset_sector = sector + i as u64;
                    let block_data = dt_clone.fill_block(block_size, offset_sector);
                    write_buf[i * block_size..(i + 1) * block_size].copy_from_slice(&block_data);
                }

                let offset_bytes = sector * block_size as u64;

                // If --no-write is set, skip the actual write phase
                if !no_write {
                    #[cfg(feature = "mmap")]
                    if let Some(mmap) = &maybe_mmap {
                        // Example: write directly to the mmap
                        let mmap_slice = &mut mmap[offset_bytes as usize
                            ..offset_bytes as usize + (current_batch_size * block_size)];
                        mmap_slice.copy_from_slice(&write_buf[..current_batch_size * block_size]);
                    }
                    #[cfg(not(feature = "mmap"))]
                    {
                        // Regular write, then flush on Windows
                        if let Err(e) = file_guard
                            .seek(SeekFrom::Start(offset_bytes))
                            .and_then(|_| {
                                file_guard.write_all(&write_buf[..current_batch_size * block_size])
                            })
                            // CHANGE 5: Force flush after each write on Windows
                            .and_then(|_| {
                                #[cfg(target_os = "windows")]
                                {
                                    file_guard.flush()
                                }
                                #[cfg(not(target_os = "windows"))]
                                {
                                    Ok(())
                                }
                            })
                        {
                            log_error(
                                &log_clone,
                                thread_idx,
                                sector,
                                "Write Error",
                                &e,
                                Some(&write_buf[..current_batch_size * block_size]),
                                None,
                                // CHANGE 6: Use actual file path, not parent()
                                Some(path_clone.clone()),
                            );
                            counters_clone.increment_write_errors();
                            sector += current_batch_size as u64;
                            pb_clone.inc(current_batch_size as u64);
                            continue;
                        }
                    }
                }

                // Now read (always) to verify
                #[cfg(feature = "mmap")]
                if let Some(mmap) = &maybe_mmap {
                    // read from the same memory region
                    let mmap_slice = &mmap[offset_bytes as usize
                        ..offset_bytes as usize + (current_batch_size * block_size)];
                    read_buf[..current_batch_size * block_size].copy_from_slice(mmap_slice);
                } else {
                    if let Err(e) = file_guard
                        .seek(SeekFrom::Start(offset_bytes))
                        .and_then(|_| {
                            file_guard.read_exact(&mut read_buf[..current_batch_size * block_size])
                        })
                    {
                        log_error(
                            &log_clone,
                            thread_idx,
                            sector,
                            "Read Error",
                            &e,
                            None,
                            Some(&read_buf[..current_batch_size * block_size]),
                            // CHANGE 7: actual path
                            Some(path_clone.clone()),
                        );
                        counters_clone.increment_read_errors();
                        sector += current_batch_size as u64;
                        pb_clone.inc(current_batch_size as u64);
                        continue;
                    }
                }

                // Compare only if we wrote known data
                if !no_write {
                    if &write_buf[..current_batch_size * block_size]
                        != &read_buf[..current_batch_size * block_size]
                    {
                        counters_clone.increment_mismatches();
                        log_error(
                            &log_clone,
                            thread_idx,
                            sector,
                            "Data Mismatch",
                            &io::Error::new(io::ErrorKind::Other, "Write vs. read mismatch"),
                            Some(&write_buf[..current_batch_size * block_size]),
                            Some(&read_buf[..current_batch_size * block_size]),
                            // CHANGE 8: actual path
                            Some(path_clone.clone()),
                        );
                    }
                }

                pb_clone.inc(current_batch_size as u64);
                sector += current_batch_size as u64;
            }

            // If using an mmap, flush changes
            #[cfg(feature = "mmap")]
            if let Some(mmap) = maybe_mmap {
                if let Err(e) = mmap.flush() {
                    eprintln!("Thread {}: Mmap flush error: {}", thread_idx, e);
                    HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                }
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
    log_simple(log_file_arc, format!("Full reliability test completed in {:.2?}", duration));

    if HAS_FATAL_ERROR.load(Ordering::SeqCst) {
        return Err(anyhow!("A fatal error (e.g., file open failure) occurred."));
    }
    Ok(())
}

// ------------------------------ Byte Formatting Helper ------------------------------
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

// -------------------------------------- Main ---------------------------------------
fn main() -> Result<()> {
    setup_signal_handler();

    let args: Vec<String> = env::args().collect();

    // New flags:
    let no_write = args.contains(&"--no-write".to_string());
    // If user passes --disable-cache, we interpret that as "use direct I/O / no OS caching"
    let disable_cache = args.contains(&"--disable-cache".to_string());
    // If user passes --use-mmap, we do an example memory-mapped I/O
    let use_mmap = args.contains(&"--use-mmap".to_string());

    // Additional random seed, defaulting to 0xDEADBEEF
    let random_seed = get_arg_value(&args, "--seed")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0xDEADBEEF);

    // Existing arguments
    let read_sector = get_arg_value(&args, "--read-sector").and_then(|v| v.parse::<u64>().ok());
    let range_read_start = get_arg_value(&args, "--range-read");
    let range_write_start = get_arg_value(&args, "--range-write");

    let data_type_str = get_arg_value(&args, "--data-type");
    let data_file_str = get_arg_value(&args, "--data-file");

    let start_sector = range_read_start
        .as_ref()
        .or_else(|| range_write_start.as_ref())
        .and_then(|v| v.parse::<u64>().ok());

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
        .unwrap_or(1);

    // Determine data pattern (added "random" variant)
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
            "random" => DataType::Random(random_seed),
            _ => {
                eprintln!("Error: unrecognized --data-type value: {}", dt);
                std::process::exit(1);
            }
        }
    } else {
        DataType::Binary
    };

    // Resolve main file path
    let path_str = get_arg_value(&args, "--path").unwrap_or_else(|| TEST_FILE_NAME.to_string());
    let path = Path::new(&path_str);
    let file_path = if path.is_dir() {
        path.join(TEST_FILE_NAME)
    } else {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    eprintln!("Failed to create directory '{}': {}", parent.display(), e);
                    anyhow!(e)
                })?;
            }
        }
        path.to_path_buf()
    };

    println!("Resolved file path: {}", file_path.display());

    // Open or create a log file
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open("disk_test.log")?;
    let log_file_arc = Arc::new(Mutex::new(log_file));

    // Retrieve & log host info
    match get_host_info() {
        Ok(info) => log_simple(&log_file_arc, format!("Host Information: {}", info)),
        Err(e) => {
            log_error(&log_file_arc, 0, 0, "Host Info Error", &e, None, None, None);
        }
    }

    // Log disk info
    let disk_info_path = if file_path.is_dir() {
        file_path.clone()
    } else {
        file_path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf()
    };
    match get_disk_info(&disk_info_path) {
        Ok(info) => log_simple(&log_file_arc, format!("Disk Information: {}", info)),
        Err(e) => {
            log_error(
                &log_file_arc,
                0,
                0,
                "Disk Info Error",
                &e,
                None,
                None,
                Some(disk_info_path.clone()),
            );
        }
    }

    // Log the start of the test
    log_simple(&log_file_arc, "Starting Disk Reliability Test...");

    // 1) Single-Sector Read
    if let Some(sector) = read_sector {
        single_sector_read(&log_file_arc, &file_path, sector, block_size)?;
        log_simple(&log_file_arc, "Single-sector read operation completed successfully.");
        return Ok(());
    }

    // 2) Range Read
    if range_read_start.is_some() && data_type_str.is_none() {
        let s = start_sector.expect("Invalid start sector for range-read");
        let e = end_sector.expect("Invalid end sector for range-read");
        range_read(&log_file_arc, &file_path, s, e, block_size)?;
        log_simple(&log_file_arc, "Range read operation completed successfully.");
        return Ok(());
    }

    // 3) Range Write
    if range_write_start.is_some() {
        let s = start_sector.expect("Invalid start sector for range-write");
        let e = end_sector.expect("Invalid end sector for range-write");
        range_write(&log_file_arc, &file_path, s, e, block_size, &data_type)?;
        log_simple(&log_file_arc, "Range write operation completed successfully.");
        return Ok(());
    }

    // 4) Full reliability test (default)
    log_simple(
        &log_file_arc,
        "No single-sector or range mode selected. Initiating full reliability test...",
    );

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
        no_write,
        disable_cache,
        use_mmap,
    )?;

    // Summarize final results
    let write_errs = counters_arc.write_errors.load(Ordering::Relaxed);
    let read_errs = counters_arc.read_errors.load(Ordering::Relaxed);
    let mismatches = counters_arc.mismatches.load(Ordering::Relaxed);
    let total_errors = write_errs + read_errs + mismatches;

    log_simple(
        &log_file_arc,
        format!(
            "Final Reliability Summary:\n  Write Errors: {}\n  Read Errors: {}\n  Data Mismatches: {}\n  Total Errors: {}",
            write_errs, read_errs, mismatches, total_errors
        ),
    );

    if total_errors == 0 {
        log_simple(&log_file_arc, "All sectors verified successfully! No errors detected.");
    } else {
        log_simple(
            &log_file_arc,
            format!(
                "Test completed with {} total errors. Review logs for details.",
                total_errors
            ),
        );
    }

    log_simple(&log_file_arc, "Disk Reliability Test completed.");
    Ok(())
}
