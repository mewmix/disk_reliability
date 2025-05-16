//! src/main.rs
#![allow(clippy::too_many_arguments)]

// Standard library imports
use std::cmp;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Instant;
use std::mem;

// Crates
use chrono::Local;
use clap::Parser;
use ctrlc;
use indicatif::{ProgressBar, ProgressStyle};
use parking_lot::Mutex;
use aligned_vec::AVec as AlignedVec; // Use AVec and alias it

// Platform-specific imports
#[cfg(target_os = "linux")]
use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
#[cfg(target_os = "windows")]
use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt}; // OsStrExt is for OsStr::encode_wide

#[cfg(target_os = "windows")]
use winapi::um::{
    fileapi::{SetFileInformationByHandle, GetDiskFreeSpaceExW, FILE_ALLOCATION_INFO},
    minwinbase::FILE_INFO_BY_HANDLE_CLASS,
    winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, GetComputerNameW},
    winnt::{ULARGE_INTEGER, HANDLE}, // ULARGE_INTEGER is used by GetDiskFreeSpaceExW
};
#[cfg(target_os = "windows")]
use winapi::shared::ntdef::LARGE_INTEGER; // Needed for FILE_ALLOCATION_INFO's AllocationSize
#[cfg(target_os = "windows")]
use std::ptr;


const TEST_FILE_NAME: &str = "disk_test_file.bin";
const SAFETY_FACTOR: f64 = 0.10;
const DIRECT_IO_ALIGNMENT: usize = 4096;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static HAS_FATAL_ERROR: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
struct ErrorCounters {
    write_errors: AtomicUsize,
    read_errors: AtomicUsize,
    mismatches: AtomicUsize,
}

impl ErrorCounters {
    fn new() -> Self { Default::default() }
    fn increment_write_errors(&self) { self.write_errors.fetch_add(1, Ordering::Relaxed); }
    fn increment_read_errors(&self) { self.read_errors.fetch_add(1, Ordering::Relaxed); }
    fn increment_mismatches(&self) { self.mismatches.fetch_add(1, Ordering::Relaxed); }
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum DataTypeChoice { Hex, Text, Binary, File }

#[derive(Debug)]
enum DataTypePattern { Hex, Text, Binary, File(Vec<u8>) }

impl DataTypePattern {
    fn fill_block_inplace(&self, buffer_slice: &mut [u8], offset_sector: u64) {
        let block_size = buffer_slice.len();
        match self {
            DataTypePattern::Hex => {
                let pattern = b"0123456789ABCDEF";
                for i in 0..block_size {
                    buffer_slice[i] = pattern[((offset_sector as usize * 7) + i) % pattern.len()];
                }
            }
            DataTypePattern::Text => {
                let sample = b"Lorem ipsum dolor sit amet. ";
                for i in 0..block_size {
                    buffer_slice[i] = sample[((offset_sector as usize) + i) % sample.len()];
                }
            }
            DataTypePattern::Binary => {
                for (i, b_ref) in buffer_slice.iter_mut().enumerate() {
                    *b_ref = (((offset_sector as usize) + i) % 256) as u8;
                }
            }
            DataTypePattern::File(source_buf) => {
                if source_buf.is_empty() {
                    buffer_slice.fill(0);
                    return;
                }
                for i in 0..block_size {
                    let source_idx = (offset_sector as usize * block_size + i) % source_buf.len();
                    buffer_slice[i] = source_buf[source_idx];
                }
            }
        }
    }

    #[allow(dead_code)] // May not be used if only inplace is utilized
    fn fill_block_to_vec(&self, block_size: usize, offset_sector: u64) -> Vec<u8> {
        let mut buffer = vec![0u8; block_size];
        self.fill_block_inplace(&mut buffer, offset_sector);
        buffer
    }
}

fn parse_size_with_suffix(s: &str) -> Result<u64, String> {
    let s_trimmed = s.trim();
    if s_trimmed.is_empty() { return Err("Input string is empty".to_string()); }
    let first_non_digit_idx = s_trimmed.find(|c: char| !c.is_digit(10));
    let (num_str_candidate, suffix_candidate_orig) = match first_non_digit_idx {
        Some(idx) => {
            if idx == 0 { return Err(format!("Invalid format: missing numeric value in '{}'", s_trimmed)); }
            s_trimmed.split_at(idx)
        }
        None => (s_trimmed, ""),
    };
    let num = num_str_candidate.parse::<u64>().map_err(|_| format!("Invalid number: '{}' in '{}'", num_str_candidate, s_trimmed))?;
    let suffix = suffix_candidate_orig.trim_start().to_uppercase();
    match suffix.as_str() {
        "" | "B" => Ok(num),
        "K" | "KB" | "KIB" => Ok(num.saturating_mul(1024)),
        "M" | "MB" | "MIB" => Ok(num.saturating_mul(1024 * 1024)),
        "G" | "GB" | "GIB" => Ok(num.saturating_mul(1024 * 1024 * 1024)),
        "T" | "TB" | "TIB" => Ok(num.saturating_mul(1024 * 1024 * 1024 * 1024)),
        _ => Err(format!("Unknown or misplaced size suffix: '{}' in '{}'", suffix_candidate_orig, s_trimmed)),
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    FullTest {
        #[clap(long)] path: Option<PathBuf>,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")] block_size: u64,
        #[clap(long, default_value_t = num_cpus::get())] threads: usize,
        #[clap(long, value_parser = parse_size_with_suffix)] batch_kib: Option<u64>,
        #[clap(long, default_value = "1")] batch_sectors: usize,
        #[clap(long, value_enum, default_value = "binary")] data_type: DataTypeChoice,
        #[clap(long)] data_file: Option<PathBuf>,
        #[clap(long)] direct_io: bool,
        #[clap(long)] preallocate: bool,
    },
    ReadSector {
        #[clap(long)] path: PathBuf,
        #[clap(long)] sector: u64,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")] block_size: u64,
        #[clap(long)] direct_io: bool,
    },
    RangeRead {
        #[clap(long)] path: PathBuf,
        #[clap(long)] start_sector: u64,
        #[clap(long, help = "End sector number (exclusive). If 0 or not provided, reads to end of file.")]
        end_sector: Option<u64>,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")] block_size: u64,
        #[clap(long)] direct_io: bool,
    },
    RangeWrite {
        #[clap(long)] path: PathBuf,
        #[clap(long)] start_sector: u64,
        #[clap(long)] end_sector: u64,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")] block_size: u64,
        #[clap(long, value_enum, default_value = "binary")] data_type: DataTypeChoice,
        #[clap(long)] data_file: Option<PathBuf>,
        #[clap(long)] direct_io: bool,
    },
}

fn setup_signal_handler() {
    ctrlc::set_handler(move || {
        eprintln!("\nReceived Ctrl+C; initiating graceful shutdown...");
        STOP_REQUESTED.store(true, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl+C handler");
}

fn current_timestamp() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn log_message_internal(
    log_file_arc_opt: &Option<Arc<Mutex<File>>>,
    pb_opt: Option<&Arc<ProgressBar>>,
    full_message: String,
) {
    if let Some(pb) = pb_opt {
        pb.println(full_message.as_str());
    } else {
        eprintln!("{}", full_message);
    }
    if let Some(ref lf_arc) = log_file_arc_opt {
        let mut lf_guard = lf_arc.lock();
        let _ = writeln!(*lf_guard, "{}", full_message);
        let _ = lf_guard.flush();
    }
}

fn log_simple<S: AsRef<str>>(
    log_f: &Option<Arc<Mutex<File>>>,
    pb: Option<&Arc<ProgressBar>>,
    msg: S,
) {
    let msg_with_ts = format!("[{}] {}", current_timestamp(), msg.as_ref());
    log_message_internal(log_f, pb, msg_with_ts);
}

fn log_error(
    log_f: &Option<Arc<Mutex<File>>>,
    pb: Option<&Arc<ProgressBar>>,
    thread_idx: usize,
    sector: u64,
    category: &str,
    err_desc: &str,
    expected: Option<&[u8]>,
    actual: Option<&[u8]>,
    path: Option<PathBuf>,
) {
    let ts = current_timestamp();
    let mut error_message = format!(
        "[{}] [THREAD {}] {} at sector {}: {}\n",
        ts, thread_idx, category, sector, err_desc
    );
    if let Some(p) = path {
        error_message.push_str(&format!("File path context: {}\n", p.display()));
    }
    if let (Some(exp), Some(act)) = (expected, actual) {
        const MAX_DUMP_LEN: usize = 64;
        let exp_slice = &exp[..cmp::min(exp.len(), MAX_DUMP_LEN)];
        let act_slice = &act[..cmp::min(act.len(), MAX_DUMP_LEN)];
        error_message.push_str(&format!(
            "Expected (first {} bytes): {:02X?}\nActual   (first {} bytes): {:02X?}\n",
            exp_slice.len(), exp_slice, act_slice.len(), act_slice
        ));
    }
    log_message_internal(log_f, pb, error_message);
}

#[cfg(target_os = "linux")]
fn get_hostname_os_impl() -> io::Result<String> {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == -1 { return Err(io::Error::last_os_error()); }
    let len = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}
#[cfg(target_os = "windows")]
fn get_hostname_os_impl() -> io::Result<String> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer_size = 0;
    unsafe { GetComputerNameW(ptr::null_mut(), &mut buffer_size) };
    if buffer_size == 0 { return Err(io::Error::last_os_error()); }
    let mut buffer: Vec<u16> = vec![0; buffer_size as usize];
    if unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut buffer_size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(std::ffi::OsString::from_wide(&buffer[..buffer_size as usize]).to_string_lossy().into_owned())
}
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn get_hostname_os_impl() -> io::Result<String> { Ok("Hostname_Not_Implemented_For_This_OS".to_string()) }

fn get_host_info() -> io::Result<String> {
    let hostname = get_hostname_os_impl()?;
    Ok(format!("Host: {}, OS: {}, Architecture: {}", hostname, std::env::consts::OS, std::env::consts::ARCH))
}

#[cfg(target_family = "unix")]
fn get_free_space(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    let c_path_str = path.as_os_str().as_bytes();
    let path_for_cstring = if c_path_str.is_empty() { Path::new(".") } else { path };
    let c_path = CString::new(path_for_cstring.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid path for CString: {}", e)))?;
    let mut stat: libc::statvfs = unsafe { mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat as *mut _) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stat.f_bavail as u64 * stat.f_frsize as u64)
}

#[cfg(target_family = "windows")]
fn get_free_space(path: &Path) -> io::Result<u64> {
    let mut path_for_api = path.to_path_buf();
    if path.is_file() || !path.exists() {
        path_for_api = path.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();
    }
    if path_for_api.as_os_str().is_empty() { path_for_api = Path::new(".").to_path_buf(); }
    let mut wide: Vec<u16> = path_for_api.as_os_str().encode_wide().collect();
    if wide.last() != Some(&0) { wide.push(0); } // Ensure null termination for Windows API
    let mut free_bytes_available: ULARGE_INTEGER = unsafe { mem::zeroed() };
    let mut total_number_of_bytes: ULARGE_INTEGER = unsafe { mem::zeroed() };
    let mut total_number_of_free_bytes: ULARGE_INTEGER = unsafe { mem::zeroed() };
    if unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free_bytes_available, &mut total_number_of_bytes, &mut total_number_of_free_bytes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { *free_bytes_available.QuadPart() })
}

fn get_disk_info(path: &Path) -> io::Result<String> {
    let free_space = get_free_space(path)?;
    let (formatted_free, unit) = format_bytes(free_space);
    Ok(format!("Disk Free Space (for path: {}): {:.2} {}", path.display(), formatted_free, unit))
}

fn open_file_options(
    _path: &Path,
    read: bool,
    write: bool,
    create: bool,
    direct_io: bool,
    log_f: &Option<Arc<Mutex<File>>>,
) -> OpenOptions {
    let mut opts = OpenOptions::new();
    if read { opts.read(true); }
    if write { opts.write(true); }
    if create { opts.create(true); }
    if direct_io {
        #[cfg(target_os = "linux")] {
            log_simple(log_f, None, "Using O_DIRECT on Linux. Ensure buffer/IO alignment and block size multiple of 512B.");
            opts.custom_flags(libc::O_DIRECT);
        }
        #[cfg(target_os = "windows")] {
            log_simple(log_f, None, "Using FILE_FLAG_NO_BUFFERING on Windows. Ensure sector alignment and block size multiple of 512B.");
            opts.custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH);
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))] {
            log_simple(log_f, None, "Direct I/O requested but not supported on this platform. Ignored.");
        }
    }
    opts
}

fn new_aligned_zeroed(len: usize, alignment: usize) -> AlignedVec<u8> {
    let mut v = AlignedVec::with_capacity(alignment, len);
    // safe, works on every version
    for _ in 0..len {
        v.push(0);
    }
    v
}

fn create_buffer(len: usize, alignment: usize, direct_io: bool) -> AlignedVec<u8> {
    if direct_io {
        new_aligned_zeroed(len, alignment)
    } else {
        let mut v = AlignedVec::with_capacity(1, len);
        for _ in 0..len {
            v.push(0);
        }
        v
    }
}



fn single_sector_read(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    sector: u64,
    block_size: usize,
    direct_io: bool,
) -> io::Result<()> {
    log_simple(log_f, None, format!("Initiating Single-Sector Read @ sector {}", sector));
    let mut file = open_file_options(file_path, true, false, false, direct_io, log_f).open(file_path)?;
    let offset = sector.saturating_mul(block_size as u64);
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = create_buffer(block_size, DIRECT_IO_ALIGNMENT, direct_io);
    if let Err(e) = file.read_exact(buffer.as_mut_slice()) {
        log_error(log_f, None, 0, sector, "Read Error", &e.to_string(), None, None, Some(file_path.to_path_buf()));
        return Err(e);
    }
    let hex_dump = buffer.chunks(16).map(|chunk| chunk.iter().map(|byte| format!("{:02X}", byte)).collect::<Vec<String>>().join(" ")).collect::<Vec<String>>().join("\n");
    log_simple(log_f, None, format!("Successfully read {} bytes @ sector {}.\nHex Dump:\n{}", block_size, sector, hex_dump));
    Ok(())
}

fn range_read(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    start_sector: u64,
    end_sector_opt: Option<u64>,
    block_size: usize,
    direct_io: bool,
) -> io::Result<()> {
    let mut file = open_file_options(file_path, true, false, false, direct_io, log_f).open(file_path)?;
    let file_len_bytes = file.metadata()?.len();
    let file_len_sectors = if block_size > 0 { file_len_bytes / block_size as u64 } else { 0 };
    let actual_end_sector = match end_sector_opt {
        Some(0) | None => file_len_sectors,
        Some(end) => {
            if end <= start_sector {
                let msg = "Invalid range: end_sector must be greater than start_sector if specified and not 0.";
                log_simple(log_f, None, msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            cmp::min(end, file_len_sectors)
        }
    };
    if actual_end_sector <= start_sector && file_len_sectors > 0 && start_sector > 0 {
        log_simple(log_f, None, format!("Start sector {} is at or beyond end of file ({} sectors). Nothing to read.", start_sector, file_len_sectors));
        return Ok(());
    } else if actual_end_sector == 0 && start_sector == 0 && file_len_sectors == 0 {
         log_simple(log_f, None, "File is empty. Nothing to read.");
        return Ok(());
    }
    log_simple(log_f, None, format!("Starting Range Read from sector {} to {} (exclusive)", start_sector, actual_end_sector));
    let mut buffer = create_buffer(block_size, DIRECT_IO_ALIGNMENT, direct_io);
    for sector_idx in start_sector..actual_end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) { log_simple(log_f, None, "Range read interrupted by user."); break; }
        let offset = sector_idx.saturating_mul(block_size as u64);
        if offset >= file_len_bytes && file_len_bytes > 0 { log_simple(log_f, None, format!("Attempted to seek past EOF at sector {}. Stopping range read.", sector_idx)); break; }
        if let Err(e) = file.seek(SeekFrom::Start(offset)) { log_error(log_f, None, 0, sector_idx, "Seek Error", &e.to_string(), None, None, Some(file_path.to_path_buf())); continue; }
        if let Err(e) = file.read_exact(buffer.as_mut_slice()) { log_error(log_f, None, 0, sector_idx, "Read Error", &e.to_string(), None, None, Some(file_path.to_path_buf())); continue; }
        let preview_len = cmp::min(16, buffer.len());
        let preview = &buffer.as_slice()[..preview_len];
        log_simple(log_f, None, format!("[Sector {}] First {} bytes in hex: {:02X?}", sector_idx, preview_len, preview));
    }
    log_simple(log_f, None, "Range read operation completed.");
    Ok(())
}

fn range_write(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    start_sector: u64,
    end_sector: u64,
    block_size: usize,
    data_pattern: &DataTypePattern,
    direct_io: bool,
) -> io::Result<()> {
    if end_sector <= start_sector {
        let msg = "Invalid range: end_sector must be greater than start_sector.";
        log_simple(log_f, None, msg);
        return Err(io::Error::new(ErrorKind::InvalidInput, msg));
    }
    log_simple(log_f, None, format!("Starting Range Write from sector {} to {}", start_sector, end_sector));
    let mut file = open_file_options(file_path, true, true, true, direct_io, log_f).open(file_path)?;
    let mut buffer_to_write = create_buffer(block_size, DIRECT_IO_ALIGNMENT, direct_io);
    for sector_idx in start_sector..end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) { log_simple(log_f, None, "Range write interrupted by user."); break; }
        data_pattern.fill_block_inplace(buffer_to_write.as_mut_slice(), sector_idx);
        let offset = sector_idx.saturating_mul(block_size as u64);
        if let Err(e) = file.seek(SeekFrom::Start(offset)).and_then(|_| file.write_all(buffer_to_write.as_slice())) {
            log_error(log_f, None, 0, sector_idx, "Write Error", &e.to_string(), Some(buffer_to_write.as_slice()), None, Some(file_path.to_path_buf()));
            continue;
        }
    }
    log_simple(log_f, None, "Range write operation completed.");
    Ok(())
}

#[cfg(target_os = "windows")]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    // winapi::shared::ntdef::LARGE_INTEGER is imported at the top.
    // winapi::um::fileapi::FILE_ALLOCATION_INFO (struct) is imported at the top.
    // winapi::um::minwinbase::FILE_INFO_BY_HANDLE_CLASS (enum type) is imported at the top.

    let mut allocation_size_li: LARGE_INTEGER = unsafe { mem::zeroed() };
    unsafe {
        *allocation_size_li.QuadPart_mut() = size as i64; // Cast u64 to i64
    }

    let info = FILE_ALLOCATION_INFO {
        AllocationSize: allocation_size_li
    };
    
    let class_value: FILE_INFO_BY_HANDLE_CLASS = winapi::um::minwinbase::FileAllocationInfo;

    let ret = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            class_value,
            &info as *const FILE_ALLOCATION_INFO as *mut _,
            mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        )
    };

    if ret == 0 {
        let err = io::Error::last_os_error();
        log_simple(log_f, None, format!("SetFileInformationByHandle for pre-allocation failed: {}. Falling back to set_len.", err));
        file.set_len(size) // Fallback
    } else {
        // Successfully set allocation size. Also ensure logical file size (EOF) is updated.
        file.set_len(size)
    }
}

#[cfg(target_os = "linux")]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    log_simple(log_f, None, format!("Attempting posix_fallocate for {} bytes...", size));
    let ret = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, size as libc::off_t) };
    if ret != 0 {
        let err = io::Error::from_raw_os_error(ret);
        log_simple(log_f, None, format!("posix_fallocate failed (errno {}): {}. Falling back to set_len.", ret, err));
        file.set_len(size)
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    log_simple(log_f, None, "True pre-allocation not supported on this OS. Using set_len.");
    file.set_len(size)
}

fn preallocate_file(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    log_simple(log_f, None, format!("Pre-allocating file to {} bytes (physical where possible)...", size));
    preallocate_file_os(file, size, log_f)
}

fn full_reliability_test(
    file_path: &Path,
    log_f_opt: &Option<Arc<Mutex<File>>>,
    counters_arc: &Arc<ErrorCounters>,
    block_size_u64: u64,
    num_threads: usize,
    data_pattern: DataTypePattern,
    batch_size_sectors: usize,
    direct_io: bool,
    preallocate: bool,
) -> io::Result<()> {
    let block_size_usize = block_size_u64 as usize;
    let parent_dir_for_space = file_path.parent().map_or_else(|| Path::new("."), |p| if p.as_os_str().is_empty() { Path::new(".") } else { p });
    let free_space = get_free_space(parent_dir_for_space)?;
    let mut total_bytes_to_test = (free_space as f64 * (1.0 - SAFETY_FACTOR)) as u64;
    total_bytes_to_test = (total_bytes_to_test / block_size_u64) * block_size_u64;
    if total_bytes_to_test == 0 {
        log_simple(log_f_opt, None, "Not enough free space for the test after applying safety factor and block alignment.");
        return Err(io::Error::new(ErrorKind::OutOfMemory, "Not enough free space for test file."));
    }
    let (ds, du) = format_bytes(total_bytes_to_test);
    log_simple(log_f_opt, None, format!("Total Test Size: {:.2} {} ({} bytes)", ds, du, total_bytes_to_test));
    let file_for_setup = open_file_options(file_path, true, true, true, false, log_f_opt).open(file_path)?;
    if preallocate { preallocate_file(&file_for_setup, total_bytes_to_test, log_f_opt)?; } else { file_for_setup.set_len(total_bytes_to_test)?; }
    drop(file_for_setup);
    let total_sectors = total_bytes_to_test / block_size_u64;
    if total_sectors == 0 && total_bytes_to_test > 0 {
        log_simple(log_f_opt, None, "Calculated total sectors is 0, but test size is non-zero. Check block size alignment.");
        return Err(io::Error::new(ErrorKind::InvalidInput, "Miscalculated total sectors."));
    }
    log_simple(log_f_opt, None, format!("Total Sectors for Test: {}", total_sectors));
    let start_time = Instant::now();
    let pb = ProgressBar::new(total_sectors);
    pb.set_style(ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta_precise}) {wide_msg}").unwrap().progress_chars("##-"));
    let pb_arc = Arc::new(pb);
    let data_pattern_arc = Arc::new(data_pattern);
    let file_path_owned = file_path.to_path_buf();
    let mut handles = Vec::with_capacity(num_threads);
    let sectors_per_thread_base = total_sectors / (num_threads as u64);
    let remaining_sectors_total = total_sectors % (num_threads as u64);

    for thread_idx in 0..num_threads {
        let log_clone = log_f_opt.clone();
        let counters_clone = Arc::clone(counters_arc);
        let pb_clone_thread = Arc::clone(&pb_arc);
        let dt_clone = Arc::clone(&data_pattern_arc);
        let file_path_thread_clone = file_path_owned.clone();
        let thread_start_sector = (thread_idx as u64 * sectors_per_thread_base) + cmp::min(thread_idx as u64, remaining_sectors_total);
        let mut num_sectors_for_thread_u64 = sectors_per_thread_base;
        if (thread_idx as u64) < remaining_sectors_total { num_sectors_for_thread_u64 += 1; }
        if num_sectors_for_thread_u64 == 0 { continue; }

        let handle = thread::spawn(move || {
            let thread_file = match open_file_options(&file_path_thread_clone, true, true, false, direct_io, &log_clone).open(&file_path_thread_clone) {
                Ok(f) => f,
                Err(e) => {
                    let err_msg = format!("Thread {}: Fatal error opening file {}: {}", thread_idx, file_path_thread_clone.display(), e);
                    pb_clone_thread.println(format!("[{}] {}", current_timestamp(), err_msg));
                    log_simple(&log_clone, Some(&pb_clone_thread), &err_msg);
                    HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                    return;
                }
            };
            let mut file_guard = thread_file;
            let batch_byte_capacity = batch_size_sectors * block_size_usize;
            let mut write_buf = create_buffer(batch_byte_capacity, DIRECT_IO_ALIGNMENT, direct_io);
            let mut read_buf  = create_buffer(batch_byte_capacity, DIRECT_IO_ALIGNMENT, direct_io);
            let mut current_sector_offset_in_thread = 0u64;

            while current_sector_offset_in_thread < num_sectors_for_thread_u64 {
                if STOP_REQUESTED.load(Ordering::SeqCst) || HAS_FATAL_ERROR.load(Ordering::SeqCst) { break; }
                let remaining_in_thread = num_sectors_for_thread_u64 - current_sector_offset_in_thread;
                let current_batch_actual_sectors = cmp::min(batch_size_sectors as u64, remaining_in_thread) as usize;
                let current_batch_byte_size = current_batch_actual_sectors * block_size_usize;
                let first_sector_in_batch_global = thread_start_sector + current_sector_offset_in_thread;

                for i in 0..current_batch_actual_sectors {
                    let global_offset_sector_for_pattern = first_sector_in_batch_global + i as u64;
                    let start_idx_in_buf = i * block_size_usize;
                    let end_idx_in_buf = start_idx_in_buf + block_size_usize;
                    dt_clone.fill_block_inplace(&mut write_buf.as_mut_slice()[start_idx_in_buf..end_idx_in_buf], global_offset_sector_for_pattern);
                }
                let offset_bytes_for_seek = first_sector_in_batch_global * block_size_u64;
                if let Err(e) = file_guard.seek(SeekFrom::Start(offset_bytes_for_seek)).and_then(|_| file_guard.write_all(&write_buf.as_slice()[..current_batch_byte_size])) {
                    log_error(&log_clone, Some(&pb_clone_thread), thread_idx, first_sector_in_batch_global, "Write Error", &e.to_string(), Some(&write_buf.as_slice()[..current_batch_byte_size]), None, Some(file_path_thread_clone.clone()));
                    counters_clone.increment_write_errors();
                } else {
                    if let Err(e) = file_guard.seek(SeekFrom::Start(offset_bytes_for_seek)).and_then(|_| file_guard.read_exact(&mut read_buf.as_mut_slice()[..current_batch_byte_size])) {
                        log_error(&log_clone, Some(&pb_clone_thread), thread_idx, first_sector_in_batch_global, "Read Error", &e.to_string(), None, Some(&read_buf.as_slice()[..current_batch_byte_size]), Some(file_path_thread_clone.clone()));
                        counters_clone.increment_read_errors();
                    } else {
                        let write_slice_for_cmp = &write_buf.as_slice()[..current_batch_byte_size];
                        let read_slice_for_cmp = &read_buf.as_slice()[..current_batch_byte_size];
                        if write_slice_for_cmp != read_slice_for_cmp {
                            counters_clone.increment_mismatches();
                            for i in 0..current_batch_actual_sectors {
                                let block_start_idx_in_buf = i * block_size_usize;
                                let block_end_idx_in_buf = block_start_idx_in_buf + block_size_usize;
                                if write_slice_for_cmp[block_start_idx_in_buf..block_end_idx_in_buf] != read_slice_for_cmp[block_start_idx_in_buf..block_end_idx_in_buf] {
                                    let mismatch_sector_global = first_sector_in_batch_global + i as u64;
                                    log_error(&log_clone, Some(&pb_clone_thread), thread_idx, mismatch_sector_global, "Data Mismatch", "Block content mismatch", Some(&write_slice_for_cmp[block_start_idx_in_buf..block_end_idx_in_buf]), Some(&read_slice_for_cmp[block_start_idx_in_buf..block_end_idx_in_buf]), Some(file_path_thread_clone.clone()));
                                    break;
                                }
                            }
                        }
                    }
                }
                pb_clone_thread.inc(current_batch_actual_sectors as u64);
                current_sector_offset_in_thread += current_batch_actual_sectors as u64;
            }
        });
        handles.push(handle);
    }

    for h in handles {
        if let Err(e) = h.join() {
            if !pb_arc.is_finished() { pb_arc.finish_and_clear(); }
            let panic_msg = format!("A worker thread panicked: {:?}", e);
            log_simple(log_f_opt, None, &panic_msg);
            HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
        }
    }
    if HAS_FATAL_ERROR.load(Ordering::SeqCst) && !pb_arc.is_finished() { pb_arc.abandon_with_message("Test aborted due to fatal error(s)."); }
    else if !pb_arc.is_finished() { pb_arc.finish_with_message("Test scan completed."); }
    let duration = start_time.elapsed();
    log_simple(log_f_opt, None, format!("Full reliability test scan phase completed in {:.2?}.", duration));
    if HAS_FATAL_ERROR.load(Ordering::SeqCst) { return Err(io::Error::new(ErrorKind::Other, "Fatal error occurred in one or more threads. Check logs.")); }
    Ok(())
}

fn format_bytes(bytes: u64) -> (f64, &'static str) {
    const KIB_F: f64 = 1024.0;
    const MIB_F: f64 = KIB_F * 1024.0;
    const GIB_F: f64 = MIB_F * 1024.0;
    const TIB_F: f64 = GIB_F * 1024.0;
    if bytes < 1024 { return (bytes as f64, "Bytes"); }
    let bytes_f = bytes as f64;
    if bytes_f < MIB_F { (bytes_f / KIB_F, "KiB") }
    else if bytes_f < GIB_F { (bytes_f / MIB_F, "MiB") }
    else if bytes_f < TIB_F { (bytes_f / GIB_F, "GiB") }
    else { (bytes_f / TIB_F, "TiB") }
}

fn resolve_file_path(cli_path: Option<PathBuf>, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<PathBuf> {
    let path_arg = cli_path.unwrap_or_else(|| PathBuf::from("."));
    let mut file_path_intermediate = if path_arg.is_dir() || path_arg.as_os_str() == "." || path_arg.as_os_str().is_empty() {
        let current_dir = env::current_dir()?;
        current_dir.join(path_arg).join(TEST_FILE_NAME)
    } else {
        if let Some(parent) = path_arg.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                log_simple(log_f, None, format!("Creating parent directory: {}", parent.display()));
                fs::create_dir_all(parent).map_err(|e| io::Error::new(e.kind(), format!("Failed to create dir {}: {}", parent.display(), e)))?;
            }
        }
        if path_arg.is_absolute() { path_arg } else { env::current_dir()?.join(path_arg) }
    };
    match file_path_intermediate.canonicalize() {
        Ok(canonical_path) => { log_simple(log_f, None, format!("Resolved and canonicalized test file path: {}", canonical_path.display())); Ok(canonical_path) }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            if !file_path_intermediate.is_absolute() { file_path_intermediate = env::current_dir()?.join(file_path_intermediate); }
            log_simple(log_f, None, format!("Resolved test file path (will be created): {}", file_path_intermediate.display()));
            Ok(file_path_intermediate)
        }
        Err(e) => { log_simple(log_f, None, format!("Error resolving file path {}: {}", file_path_intermediate.display(), e)); Err(e) }
    }
}

fn main() {
    let log_file_path = "disk_test.log";
    let log_file_arc_opt: Option<Arc<Mutex<File>>> =
        match OpenOptions::new().create(true).append(true).write(true).open(log_file_path) {
            Ok(f) => Some(Arc::new(Mutex::new(f))),
            Err(e) => { eprintln!("[{}] Failed to open log file '{}': {}. Further logs will only go to stderr.", current_timestamp(), log_file_path, e); None }
        };
    let main_result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| { main_logic(log_file_arc_opt.clone()) }));
    let exit_code = match main_result {
        Ok(Ok(())) => { log_simple(&log_file_arc_opt, None, "Test completed successfully."); 0 }
        Ok(Err(e)) => { log_simple(&log_file_arc_opt, None, format!("Test failed with an error: {}", e)); 1 }
        Err(panic_payload) => {
            let mut panic_msg = format!("[{}] A critical error occurred: Test panicked!", current_timestamp());
            if let Some(s) = panic_payload.downcast_ref::<String>() { panic_msg.push_str(&format!("\nPanic message: {}", s)); }
            else if let Some(s) = panic_payload.downcast_ref::<&str>() { panic_msg.push_str(&format!("\nPanic message: {}", s)); }
            else { panic_msg.push_str("\nPanic payload: (type not recognized as string)"); }
            eprintln!("{}", panic_msg);
            if let Some(ref lf_arc) = log_file_arc_opt {
                let mut lf_guard = lf_arc.lock();
                let _ = writeln!(*lf_guard, "{}", panic_msg);
                let _ = lf_guard.flush();
            }
            101
        }
    };
    std::process::exit(exit_code);
}

fn main_logic(log_file_arc_opt: Option<Arc<Mutex<File>>>) -> io::Result<()> {
    setup_signal_handler();
    let cli = Cli::parse();
    log_simple(&log_file_arc_opt, None, "Starting Disk Stress Test...");
    log_simple(&log_file_arc_opt, None, format!("CLI Command: {:?}", cli));
    if let Ok(info) = get_host_info() { log_simple(&log_file_arc_opt, None, format!("Host Information: {}", info)); }
    else { log_simple(&log_file_arc_opt, None, "Could not retrieve host information."); }
    let initial_path_for_disk_info = match &cli.command {
        Commands::FullTest { path, .. } => path.as_ref().map_or_else(|| Path::new("."), |p| p.as_path()),
        Commands::ReadSector { path, .. } | Commands::RangeRead { path, .. } | Commands::RangeWrite { path, .. } => path.as_path(),
    };
    if let Ok(info) = get_disk_info(initial_path_for_disk_info) { log_simple(&log_file_arc_opt, None, &info); }
    else { log_simple(&log_file_arc_opt, None, format!("Could not retrieve disk info for path: {}", initial_path_for_disk_info.display())); }

    match cli.command {
        Commands::FullTest { path, block_size, threads, batch_kib, batch_sectors, data_type, data_file, direct_io, preallocate } => {
            let file_path = resolve_file_path(path, &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 { log_simple(&log_file_arc_opt, None, "Block size 0 specified for FullTest, defaulting to 4096 bytes."); actual_block_size_u64 = 4096; }
            if direct_io && actual_block_size_u64 % 512 != 0 { let msg = format!("ERROR: Direct I/O for FullTest, block size {} not multiple of 512.", actual_block_size_u64); log_simple(&log_file_arc_opt, None, &msg); return Err(io::Error::new(ErrorKind::InvalidInput, msg)); }
            log_simple(&log_file_arc_opt, None, format!("Effective block size: {} bytes", actual_block_size_u64));
            log_simple(&log_file_arc_opt, None, format!("Threads: {}", threads));
            log_simple(&log_file_arc_opt, None, format!("Direct I/O: {}", direct_io));
            log_simple(&log_file_arc_opt, None, format!("Preallocate: {}", preallocate));
            let pattern = match data_type {
                DataTypeChoice::Hex => DataTypePattern::Hex, DataTypeChoice::Text => DataTypePattern::Text, DataTypeChoice::Binary => DataTypePattern::Binary,
                DataTypeChoice::File => {
                    let df_path = data_file.ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "--data-file required for --data-type=file"))?;
                    if let Ok(metadata) = fs::metadata(&df_path) { let file_len = metadata.len(); log_simple(&log_file_arc_opt, None, format!("Loading data pattern from file: {} (Size: {} bytes)", df_path.display(), file_len)); if file_len > 1024 * 1024 * 100 { log_simple(&log_file_arc_opt, None, format!("WARNING: Data file is large ({} bytes).", file_len)); } }
                    else { log_simple(&log_file_arc_opt, None, format!("Loading data pattern from file: {} (metadata read failed)", df_path.display())); }
                    DataTypePattern::File(fs::read(&df_path).map_err(|e| io::Error::new(e.kind(), format!("Failed to read data_file {}: {}", df_path.display(), e)))?)
                }
            };
            log_simple(&log_file_arc_opt, None, format!("Data pattern: {:?}", data_type));
            let actual_batch_size_sectors_calc = if let Some(kib) = batch_kib { (kib.saturating_mul(1024)) / actual_block_size_u64 } else { batch_sectors as u64 };
            let actual_batch_size_sectors = cmp::max(1, actual_batch_size_sectors_calc as usize);
            log_simple(&log_file_arc_opt, None, format!("Effective batch size: {} sectors ({} bytes per batch)", actual_batch_size_sectors, actual_batch_size_sectors as u64 * actual_block_size_u64));
            let counters_arc = Arc::new(ErrorCounters::new());
            full_reliability_test(&file_path, &log_file_arc_opt, &counters_arc, actual_block_size_u64, threads, pattern, actual_batch_size_sectors, direct_io, preallocate)?;
            let write_errs = counters_arc.write_errors.load(Ordering::Relaxed); let read_errs = counters_arc.read_errors.load(Ordering::Relaxed); let mismatches = counters_arc.mismatches.load(Ordering::Relaxed);
            let total_errors = write_errs + read_errs + mismatches;
            log_simple(&log_file_arc_opt, None, "--- Reliability Test Summary ---");
            log_simple(&log_file_arc_opt, None, format!("  Write Errors: {}", write_errs)); log_simple(&log_file_arc_opt, None, format!("  Read Errors:  {}", read_errs)); log_simple(&log_file_arc_opt, None, format!("  Mismatches:   {}", mismatches)); log_simple(&log_file_arc_opt, None, format!("  Total Errors: {}", total_errors));
            if total_errors == 0 && !HAS_FATAL_ERROR.load(Ordering::SeqCst) { log_simple(&log_file_arc_opt, None, "All checks passed. No errors detected."); }
            else { log_simple(&log_file_arc_opt, None, format!("Test completed with {} non-fatal errors.", total_errors)); if HAS_FATAL_ERROR.load(Ordering::SeqCst) { log_simple(&log_file_arc_opt, None, "A fatal error was also encountered."); } return Err(io::Error::new(ErrorKind::Other, format!("Test finished with {} errors and/or fatal error.", total_errors))); }
        }
        Commands::ReadSector { path, sector, block_size, direct_io } => {
            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size; if actual_block_size_u64 == 0 { log_simple(&log_file_arc_opt, None, "Block size 0 for ReadSector, defaulting to 4096."); actual_block_size_u64 = 4096; }
            if direct_io && actual_block_size_u64 % 512 != 0 { let msg = format!("ERROR: Direct I/O for ReadSector, block size {} not multiple of 512.", actual_block_size_u64); log_simple(&log_file_arc_opt, None, &msg); return Err(io::Error::new(ErrorKind::InvalidInput, msg)); }
            single_sector_read(&log_file_arc_opt, &file_path, sector, actual_block_size_u64 as usize, direct_io)?;
        }
        Commands::RangeRead { path, start_sector, end_sector, block_size, direct_io } => {
            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size; if actual_block_size_u64 == 0 { log_simple(&log_file_arc_opt, None, "Block size 0 for RangeRead, defaulting to 4096."); actual_block_size_u64 = 4096; }
            if direct_io && actual_block_size_u64 % 512 != 0 { let msg = format!("ERROR: Direct I/O for RangeRead, block size {} not multiple of 512.", actual_block_size_u64); log_simple(&log_file_arc_opt, None, &msg); return Err(io::Error::new(ErrorKind::InvalidInput, msg)); }
            range_read(&log_file_arc_opt, &file_path, start_sector, end_sector, actual_block_size_u64 as usize, direct_io)?;
        }
        Commands::RangeWrite { path, start_sector, end_sector, block_size, data_type, data_file, direct_io } => {
            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size; if actual_block_size_u64 == 0 { log_simple(&log_file_arc_opt, None, "Block size 0 for RangeWrite, defaulting to 4096."); actual_block_size_u64 = 4096; }
            if direct_io && actual_block_size_u64 % 512 != 0 { let msg = format!("ERROR: Direct I/O for RangeWrite, block size {} not multiple of 512.", actual_block_size_u64); log_simple(&log_file_arc_opt, None, &msg); return Err(io::Error::new(ErrorKind::InvalidInput, msg)); }
            let pattern = match data_type {
                DataTypeChoice::Hex => DataTypePattern::Hex, DataTypeChoice::Text => DataTypePattern::Text, DataTypeChoice::Binary => DataTypePattern::Binary,
                DataTypeChoice::File => {
                    let df_path = data_file.ok_or_else(|| io::Error::new(ErrorKind::InvalidInput, "--data-file required"))?;
                    if let Ok(metadata) = fs::metadata(&df_path) { let file_len = metadata.len(); log_simple(&log_file_arc_opt, None, format!("RangeWrite: Loading data pattern file: {} (Size: {} bytes)", df_path.display(), file_len)); if file_len > 1024 * 1024 * 100 { log_simple(&log_file_arc_opt, None, format!("WARNING: Data file for RangeWrite is large ({} bytes).", file_len)); } }
                    DataTypePattern::File(fs::read(df_path)?)
                }
            };
            range_write(&log_file_arc_opt, &file_path, start_sector, end_sector, actual_block_size_u64 as usize, &pattern, direct_io)?;
        }
    }
    Ok(())
}