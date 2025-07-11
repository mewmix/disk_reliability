#![allow(clippy::too_many_arguments)]

// Standard library imports
use std::cmp;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem;
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Instant;

use aligned_vec::AVec as AlignedVec;
// Crates
use chrono::Local;
use clap::Parser;
use crossbeam_channel::{bounded};
use ctrlc;
use disk_tester::{run_lean_test, LeanTest};
use indicatif::{ProgressBar, ProgressStyle};
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use std::ptr;
mod hardware_info;
#[cfg(target_os = "macos")]
mod mac_usb_report;
#[cfg(all(target_os = "macos", feature = "direct"))]
mod macos_direct;
mod serial;
mod auto_tune;

// Platform-specific imports
#[cfg(all(target_os = "linux", feature = "direct"))]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(all(target_os = "windows", feature = "direct"))]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawHandle;
#[cfg(target_os = "windows")]
use winapi::shared::ntdef::LARGE_INTEGER; // Needed for FILE_ALLOCATION_INFO's AllocationSize
#[cfg(all(target_os = "windows", feature = "direct"))]
use winapi::um::winbase::{FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH};
#[cfg(target_os = "windows")]
use winapi::um::{
    fileapi::{GetDiskFreeSpaceExW, SetFileInformationByHandle, FILE_ALLOCATION_INFO},
    minwinbase::FILE_INFO_BY_HANDLE_CLASS,
    winbase::GetComputerNameW,
    winnt::{HANDLE, ULARGE_INTEGER}, // ULARGE_INTEGER is used by GetDiskFreeSpaceExW
};

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

const TEST_FILE_NAME: &str = "disk_test_file.bin";
const SAFETY_FACTOR: f64 = 0.10; // Used when test_size is not specified
#[cfg(feature = "direct")]
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
    fn new() -> Self {
        Default::default()
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

#[derive(Debug, Clone, clap::ValueEnum)]
enum DataTypeChoice {
    Hex,
    Text,
    Binary,
    File,
    Random,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum LeanTestChoice {
    #[clap(name = "seq1m-q8t1", help = "Sequential 1MiB blocks, QD8, 1 thread")]
    Seq1Mq8t1,
    #[clap(name = "seq1m-q1t1", help = "Sequential 1MiB blocks, single queue")]
    Seq1Mq1t1,
    #[clap(name = "rnd4k-q32t1", help = "Random 4KiB blocks, QD32, 1 threads")]
    Rnd4kQ32T1,
    #[clap(name = "rnd4k-q1t1", help = "Random 4KiB blocks, single queue")]
    Rnd4kQ1t1,
}

impl From<LeanTestChoice> for disk_tester::LeanTest {
    fn from(c: LeanTestChoice) -> Self {
        match c {
            LeanTestChoice::Seq1Mq8t1 => disk_tester::LeanTest::Seq1Mq8t1,
            LeanTestChoice::Seq1Mq1t1 => disk_tester::LeanTest::Seq1Mq1t1,
            LeanTestChoice::Rnd4kQ32T1 => disk_tester::LeanTest::Rnd4kQ32T1,
            LeanTestChoice::Rnd4kQ1t1 => disk_tester::LeanTest::Rnd4kQ1t1,
        }
    }
}

#[derive(Debug, Clone)]
enum DataTypePattern {
    Hex,
    Text,
    Binary,
    File(Vec<u8>),
    Random,
}

impl DataTypePattern {
    fn fill_block_inplace(&self, buffer_slice: &mut [u8], offset_sector: u64) {
        let block_size = buffer_slice.len();
        match self {
            DataTypePattern::Hex => {
                let pattern = b"0123456789ABCDEF";
                let mut tile = [0u8; 16];
                tile.copy_from_slice(pattern);
                let start_offset = (offset_sector as usize * 7) % pattern.len();
                // Create a rotated tile for the specific offset
                let mut rotated_tile = [0u8; 16];
                rotated_tile[..(16 - start_offset)].copy_from_slice(&tile[start_offset..]);
                rotated_tile[(16 - start_offset)..].copy_from_slice(&tile[..start_offset]);

                for chunk in buffer_slice.chunks_mut(16) {
                    let len = chunk.len();
                    chunk.copy_from_slice(&rotated_tile[..len]);
                }
            }
            DataTypePattern::Text => {
                let sample = b"Lorem ipsum dolor sit amet. ";
                for i in 0..block_size {
                    buffer_slice[i] = sample[((offset_sector as usize) + i) % sample.len()];
                }
            }
            DataTypePattern::Binary => {
                let mut tile = [0u8; 256];
                for i in 0..256 {
                    tile[i] = i as u8;
                }
                let start_offset = (offset_sector as usize) % 256;
                for (i, b_ref) in buffer_slice.iter_mut().enumerate() {
                    *b_ref = tile[(start_offset + i) % 256];
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
            DataTypePattern::Random => {
                let mut rng = thread_rng();
                rng.fill(buffer_slice);
            }
        }
    }
}

fn parse_size_with_suffix(s: &str) -> Result<u64, String> {
    let s_trimmed = s.trim();
    if s_trimmed.is_empty() {
        return Err("Input string is empty".to_string());
    }
    let first_non_digit_idx = s_trimmed.find(|c: char| !c.is_digit(10));
    let (num_str_candidate, suffix_candidate_orig) = match first_non_digit_idx {
        Some(idx) => {
            if idx == 0 {
                return Err(format!(
                    "Invalid format: missing numeric value in '{}'",
                    s_trimmed
                ));
            }
            s_trimmed.split_at(idx)
        }
        None => (s_trimmed, ""),
    };
    let num = num_str_candidate
        .parse::<u64>()
        .map_err(|_| format!("Invalid number: '{}' in '{}'", num_str_candidate, s_trimmed))?;
    let suffix = suffix_candidate_orig.trim_start().to_uppercase();
    match suffix.as_str() {
        "" | "B" => Ok(num),
        "K" | "KB" | "KIB" => Ok(num.saturating_mul(1024)),
        "M" | "MB" | "MIB" => Ok(num.saturating_mul(1024 * 1024)),
        "G" | "GB" | "GIB" => Ok(num.saturating_mul(1024 * 1024 * 1024)),
        "T" | "TB" | "TIB" => Ok(num.saturating_mul(1024 * 1024 * 1024 * 1024)),
        _ => Err(format!(
            "Unknown or misplaced size suffix: '{}' in '{}'",
            suffix_candidate_orig, s_trimmed
        )),
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
    #[clap(long, global = true, help = "Enable verbose logging output.")]
    verbose: bool,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    FullTest {
        #[clap(long)]
        path: Option<PathBuf>,
        #[clap(long, value_parser = parse_size_with_suffix, help = "Specify total data size to test (e.g., 10G, 512M). If not set, uses a percentage of free disk space.")]
        test_size: Option<u64>,
        #[clap(
            long,
            default_value_t = 0,
            help = "Start test operations from this sector offset within the file."
        )]
        resume_from_sector: u64,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")]
        block_size: u64,
        #[clap(long)]
        threads: Option<usize>,
        #[clap(long)]
        queue_depth: Option<usize>,
        #[clap(long, value_parser = parse_size_with_suffix)]
        batch_size: Option<u64>,
        #[clap(long, value_enum, default_value = "binary")]
        data_type: DataTypeChoice,
        #[clap(long)]
        data_file: Option<PathBuf>,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
        #[clap(long)]
        preallocate: bool,
        #[clap(
            long,
            help = "Alternate between random and sequential patterns during writes"
        )]
        dual_pattern: bool,
        #[clap(
            long,
            help = "Verify data in a separate pass after all writes are complete, instead of immediately after each write."
        )]
        deferred_verify: bool,
        #[clap(
            long,
            default_value_t = 1,
            help = "Number of passes for the full test (max 3)."
        )]
        passes: usize,
    },
    Bench {
        #[clap(long)]
        path: Option<PathBuf>,
        #[clap(long, value_enum, default_value = "seq1m-q8t1")]
        mode: LeanTestChoice,
        #[clap(long, help = "Emit output in JSON format")]
        json: bool,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
    },
    ReadSector {
        #[clap(long)]
        path: PathBuf,
        #[clap(long)]
        sector: u64,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")]
        block_size: u64,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
    },
    WriteSector {
        #[clap(long)]
        path: PathBuf,
        #[clap(long)]
        sector: u64,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")]
        block_size: u64,
        #[clap(long, value_enum, default_value = "binary")]
        data_type: DataTypeChoice,
        #[clap(long)]
        data_file: Option<PathBuf>,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
    },
    RangeRead {
        #[clap(long)]
        path: PathBuf,
        #[clap(long)]
        start_sector: u64,
        #[clap(
            long,
            help = "End sector number (exclusive). If 0 or not provided, reads to end of file."
        )]
        end_sector: Option<u64>,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")]
        block_size: u64,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
    },
    RangeWrite {
        #[clap(long)]
        path: PathBuf,
        #[clap(long)]
        start_sector: u64,
        #[clap(long)]
        end_sector: u64, // Exclusive
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")]
        block_size: u64,
        #[clap(long, value_enum, default_value = "binary")]
        data_type: DataTypeChoice,
        #[clap(long)]
        data_file: Option<PathBuf>,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
    },
    VerifyRange {
        #[clap(long)]
        path: PathBuf,
        #[clap(long)]
        start_sector: u64,
        #[clap(
            long,
            help = "End sector number (exclusive). If 0 or not provided, verifies to end of file."
        )]
        end_sector: Option<u64>,
        #[clap(long, value_parser = parse_size_with_suffix, default_value = "4K")]
        block_size: u64,
        #[clap(long, value_enum, default_value = "binary")]
        data_type: DataTypeChoice,
        #[clap(long)]
        data_file: Option<PathBuf>,
        #[cfg(feature = "direct")]
        #[clap(long)]
        direct_io: bool,
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
        "[{}] [THREAD {}] {} at absolute file sector {}: {}\n", // Clarified sector meaning
        ts, thread_idx, category, sector, err_desc
    );
    if let Some(p) = path {
        error_message.push_str(&format!("File path context: {}\n", p.display()));
    }

    const MAX_DUMP_LEN: usize = 64;

    let expected_label = if category.contains("Mismatch") {
        "Expected"
    } else {
        "Intended Data"
    };

    if let Some(exp) = expected {
        let exp_slice = &exp[..cmp::min(exp.len(), MAX_DUMP_LEN)];
        error_message.push_str(&format!(
            "{} (first {} bytes): {:02X?}\n",
            expected_label,
            exp_slice.len(),
            exp_slice
        ));
    }

    if let Some(act) = actual {
        let act_slice = &act[..cmp::min(act.len(), MAX_DUMP_LEN)];
        error_message.push_str(&format!(
            "Actual   (first {} bytes): {:02X?}\n",
            act_slice.len(),
            act_slice
        ));
    }

    log_message_internal(log_f, pb, error_message);
}

#[cfg(target_os = "linux")]
fn get_hostname_os_impl() -> io::Result<String> {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}
#[cfg(target_os = "macos")]
fn get_hostname_os_impl() -> io::Result<String> {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&x| x == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).into_owned())
}
#[cfg(target_os = "windows")]
fn get_hostname_os_impl() -> io::Result<String> {
    use std::os::windows::ffi::OsStringExt;
    let mut buffer_size = 0;
    unsafe { GetComputerNameW(ptr::null_mut(), &mut buffer_size) };
    if buffer_size == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer: Vec<u16> = vec![0; buffer_size as usize];
    if unsafe { GetComputerNameW(buffer.as_mut_ptr(), &mut buffer_size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(
        std::ffi::OsString::from_wide(&buffer[..buffer_size as usize])
            .to_string_lossy()
            .into_owned(),
    )
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn get_hostname_os_impl() -> io::Result<String> {
    Ok("Hostname_Not_Implemented_For_This_OS".to_string())
}

fn get_host_info() -> io::Result<String> {
    let hostname = get_hostname_os_impl()?;
    Ok(format!(
        "Host: {}, OS: {}, Architecture: {}",
        hostname,
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
}

#[cfg(target_family = "unix")]
fn get_free_space(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let c_path_str = path.as_os_str().as_bytes();
    let path_for_cstring = if c_path_str.is_empty() {
        Path::new(".")
    } else {
        path
    };
    let c_path = CString::new(path_for_cstring.as_os_str().as_bytes()).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("Invalid path for CString: {}", e),
        )
    })?;
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
        path_for_api = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
    }
    if path_for_api.as_os_str().is_empty() {
        path_for_api = Path::new(".").to_path_buf();
    }
    let mut wide: Vec<u16> = path_for_api.as_os_str().encode_wide().collect();
    if wide.last() != Some(&0) {
        wide.push(0);
    } // Ensure null termination for Windows API
    let mut free_bytes_available: ULARGE_INTEGER = unsafe { mem::zeroed() };
    let mut total_number_of_bytes: ULARGE_INTEGER = unsafe { mem::zeroed() };
    let mut total_number_of_free_bytes: ULARGE_INTEGER = unsafe { mem::zeroed() };
    if unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes_available,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { *free_bytes_available.QuadPart() })
}

fn get_disk_info(path: &Path) -> io::Result<String> {
    let free_space = get_free_space(path)?;
    let (formatted_free, unit) = format_bytes_int(free_space);
    Ok(format!(
        "Disk Free Space (for path: {}): {} {}",
        path.display(),
        formatted_free,
        unit
    ))
}

fn open_file_options(
    _path: &Path,
    read: bool,
    write: bool,
    create: bool,
    direct_io: bool,
    _log_f: &Option<Arc<Mutex<File>>>,
) -> OpenOptions {
    let mut opts = OpenOptions::new();
    if read {
        opts.read(true);
    }
    if write {
        opts.write(true);
    }
    if create {
        opts.create(true);
    }

    if direct_io {
        #[cfg(feature = "direct")]
        {
            #[cfg(target_os = "linux")]
            {
                // This message is now logged only once in main_logic to avoid spamming from multiple threads
                opts.custom_flags(libc::O_DIRECT);
            }
            #[cfg(target_os = "windows")]
            {
                opts.custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH);
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            {
                // No action, message logged in main_logic
            }
        }
        #[cfg(not(feature = "direct"))]
        {
            // Suppress unused variable warning if direct_io is always false
            let _ = direct_io;
        }
    }

    opts
}

/// Wrapper around `open_file_options().open()` that, on macOS+direct,
/// activates F_NOCACHE / F_RDAHEAD once the FD is live.
fn open_file<P: AsRef<Path>>(
    path: P,
    read: bool,
    write: bool,
    create: bool,
    direct_io: bool,
    log_f: &Option<Arc<Mutex<File>>>,
) -> io::Result<File> {
    let file =
        open_file_options(path.as_ref(), read, write, create, direct_io, log_f).open(&path)?;

    #[cfg(all(target_os = "macos", feature = "direct"))]
    {
        if direct_io {
            match macos_direct::enable_nocache(&file) {
                Ok(_) => log_simple(
                    log_f,
                    None,
                    "F_NOCACHE active – I/O is now uncached on macOS.",
                ),
                Err(e) => log_simple(
                    log_f,
                    None,
                    format!(
                        "\u{26a0}\u{fe0f}  Unable to set F_NOCACHE: {e} (falling back to buffered I/O)"
                    ),
                ),
            }
        }
    }
    Ok(file)
}

/// Allocates an `AlignedVec` of `len` zero-filled bytes.
#[inline]
fn alloc_buffer(len: usize, direct: bool) -> AlignedVec<u8> {
    let align = if direct {
        #[cfg(feature = "direct")]
        {
            DIRECT_IO_ALIGNMENT
        }
        #[cfg(not(feature = "direct"))]
        {
            1
        }
    } else {
        1
    };

    // return value (no semicolon!)
    AlignedVec::from_iter(align, std::iter::repeat(0u8).take(len))
}

fn single_sector_read(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    sector: u64,
    block_size: usize,
    direct_io: bool,
) -> io::Result<()> {
    log_simple(
        log_f,
        None,
        format!("Initiating Single-Sector Read @ sector {}", sector),
    );
    let mut file = open_file(file_path, true, false, false, direct_io, log_f)?;
    let offset = sector.saturating_mul(block_size as u64);

    // Check if file is large enough before seeking & reading
    let file_len = file.metadata()?.len();
    if offset >= file_len {
        let msg = format!(
            "Error: Sector offset {} ({} bytes) is beyond end of file ({} bytes). Cannot read.",
            sector, offset, file_len
        );
        log_simple(log_f, None, &msg);
        return Err(io::Error::new(ErrorKind::UnexpectedEof, msg));
    }
    if offset.saturating_add(block_size as u64) > file_len {
        let msg = format!("Warning: Sector {} read ({} bytes) extends partially beyond EOF ({} bytes). Will attempt partial read if possible or error.", sector, block_size, file_len);
        log_simple(log_f, None, &msg);
        // read_exact will error if it can't fill the buffer. This is usually desired.
    }

    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = alloc_buffer(block_size, direct_io);
    if let Err(e) = file.read_exact(buffer.as_mut_slice()) {
        log_error(
            log_f,
            None,
            0,
            sector,
            "Read Error",
            &e.to_string(),
            None,
            None,
            Some(file_path.to_path_buf()),
        );
        return Err(e);
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
        log_f,
        None,
        format!(
            "Successfully read {} bytes @ sector {}.\nHex Dump:\n{}",
            block_size, sector, hex_dump
        ),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_size_with_suffix() {
        assert_eq!(parse_size_with_suffix("1K").unwrap(), 1024);
        assert_eq!(parse_size_with_suffix("1KB").unwrap(), 1024);
        assert_eq!(parse_size_with_suffix("1MiB").unwrap(), 1024 * 1024);
        assert_eq!(
            parse_size_with_suffix("2G").unwrap(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(parse_size_with_suffix("1tb").unwrap(), 1024_u64.pow(4));
        assert_eq!(parse_size_with_suffix("256").unwrap(), 256);
        assert_eq!(parse_size_with_suffix(" 512k ").unwrap(), 512 * 1024);
        assert!(parse_size_with_suffix("abc").is_err());
    }

    #[test]
    fn test_format_bytes_int() {
        assert_eq!(format_bytes_int(512), (512, "Bytes"));
        assert_eq!(format_bytes_int(1536), (1, "KiB"));
        assert_eq!(format_bytes_int(3 * 1024 * 1024), (3, "MiB"));
        assert_eq!(format_bytes_int(5 * 1024 * 1024 * 1024), (5, "GiB"));
    }

    #[test]
    fn test_format_bytes_float() {
        assert_eq!(format_bytes_float(512), (512.0, "Bytes"));
        assert_eq!(format_bytes_float(2048), (2.0, "KiB"));
        assert_eq!(format_bytes_float(3 * 1024 * 1024), (3.0, "MiB"));
        assert_eq!(format_bytes_float(2 * 1024 * 1024 * 1024), (2.0, "GiB"));
    }

    #[test]
    fn test_data_pattern_fill_block() {
        let mut buf = vec![0u8; 16];
        DataTypePattern::Hex.fill_block_inplace(&mut buf, 0);
        assert_eq!(&buf, b"0123456789ABCDEF");

        DataTypePattern::Binary.fill_block_inplace(&mut buf, 1);
        let expected: Vec<u8> = (1u8..=16).collect();
        assert_eq!(buf, expected);

        DataTypePattern::Text.fill_block_inplace(&mut buf, 0);
        assert!(std::str::from_utf8(&buf).unwrap().starts_with("Lorem"));

        let mut buf_file = vec![0u8; 6];
        let src = b"ABCD".to_vec();
        DataTypePattern::File(src.clone()).fill_block_inplace(&mut buf_file, 0);
        assert_eq!(&buf_file, b"ABCDAB");
        DataTypePattern::File(src).fill_block_inplace(&mut buf_file, 1);
        assert_eq!(&buf_file, b"CDABCD");

        let mut random_buf = vec![0u8; 32];
        DataTypePattern::Random.fill_block_inplace(&mut random_buf, 0);
        // ensure not all zeros
        assert!(random_buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_single_sector_write_and_read() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path();
        let log: Option<Arc<Mutex<File>>> = None;

        let pattern = DataTypePattern::Binary;
        single_sector_write(&log, path, 0, 16, &pattern, false).unwrap();

        let mut file = File::open(path).unwrap();
        let mut buf = vec![0u8; 16];
        file.read_exact(&mut buf).unwrap();
        let mut expected = vec![0u8; 16];
        pattern.fill_block_inplace(&mut expected, 0);
        assert_eq!(buf, expected);

        single_sector_read(&log, path, 0, 16, false).unwrap();
    }

    #[test]
    fn test_dual_pattern_split_in_batch() {
        let block_size = 8;
        let sectors = 4;
        let pattern = DataTypePattern::Binary;
        let mut buf = vec![0u8; block_size * sectors];
        let mut tile = vec![0u8; block_size];
        let split = sectors / 2;
        for i in 0..sectors {
            let abs = i as u64;
            if i < split {
                pattern.fill_block_inplace(&mut tile, abs);
            } else {
                DataTypePattern::Random.fill_block_inplace(&mut tile, abs);
            }
            let start = i * block_size;
            buf[start..start + block_size].copy_from_slice(&tile);
        }

        let mut expected_first = vec![0u8; block_size];
        pattern.fill_block_inplace(&mut expected_first, 0);
        assert_eq!(&buf[0..block_size], &expected_first);

        let mut expected_second = vec![0u8; block_size];
        pattern.fill_block_inplace(&mut expected_second, split as u64);
        assert_ne!(
            &buf[split * block_size..(split + 1) * block_size],
            &expected_second
        );
    }
}

fn single_sector_write(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    sector: u64,
    block_size: usize,
    data_pattern: &DataTypePattern,
    direct_io: bool,
) -> io::Result<()> {
    log_simple(
        log_f,
        None,
        format!("Initiating Single-Sector Write @ sector {}", sector),
    );
    let mut file = open_file(file_path, false, true, true, direct_io, log_f)?;

    let offset = sector.saturating_mul(block_size as u64);
    let required_len_for_write = offset.saturating_add(block_size as u64);

    let current_len = file.metadata()?.len();
    if current_len < required_len_for_write {
        log_simple(
            log_f,
            None,
            format!(
                "File current size {} bytes. Extending to {} bytes to accommodate write at sector {}.",
                current_len, required_len_for_write, sector
            ),
        );
        file.set_len(required_len_for_write)?;
    }

    file.seek(SeekFrom::Start(offset))?;

    let mut buffer_to_write = alloc_buffer(block_size, direct_io);
    data_pattern.fill_block_inplace(buffer_to_write.as_mut_slice(), sector); // Use `sector` as the global offset for pattern generation

    if let Err(e) = file.write_all(buffer_to_write.as_slice()) {
        log_error(
            log_f,
            None,
            0,
            sector,
            "Write Error",
            &e.to_string(),
            Some(buffer_to_write.as_slice()),
            None,
            Some(file_path.to_path_buf()),
        );
        return Err(e);
    }

    log_simple(
        log_f,
        None,
        format!(
            "Successfully wrote {} bytes with selected pattern @ sector {}.",
            block_size, sector
        ),
    );
    Ok(())
}

fn range_read(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    start_sector: u64,
    end_sector_opt: Option<u64>,
    block_size: usize,
    direct_io: bool,
    verbose: bool,
) -> io::Result<()> {
    let mut file = open_file(file_path, true, false, false, direct_io, log_f)?;
    let file_len_bytes = file.metadata()?.len();
    let file_len_sectors = if block_size > 0 {
        file_len_bytes / block_size as u64
    } else {
        0
    };
    let actual_end_sector = match end_sector_opt {
        Some(0) | None => file_len_sectors,
        Some(end) => {
            if end <= start_sector {
                let msg =
                    "Invalid range: end_sector must be greater than start_sector if specified and not 0.";
                log_simple(log_f, None, msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            cmp::min(end, file_len_sectors)
        }
    };
    if actual_end_sector <= start_sector && file_len_sectors > 0 && start_sector > 0 {
        log_simple(
            log_f,
            None,
            format!(
                "Start sector {} is at or beyond end of file ({} sectors). Nothing to read.",
                start_sector, file_len_sectors
            ),
        );
        return Ok(());
    } else if actual_end_sector == 0 && start_sector == 0 && file_len_sectors == 0 {
        log_simple(log_f, None, "File is empty. Nothing to read.");
        return Ok(());
    }
    log_simple(
        log_f,
        None,
        format!(
            "Starting Range Read from sector {} to {} (exclusive)",
            start_sector, actual_end_sector
        ),
    );
    let mut buffer = alloc_buffer(block_size, direct_io);
    for sector_idx in start_sector..actual_end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            log_simple(log_f, None, "Range read interrupted by user.");
            break;
        }
        let offset = sector_idx.saturating_mul(block_size as u64);
        if offset >= file_len_bytes && file_len_bytes > 0 {
            log_simple(
                log_f,
                None,
                format!(
                    "Attempted to seek past EOF at sector {}. Stopping range read.",
                    sector_idx
                ),
            );
            break;
        }
        if let Err(e) = file.seek(SeekFrom::Start(offset)) {
            log_error(
                log_f,
                None,
                0,
                sector_idx,
                "Seek Error",
                &e.to_string(),
                None,
                None,
                Some(file_path.to_path_buf()),
            );
            continue;
        }
        if let Err(e) = file.read_exact(buffer.as_mut_slice()) {
            log_error(
                log_f,
                None,
                0,
                sector_idx,
                "Read Error",
                &e.to_string(),
                None,
                None,
                Some(file_path.to_path_buf()),
            );
            continue;
        }
        if cfg!(debug_assertions) || verbose {
            let preview_len = cmp::min(16, buffer.len());
            let preview = &buffer.as_slice()[..preview_len];
            log_simple(
                log_f,
                None,
                format!(
                    "[Sector {}] First {} bytes in hex: {:02X?}",
                    sector_idx, preview_len, preview
                ),
            );
        }
    }
    log_simple(log_f, None, "Range read operation completed.");
    Ok(())
}

fn range_write(
    log_f: &Option<Arc<Mutex<File>>>,
    file_path: &Path,
    start_sector: u64,
    end_sector: u64, // Exclusive
    block_size: usize,
    data_pattern: &DataTypePattern,
    direct_io: bool,
) -> io::Result<()> {
    if end_sector <= start_sector {
        let msg = "Invalid range: end_sector must be greater than start_sector.";
        log_simple(log_f, None, msg);
        return Err(io::Error::new(ErrorKind::InvalidInput, msg));
    }
    log_simple(
        log_f,
        None,
        format!(
            "Starting Range Write from sector {} to {} (exclusive)",
            start_sector, end_sector
        ),
    );
    let mut file = open_file(file_path, true, true, true, direct_io, log_f)?;

    let required_len_for_write = end_sector.saturating_mul(block_size as u64);
    let current_len = file.metadata()?.len();
    if current_len < required_len_for_write {
        log_simple(
            log_f,
            None,
            format!(
                "File current size {} bytes. Extending to {} bytes to accommodate range write.",
                current_len, required_len_for_write
            ),
        );
        file.set_len(required_len_for_write)?;
    }

    let mut buffer_to_write = alloc_buffer(block_size, direct_io);
    for sector_idx in start_sector..end_sector {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            log_simple(log_f, None, "Range write interrupted by user.");
            break;
        }
        data_pattern.fill_block_inplace(buffer_to_write.as_mut_slice(), sector_idx); // Use absolute sector_idx for pattern
        let offset = sector_idx.saturating_mul(block_size as u64);
        if let Err(e) = file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| file.write_all(buffer_to_write.as_slice()))
        {
            log_error(
                log_f,
                None,
                0,
                sector_idx,
                "Write Error",
                &e.to_string(),
                Some(buffer_to_write.as_slice()),
                None,
                Some(file_path.to_path_buf()),
            );
            continue; // Optionally, could return Err(e) to stop on first error
        }
    }
    log_simple(log_f, None, "Range write operation completed.");
    Ok(())
}

fn range_verify(
    log_f: &Option<Arc<Mutex<File>>>,
    counters_arc: &Arc<ErrorCounters>,
    file_path: &Path,
    start_sector: u64,
    end_sector_opt: Option<u64>,
    block_size: usize,
    data_pattern: &DataTypePattern,
    direct_io: bool,
) -> io::Result<()> {
    let mut file = open_file(file_path, true, false, false, direct_io, log_f)?;
    let file_len_bytes = file.metadata()?.len();
    let file_len_sectors = if block_size > 0 {
        file_len_bytes / block_size as u64
    } else {
        0
    };

    let actual_end_sector = match end_sector_opt {
        Some(0) | None => file_len_sectors,
        Some(end) => {
            if end <= start_sector {
                let msg = "Invalid range for verification: end_sector must be greater than start_sector if specified and not 0.";
                log_simple(log_f, None, msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            cmp::min(end, file_len_sectors)
        }
    };

    if actual_end_sector <= start_sector {
        if file_len_sectors == 0 && start_sector == 0 {
            log_simple(log_f, None, "File is empty. Nothing to verify.");
        } else {
            log_simple(log_f, None, format!("Start sector {} is at or beyond end of specified/actual file range ({} sectors). Nothing to verify.", start_sector, actual_end_sector));
        }
        return Ok(());
    }

    log_simple(
        log_f,
        None,
        format!(
            "Starting Range Verify from sector {} to {} (exclusive)",
            start_sector, actual_end_sector
        ),
    );

    let total_sectors_to_verify = actual_end_sector.saturating_sub(start_sector);
    if total_sectors_to_verify == 0 {
        // Should be caught by above, but defensive.
        log_simple(log_f, None, "No sectors in range to verify.");
        return Ok(());
    }

    let pb = ProgressBar::new(total_sectors_to_verify);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta_precise}) Mismatches: {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb.set_message("0"); // Initial mismatches
    let pb_arc = Arc::new(pb);

    let mut read_buffer = alloc_buffer(block_size, direct_io);
    let mut expected_buffer = alloc_buffer(block_size, false); // Pattern buffer, standard alignment ok

    let mut local_mismatches = 0;

    for sector_idx_offset in 0..total_sectors_to_verify {
        if STOP_REQUESTED.load(Ordering::SeqCst) {
            log_simple(log_f, Some(&pb_arc), "Range verify interrupted by user.");
            break;
        }

        let current_sector_absolute = start_sector + sector_idx_offset;
        let offset_bytes = current_sector_absolute.saturating_mul(block_size as u64);

        if offset_bytes >= file_len_bytes {
            // Should not happen if actual_end_sector is derived from file_len_sectors
            log_simple(
                log_f,
                Some(&pb_arc),
                format!(
                    "Attempted to read past EOF at sector {}. Stopping range verify.",
                    current_sector_absolute
                ),
            );
            break;
        }

        if let Err(e) = file.seek(SeekFrom::Start(offset_bytes)) {
            log_error(
                log_f,
                Some(&pb_arc),
                0,
                current_sector_absolute,
                "Seek Error",
                &e.to_string(),
                None,
                None,
                Some(file_path.to_path_buf()),
            );
            counters_arc.increment_read_errors();
            pb_arc.inc(1);
            continue;
        }

        if let Err(e) = file.read_exact(read_buffer.as_mut_slice()) {
            log_error(
                log_f,
                Some(&pb_arc),
                0,
                current_sector_absolute,
                "Read Error",
                &e.to_string(),
                None,
                None,
                Some(file_path.to_path_buf()),
            );
            counters_arc.increment_read_errors();
            pb_arc.inc(1);
            continue;
        }

        data_pattern.fill_block_inplace(expected_buffer.as_mut_slice(), current_sector_absolute);

        if read_buffer.as_slice() != expected_buffer.as_slice() {
            local_mismatches += 1;
            counters_arc.increment_mismatches();
            log_error(
                log_f,
                Some(&pb_arc),
                0,
                current_sector_absolute,
                "Data Mismatch",
                "Block content mismatch during verification",
                Some(expected_buffer.as_slice()),
                Some(read_buffer.as_slice()),
                Some(file_path.to_path_buf()),
            );
            pb_arc.set_message(format!("{}", local_mismatches));
        }
        pb_arc.inc(1);
    }

    if !pb_arc.is_finished() {
        pb_arc.finish_with_message(format!("Completed. Mismatches: {}", local_mismatches));
    }
    log_simple(
        log_f,
        None,
        format!(
            "Range verify operation completed. Total mismatches found: {}",
            local_mismatches
        ),
    );
    if local_mismatches > 0 || counters_arc.read_errors.load(Ordering::Relaxed) > 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{} mismatches and {} read/seek errors found during verification.",
                local_mismatches,
                counters_arc.read_errors.load(Ordering::Relaxed)
            ),
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    let mut allocation_size_li: LARGE_INTEGER = unsafe { mem::zeroed() };
    unsafe {
        *allocation_size_li.QuadPart_mut() = size as i64;
    }
    let info = FILE_ALLOCATION_INFO {
        AllocationSize: allocation_size_li,
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
        log_simple(
            log_f,
            None,
            format!(
                "SetFileInformationByHandle for pre-allocation failed: {}. Falling back to set_len.",
                err
            ),
        );
        file.set_len(size) // Fallback
    } else {
        // After a successful SetFileInformationByHandle, the file size is already updated;
        // a second set_len() is redundant.
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    log_simple(
        log_f,
        None,
        format!("Attempting posix_fallocate for {} bytes...", size),
    );
    let ret = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, size as libc::off_t) };
    if ret != 0 {
        let err = io::Error::from_raw_os_error(ret);
        log_simple(
            log_f,
            None,
            format!(
                "posix_fallocate failed (errno {}): {}. Falling back to set_len.",
                ret, err
            ),
        );
        file.set_len(size)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    #[repr(C)]
    struct Fstore {
        fst_flags: u32,
        fst_posmode: i32,
        fst_offset: i64,
        fst_length: i64,
        fst_bytesalloc: i64,
    }
    const F_ALLOCATECONTIG: u32 = 0x2;
    const F_ALLOCATEALL: u32 = 0x4;
    const F_PEOFPOSMODE: i32 = 3;
    let mut store = Fstore {
        fst_flags: F_ALLOCATECONTIG,
        fst_posmode: F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: size as i64,
        fst_bytesalloc: 0,
    };
    let fd = file.as_raw_fd();
    let ret = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &store) };
    if ret == -1 {
        store.fst_flags = F_ALLOCATEALL;
        let ret_all = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &store) };
        if ret_all == -1 {
            log_simple(
                log_f,
                None,
                format!(
                    "F_PREALLOCATE failed: {}. Falling back to set_len.",
                    io::Error::last_os_error()
                ),
            );
            return file.set_len(size);
        }
    }
    file.set_len(size)?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn preallocate_file_os(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    log_simple(
        log_f,
        None,
        "True pre-allocation not supported on this OS. Using set_len.",
    );
    file.set_len(size)
}

fn preallocate_file(file: &File, size: u64, log_f: &Option<Arc<Mutex<File>>>) -> io::Result<()> {
    log_simple(
        log_f,
        None,
        format!(
            "Pre-allocating file to {} bytes (physical where possible)...",
            size
        ),
    );
    preallocate_file_os(file, size, log_f)
}

#[inline]
fn mib_s(bytes: u64, secs: f64) -> f64 {
    if secs > 0.0 {
        (bytes as f64 / 1_048_576.0) / secs
    } else {
        0.0
    }
}

fn full_reliability_test(
    file_path: &Path,
    log_f_opt: &Option<Arc<Mutex<File>>>,
    counters_arc: &Arc<ErrorCounters>,
    user_specified_test_size: Option<u64>,
    resume_from_sector: u64, // Absolute sector in file to start test operations
    block_size_u64: u64,
    num_threads: usize,
    queue_depth: usize,
    data_pattern: DataTypePattern,
    batch_size_sectors: usize,
    direct_io: bool,
    preallocate: bool,
    dual_pattern: bool,
    deferred_verify: bool,
    _verbose: bool,
) -> io::Result<()> {
    let block_size_usize = block_size_u64 as usize;
    if block_size_u64 == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "Block size cannot be zero.",
        ));
    }

    let parent_dir_for_space = file_path.parent().map_or_else(
        || Path::new("."),
        |p| {
            if p.as_os_str().is_empty() {
                Path::new(".")
            } else {
                p
            }
        },
    );
    let free_space_on_volume = get_free_space(parent_dir_for_space)?;

    let start_offset_bytes_for_resume = resume_from_sector.saturating_mul(block_size_u64);

    let (actual_bytes_to_test, required_total_file_size) = if let Some(requested_size_from_user) =
        user_specified_test_size
    {
        let aligned_requested_data_size =
            (requested_size_from_user / block_size_u64) * block_size_u64;

        if aligned_requested_data_size == 0 && requested_size_from_user > 0 {
            log_simple(log_f_opt, None, format!("Warning: Requested test data size {} B is less than block size {} B. Effective data test size is 0 B.", requested_size_from_user, block_size_u64));
        }

        let calculated_total_file_footprint =
            start_offset_bytes_for_resume.saturating_add(aligned_requested_data_size);

        if calculated_total_file_footprint > free_space_on_volume {
            let (fs_fmt, fs_unit) = format_bytes_int(free_space_on_volume);
            let (req_fmt, req_unit) = format_bytes_int(calculated_total_file_footprint);
            let msg = format!(
                "Error: Test configuration requires {} {} ({} B file size: {} B resume offset + {} B test data), but only {} {} ({} B) is free on the volume.",
                req_fmt, req_unit, calculated_total_file_footprint, start_offset_bytes_for_resume, aligned_requested_data_size,
                fs_fmt, fs_unit, free_space_on_volume
            );
            log_simple(log_f_opt, None, &msg);
            return Err(io::Error::new(ErrorKind::OutOfMemory, msg));
        }
        (aligned_requested_data_size, calculated_total_file_footprint)
    } else {
        // Auto-calculate size based on free space
        if start_offset_bytes_for_resume >= free_space_on_volume {
            let (fs_fmt, fs_unit) = format_bytes_int(free_space_on_volume);
            let (start_fmt, start_unit) = format_bytes_int(start_offset_bytes_for_resume);
            let msg = format!("Error: Resume offset {} {} ({} B at sector {}) is >= available free space {} {} ({} B). Cannot test.",
                start_fmt, start_unit, start_offset_bytes_for_resume, resume_from_sector,
                fs_fmt, fs_unit, free_space_on_volume);
            log_simple(log_f_opt, None, &msg);
            return Err(io::Error::new(ErrorKind::OutOfMemory, msg));
        }
        let space_available_for_data = free_space_on_volume - start_offset_bytes_for_resume;
        let data_bytes_target_with_safety =
            (space_available_for_data as f64 * (1.0 - SAFETY_FACTOR)) as u64;
        let aligned_data_bytes_auto =
            (data_bytes_target_with_safety / block_size_u64) * block_size_u64;
        let calculated_total_file_footprint_auto =
            start_offset_bytes_for_resume.saturating_add(aligned_data_bytes_auto);
        (
            aligned_data_bytes_auto,
            calculated_total_file_footprint_auto,
        )
    };

    let (ds_test, du_test) = format_bytes_int(actual_bytes_to_test);
    let (ds_file, du_file) = format_bytes_int(required_total_file_size);

    let (file_val, file_unit) = format_bytes_float(required_total_file_size);
    let (portion_val, portion_unit) =
        format_bytes_float(batch_size_sectors as u64 * block_size_u64);
    let (buf_val, buf_unit) = format_bytes_float(block_size_u64);
    log_simple(
        log_f_opt,
        None,
        format!(
            "Using test file of {:.2} {} ({} bytes), write/read/verify {:.2} {} portions at a time using a {:.0} {} memory buffer",
            file_val,
            file_unit,
            required_total_file_size,
            portion_val,
            portion_unit,
            buf_val,
            buf_unit
        ),
    );

    log_simple(
        log_f_opt,
        None,
        format!(
            "Effective Test Data Size: {} {} ({} bytes)",
            ds_test, du_test, actual_bytes_to_test
        ),
    );
    if resume_from_sector > 0 {
        log_simple(
            log_f_opt,
            None,
            format!(
                "Test operations starting at sector: {} (file offset {} bytes)",
                resume_from_sector, start_offset_bytes_for_resume
            ),
        );
    }
    log_simple(
        log_f_opt,
        None,
        format!(
            "Required Total File Size for Test: {} {} ({} bytes)",
            ds_file, du_file, required_total_file_size
        ),
    );

    let file_for_setup = open_file(file_path, true, true, true, false, log_f_opt)?;
    if preallocate {
        preallocate_file(&file_for_setup, required_total_file_size, log_f_opt)?;
    } else {
        // Ensure file is at least this large. set_len can also truncate.
        file_for_setup.set_len(required_total_file_size)?;
    }
    drop(file_for_setup);

    let total_sectors_in_test_run = actual_bytes_to_test / block_size_u64;

    if total_sectors_in_test_run == 0 {
        log_simple(
            log_f_opt,
            None,
            "Total sectors to process in this run is 0. Test data phase will be skipped.",
        );
        if required_total_file_size > 0 {
            log_simple(log_f_opt, None, format!("Note: Test file '{}' may have been created/resized to {} bytes due to resume_from_sector or preallocation settings.", file_path.display(), required_total_file_size));
        }
        return Ok(()); // No data to test, but setup might have occurred.
    }
    log_simple(
        log_f_opt,
        None,
        format!(
            "Total Sectors in this Test Run: {}",
            total_sectors_in_test_run
        ),
    );

    let start_time = Instant::now();
    let data_pattern_arc = Arc::new(data_pattern);
    let file_path_owned = file_path.to_path_buf();

    // The main test logic is now split based on the verification strategy
    if deferred_verify {
        // ===============================================================
        // DEFERRED VERIFICATION: Write Pass -> Verify Pass
        // ===============================================================
        log_simple(log_f_opt, None, "--- Starting Write Pass ---");

        // --- WRITE PASS ---
        {
            let pb = ProgressBar::new(total_sectors_in_test_run);
            pb.set_style(
                ProgressStyle::with_template(
                    "Writing [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta_precise}) {wide_msg}",
                )
                .unwrap()
                .progress_chars("##-"),
            );
            let pb_arc = Arc::new(pb);

            enum WriteJob {
                Write {
                    abs_start_sector: u64,
                    sector_count: usize,
                    buf: AlignedVec<u8>,
                },
                Terminate,
            }
            struct WriteResult {
                abs_start_sector: u64,
                sector_count: u32,
                io_error: Option<io::Error>,
                write_secs: f64,
                buf: AlignedVec<u8>,
            }

            let (req_tx, req_rx) = bounded::<WriteJob>(queue_depth);
            let (res_tx, res_rx) = bounded::<WriteResult>(queue_depth);

            let mut workers = Vec::with_capacity(num_threads);
            for i in 0..num_threads {
                let worker_file_path = file_path_owned.clone();
                let worker_log = log_f_opt.clone();
                let worker_pb_arc = pb_arc.clone();
                let thread_req_rx = req_rx.clone();
                let thread_res_tx = res_tx.clone();

                workers.push(thread::spawn(move || {
                    let mut f = match open_file(
                        &worker_file_path,
                        false,
                        true,
                        false,
                        direct_io,
                        &worker_log,
                    ) {
                        Ok(fd) => fd,
                        Err(e) => {
                            log_simple(
                                &worker_log,
                                Some(&worker_pb_arc),
                                format!("[Thread {}] Cannot open test file for writing: {}", i, e),
                            );
                            HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                            return;
                        }
                    };

                    for job in thread_req_rx.iter() {
                        match job {
                            WriteJob::Terminate => break,
                            WriteJob::Write {
                                abs_start_sector,
                                sector_count,
                                buf,
                            } => {
                                let byte_len = sector_count * block_size_usize;
                                let byte_offs = abs_start_sector * block_size_u64;

                                let w_start = Instant::now();
                                let io_res = f
                                    .seek(SeekFrom::Start(byte_offs))
                                    .and_then(|_| f.write_all(&buf[..byte_len]));
                                let write_secs = w_start.elapsed().as_secs_f64();

                                let _ = thread_res_tx.send(WriteResult {
                                    abs_start_sector,
                                    sector_count: sector_count as u32,
                                    io_error: io_res.err(),
                                    write_secs,
                                    buf,
                                });
                            }
                        }
                    }
                }));
            }
            drop(req_rx); // Drop original rx, workers have clones.

            // Producer/Consumer on main thread
            let mut buffer_pool: Vec<_> = (0..queue_depth.max(2))
                .map(|_| alloc_buffer(batch_size_sectors * block_size_usize, direct_io))
                .collect();
            let mut pattern_tile = alloc_buffer(block_size_usize, false);

            let mut global_sector_cursor = 0u64;
            let mut jobs_in_flight = 0;

            'write_loop: loop {
                while global_sector_cursor < total_sectors_in_test_run {
                    if let Some(mut target_buf) = buffer_pool.pop() {
                        let remaining = total_sectors_in_test_run - global_sector_cursor;
                        let this_batch_sectors =
                            cmp::min(batch_size_sectors as u64, remaining) as usize;
                        let abs_first_sector = resume_from_sector + global_sector_cursor;

                        let split_point = this_batch_sectors / 2;
                        for i in 0..this_batch_sectors {
                            let current_abs_sector = abs_first_sector + i as u64;
                            if dual_pattern && i >= split_point {
                                DataTypePattern::Random
                                    .fill_block_inplace(&mut pattern_tile, current_abs_sector);
                            } else {
                                data_pattern_arc
                                    .fill_block_inplace(&mut pattern_tile, current_abs_sector);
                            }
                            let start = i * block_size_usize;
                            target_buf[start..start + block_size_usize]
                                .copy_from_slice(&pattern_tile);
                        }

                        if req_tx
                            .send(WriteJob::Write {
                                abs_start_sector: abs_first_sector,
                                sector_count: this_batch_sectors,
                                buf: target_buf,
                            })
                            .is_err()
                        {
                            break;
                        }

                        jobs_in_flight += 1;
                        global_sector_cursor += this_batch_sectors as u64;
                    } else {
                        break;
                    }
                }

                if jobs_in_flight == 0 && global_sector_cursor >= total_sectors_in_test_run {
                    break 'write_loop;
                }
                if HAS_FATAL_ERROR.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
                    break 'write_loop;
                }

                match res_rx.recv() {
                    Ok(msg) => {
                        jobs_in_flight -= 1;
                        pb_arc.inc(msg.sector_count as u64);

                        if let Some(e) = msg.io_error {
                            counters_arc.increment_write_errors();
                            log_error(
                                &log_f_opt,
                                Some(&pb_arc),
                                0,
                                msg.abs_start_sector,
                                "Write Error",
                                &e.to_string(),
                                None,
                                None,
                                Some(file_path_owned.clone()),
                            );
                        }

                        buffer_pool.push(msg.buf);
                    }
                    Err(_) => {
                        if jobs_in_flight > 0 {
                            log_simple(
                                log_f_opt,
                                Some(&pb_arc),
                                "Result channel closed; workers may have panicked.",
                            );
                            HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                        }
                        break 'write_loop;
                    }
                }
            }

            // Graceful shutdown
            for _ in 0..num_threads {
                req_tx.send(WriteJob::Terminate).ok();
            }
            drop(req_tx);
            // Drain any remaining results
            while let Ok(msg) = res_rx.try_recv() {
                pb_arc.inc(msg.sector_count as u64);
                buffer_pool.push(msg.buf);
            }
            for handle in workers {
                handle.join().expect("write worker thread panicked");
            }

            if HAS_FATAL_ERROR.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
                pb_arc.abandon_with_message("Write pass aborted.");
            } else {
                pb_arc.finish_with_message("Write pass complete.");
            }
        }

        // Abort if write pass had errors
        if HAS_FATAL_ERROR.load(Ordering::SeqCst)
            || counters_arc.write_errors.load(Ordering::Relaxed) > 0
        {
            return Err(io::Error::new(
                ErrorKind::Other,
                "Test aborted due to errors in write pass.",
            ));
        }

        log_simple(log_f_opt, None, "--- Starting Verify Pass ---");
        // --- VERIFY PASS ---
        {
            let pb = ProgressBar::new(total_sectors_in_test_run);
            pb.set_style(
                ProgressStyle::with_template(
                    "Verifying [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta_precise}) Mismatches: {msg}",
                )
                .unwrap()
                .progress_chars("##-"),
            );
            pb.set_message("0");
            let pb_arc = Arc::new(pb);

            enum VerifyJob {
                Verify {
                    abs_start_sector: u64,
                    sector_count: usize,
                },
                Terminate,
            }
            struct VerifyResult {
                abs_start_sector: u64,
                sector_count: u32,
                diff: Option<u32>,
                expected_byte: Option<u8>,
                actual_byte: Option<u8>,
                io_error: Option<io::Error>,
            }

            let (req_tx, req_rx) = bounded::<VerifyJob>(queue_depth);
            let (res_tx, res_rx) = bounded::<VerifyResult>(queue_depth);
            let mut workers = Vec::with_capacity(num_threads);
            for i in 0..num_threads {
                let worker_file_path = file_path_owned.clone();
                let worker_log = log_f_opt.clone();
                let worker_pb_arc = pb_arc.clone();
                let thread_req_rx = req_rx.clone();
                let thread_res_tx = res_tx.clone();
                let thread_data_pattern_arc = data_pattern_arc.clone();

                workers.push(thread::spawn(move || {
                    let mut f = match open_file(
                        &worker_file_path,
                        true,
                        false,
                        false,
                        direct_io,
                        &worker_log,
                    ) {
                        Ok(fd) => fd,
                        Err(e) => {
                            log_simple(
                                &worker_log,
                                Some(&worker_pb_arc),
                                format!("[Thread {}] Cannot open test file for reading: {}", i, e),
                            );
                            HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                            return;
                        }
                    };

                    let mut read_buf =
                        alloc_buffer(batch_size_sectors * block_size_usize, direct_io);
                    let mut expected_buf =
                        alloc_buffer(batch_size_sectors * block_size_usize, false);
                    let mut pattern_tile = alloc_buffer(block_size_usize, false);

                    for job in thread_req_rx.iter() {
                        match job {
                            VerifyJob::Terminate => break,
                            VerifyJob::Verify {
                                abs_start_sector,
                                sector_count,
                            } => {
                                let byte_len = sector_count * block_size_usize;
                                let byte_offs = abs_start_sector * block_size_u64;

                                let io_res = f
                                    .seek(SeekFrom::Start(byte_offs))
                                    .and_then(|_| f.read_exact(&mut read_buf[..byte_len]));

                                let mut diff = None;
                                let mut expected_b = None;
                                let mut actual_b = None;

                                if io_res.is_ok() {
                                    // Regenerate expected pattern for this batch
                                    let split_point = sector_count / 2;
                                    for i in 0..sector_count {
                                        let current_abs_sector = abs_start_sector + i as u64;
                                        if dual_pattern && i >= split_point {
                                            DataTypePattern::Random.fill_block_inplace(
                                                &mut pattern_tile,
                                                current_abs_sector,
                                            );
                                        } else {
                                            thread_data_pattern_arc.fill_block_inplace(
                                                &mut pattern_tile,
                                                current_abs_sector,
                                            );
                                        }
                                        let start = i * block_size_usize;
                                        expected_buf[start..start + block_size_usize]
                                            .copy_from_slice(&pattern_tile);
                                    }

                                    if expected_buf[..byte_len] != read_buf[..byte_len] {
                                        if let Some(idx) = expected_buf
                                            .iter()
                                            .zip(&read_buf[..byte_len])
                                            .position(|(a, b)| a != b)
                                        {
                                            diff = Some(idx as u32);
                                            expected_b = Some(expected_buf[idx]);
                                            actual_b = Some(read_buf[idx]);
                                        }
                                    }
                                }

                                let _ = thread_res_tx.send(VerifyResult {
                                    abs_start_sector,
                                    sector_count: sector_count as u32,
                                    diff,
                                    expected_byte: expected_b,
                                    actual_byte: actual_b,
                                    io_error: io_res.err(),
                                });
                            }
                        }
                    }
                }));
            }
            drop(req_rx);

            let mut global_sector_cursor = 0u64;
            let mut jobs_in_flight = 0;
            let mut local_mismatches = 0;

            'verify_loop: loop {
                while jobs_in_flight < queue_depth
                    && global_sector_cursor < total_sectors_in_test_run
                {
                    let remaining = total_sectors_in_test_run - global_sector_cursor;
                    let this_batch_sectors =
                        cmp::min(batch_size_sectors as u64, remaining) as usize;
                    let abs_first_sector = resume_from_sector + global_sector_cursor;

                    if req_tx
                        .send(VerifyJob::Verify {
                            abs_start_sector: abs_first_sector,
                            sector_count: this_batch_sectors,
                        })
                        .is_err()
                    {
                        break;
                    }
                    jobs_in_flight += 1;
                    global_sector_cursor += this_batch_sectors as u64;
                }

                if jobs_in_flight == 0 && global_sector_cursor >= total_sectors_in_test_run {
                    break 'verify_loop;
                }
                if HAS_FATAL_ERROR.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
                    break 'verify_loop;
                }

                match res_rx.recv() {
                    Ok(msg) => {
                        jobs_in_flight -= 1;
                        pb_arc.inc(msg.sector_count as u64);
                        if let Some(e) = msg.io_error {
                            counters_arc.increment_read_errors();
                            log_error(
                                &log_f_opt,
                                Some(&pb_arc),
                                0,
                                msg.abs_start_sector,
                                "Read Error",
                                &e.to_string(),
                                None,
                                None,
                                Some(file_path_owned.clone()),
                            );
                        } else if let Some(diff_offset) = msg.diff {
                            local_mismatches += 1;
                            counters_arc.increment_mismatches();
                            let detail = if let (Some(exp_b), Some(act_b)) =
                                (msg.expected_byte, msg.actual_byte)
                            {
                                format!(
                                "First mismatch at byte offset {} in batch (wrote {:02X} vs read {:02X})",
                                diff_offset, exp_b, act_b
                            )
                            } else {
                                format!("First mismatch at byte offset {} in batch", diff_offset)
                            };
                            log_error(
                                &log_f_opt,
                                Some(&pb_arc),
                                0,
                                msg.abs_start_sector,
                                "Data Mismatch",
                                &detail,
                                msg.expected_byte.as_ref().map(|b| std::slice::from_ref(b)),
                                msg.actual_byte.as_ref().map(|b| std::slice::from_ref(b)),
                                Some(file_path_owned.clone()),
                            );
                            pb_arc.set_message(format!("{}", local_mismatches));
                        }
                    }
                    Err(_) => break 'verify_loop,
                }
            }

            for _ in 0..num_threads {
                req_tx.send(VerifyJob::Terminate).ok();
            }
            drop(req_tx);
            while let Ok(msg) = res_rx.try_recv() {
                pb_arc.inc(msg.sector_count as u64);
            }
            for handle in workers {
                handle.join().expect("verify worker thread panicked");
            }

            if HAS_FATAL_ERROR.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
                pb_arc.abandon_with_message(format!(
                    "Verify pass aborted. Mismatches found: {}",
                    local_mismatches
                ));
            } else {
                pb_arc.finish_with_message(format!(
                    "Verify pass complete. Mismatches found: {}",
                    local_mismatches
                ));
            }
        }
    } else {
        // ===============================================================
        // IMMEDIATE VERIFICATION: Write -> Read -> Verify in one loop
        // ===============================================================
        let pb = ProgressBar::new(total_sectors_in_test_run);
        pb.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta_precise}) {wide_msg}",
            )
            .unwrap()
            .progress_chars("##-"),
        );
        let pb_arc = Arc::new(pb);

        enum IoJob {
            WriteReadVerify {
                abs_start_sector: u64,
                sector_count: usize,
                buf: AlignedVec<u8>,
            },
            Terminate,
        }

        struct IoResultMsg {
            abs_start_sector: u64,
            sector_count: u32,
            diff: Option<u32>,
            expected_byte: Option<u8>,
            actual_byte: Option<u8>,
            io_error: Option<io::Error>,
            write_secs_first: f64,
            read_secs_first: f64,
            write_secs_second: f64,
            read_secs_second: f64,
            buf: AlignedVec<u8>,
        }

        let (req_tx, req_rx) = bounded::<IoJob>(queue_depth);
        let (res_tx, res_rx) = bounded::<IoResultMsg>(queue_depth);

        let mut workers = Vec::with_capacity(num_threads);
        for i in 0..num_threads {
            let worker_file_path = file_path_owned.clone();
            let worker_log = log_f_opt.clone();
            let worker_pb_arc = pb_arc.clone();
            let thread_req_rx = req_rx.clone();
            let thread_res_tx = res_tx.clone();

            workers.push(thread::spawn(move || {
                let mut f = match open_file(
                    &worker_file_path,
                    true,
                    true,
                    false,
                    direct_io,
                    &worker_log,
                ) {
                    Ok(fd) => fd,
                    Err(e) => {
                        log_simple(
                            &worker_log,
                            Some(&worker_pb_arc),
                            format!("[Thread {}] Cannot open test file: {}", i, e),
                        );
                        HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                        return;
                    }
                };
                let mut read_buf =
                    alloc_buffer(batch_size_sectors * block_size_usize, direct_io);

                for job in thread_req_rx.iter() {
                    if let IoJob::WriteReadVerify {
                        abs_start_sector,
                        sector_count,
                        buf,
                    } = job
                    {
                        let byte_len = sector_count * block_size_usize;
                        let byte_offs = abs_start_sector * block_size_u64;

                        let (
                            io_res,
                            write_secs_first,
                            read_secs_first,
                            write_secs_second,
                            read_secs_second,
                        ) = if dual_pattern {
                            let split = sector_count / 2;
                            let first_len = split * block_size_usize;

                            let w0 = Instant::now();
                            let wr = f.seek(SeekFrom::Start(byte_offs)).and_then(|_| f.write_all(&buf[..first_len]));
                            let wsf = w0.elapsed().as_secs_f64();

                            let w1 = Instant::now();
                            let wr2 = f.write_all(&buf[first_len..byte_len]);
                            let wss = w1.elapsed().as_secs_f64();
                            let write_res = wr.and(wr2);

                            let r0 = Instant::now();
                            let rd = f
                                .seek(SeekFrom::Start(byte_offs))
                                .and_then(|_| f.read_exact(&mut read_buf[..first_len]));
                            let rsf = r0.elapsed().as_secs_f64();

                            let r1 = Instant::now();
                            let rd2 = f.read_exact(&mut read_buf[first_len..byte_len]);
                            let rss = r1.elapsed().as_secs_f64();
                            
                            (write_res.and(rd).and(rd2), wsf, rsf, wss, rss)
                        } else {
                            let w_start = Instant::now();
                            let w_res = f
                                .seek(SeekFrom::Start(byte_offs))
                                .and_then(|_| f.write_all(&buf[..byte_len]));
                            let write_secs = w_start.elapsed().as_secs_f64();

                            let (r_res, read_secs) = if w_res.is_ok() {
                                let r_start = Instant::now();
                                let res = f
                                    .seek(SeekFrom::Start(byte_offs))
                                    .and_then(|_| f.read_exact(&mut read_buf[..byte_len]));
                                (res, r_start.elapsed().as_secs_f64())
                            } else {
                                (Ok(()), 0.0)
                            };
                            (w_res.and(r_res), write_secs, read_secs, 0.0, 0.0)
                        };

                        let mut diff = None;
                        let mut expected_b = None;
                        let mut actual_b = None;
                        if io_res.is_ok() {
                            if buf[..byte_len] != read_buf[..byte_len] {
                                if let Some(idx) = buf
                                    .iter()
                                    .zip(&read_buf[..byte_len])
                                    .position(|(a, b)| a != b)
                                {
                                    diff = Some(idx as u32);
                                    expected_b = Some(buf[idx]);
                                    actual_b = Some(read_buf[idx]);
                                }
                            }
                        }

                        let _ = thread_res_tx.send(IoResultMsg {
                            abs_start_sector,
                            sector_count: sector_count as u32,
                            diff,
                            expected_byte: expected_b,
                            actual_byte: actual_b,
                            io_error: io_res.err(),
                            write_secs_first,
                            read_secs_first,
                            write_secs_second,
                            read_secs_second,
                            buf,
                        });
                    } else {
                        break;
                    }
                }
            }));
        }
        drop(req_rx);

        let mut buffer_pool: Vec<_> = (0..queue_depth.max(2))
            .map(|_| alloc_buffer(batch_size_sectors * block_size_usize, direct_io))
            .collect();
        let mut pattern_tile = alloc_buffer(block_size_usize, false);
        let mut global_sector_cursor = 0u64;
        let mut jobs_in_flight = 0;

        'immediate_loop: loop {
            while global_sector_cursor < total_sectors_in_test_run {
                if let Some(mut target_buf) = buffer_pool.pop() {
                    let remaining = total_sectors_in_test_run - global_sector_cursor;
                    let this_batch_sectors =
                        cmp::min(batch_size_sectors as u64, remaining) as usize;
                    let abs_first_sector = resume_from_sector + global_sector_cursor;

                    let split_point = this_batch_sectors / 2;
                    for i in 0..this_batch_sectors {
                        let current_abs_sector = abs_first_sector + i as u64;
                        if dual_pattern && i >= split_point {
                            DataTypePattern::Random
                                .fill_block_inplace(&mut pattern_tile, current_abs_sector);
                        } else {
                            data_pattern_arc
                                .fill_block_inplace(&mut pattern_tile, current_abs_sector);
                        }
                        let start = i * block_size_usize;
                        target_buf[start..start + block_size_usize]
                            .copy_from_slice(&pattern_tile);
                    }

                    if req_tx
                        .send(IoJob::WriteReadVerify {
                            abs_start_sector: abs_first_sector,
                            sector_count: this_batch_sectors,
                            buf: target_buf,
                        })
                        .is_err()
                    {
                        break;
                    }

                    jobs_in_flight += 1;
                    global_sector_cursor += this_batch_sectors as u64;
                } else {
                    break;
                }
            }

            if jobs_in_flight == 0 && global_sector_cursor >= total_sectors_in_test_run {
                break 'immediate_loop;
            }
            if HAS_FATAL_ERROR.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
                break 'immediate_loop;
            }

            match res_rx.recv() {
                Ok(msg) => {
                    jobs_in_flight -= 1;
                    pb_arc.inc(msg.sector_count as u64);
                    
                    let batch_bytes = msg.sector_count as u64 * block_size_u64;
                    let (off_start_val, off_start_unit) = format_bytes_int(msg.abs_start_sector * block_size_u64);
                    let (off_end_val, off_end_unit) = format_bytes_int((msg.abs_start_sector + msg.sector_count as u64) * block_size_u64);
                    let (batch_val, batch_unit) = format_bytes_int(batch_bytes);
                    let (buf_val, buf_unit) = format_bytes_int(block_size_u64);

                    if dual_pattern {
                        let first_bytes = (msg.sector_count as usize / 2) as u64 * block_size_u64;
                        let second_bytes = batch_bytes - first_bytes;
                        let w0 = mib_s(first_bytes, msg.write_secs_first);
                        let r0 = mib_s(first_bytes, msg.read_secs_first);
                        let w1 = mib_s(second_bytes, msg.write_secs_second);
                        let r1 = mib_s(second_bytes, msg.read_secs_second);
                        log_simple(
                            &log_f_opt,
                            Some(&pb_arc),
                            format!(
                                "{off_start_val} {off_start_unit} - \
                                {off_end_val} {off_end_unit}: \
                                {batch_val} {batch_unit}/{buf_val} {buf_unit} (dual)  \
                                binary {w0:.0} MiB/sec … {r0:.0} MiB/sec | \
                                random {w1:.0} MiB/sec … {r1:.0} MiB/sec"
                            )
                        );
                    } else {
                        let w0 = mib_s(batch_bytes, msg.write_secs_first);
                        let r0 = mib_s(batch_bytes, msg.read_secs_first);
                        let base_label = match &*data_pattern_arc {
                            DataTypePattern::Hex => "hex",
                            DataTypePattern::Text => "text",
                            DataTypePattern::Binary => "binary",
                            DataTypePattern::File(_) => "file",
                            DataTypePattern::Random => "random",
                        };
                        log_simple(
                            &log_f_opt,
                            Some(&pb_arc),
                            format!(
                                "{off_start_val} {off_start_unit} - {off_end_val} {off_end_unit}: {batch_val} {batch_unit}/{buf_val} {buf_unit} ({})  {:.0} MiB/sec W, {:.0} MiB/s R",
                                base_label,
                                w0,
                                r0,
                            ),
                        );
                    }

                    if let Some(e) = msg.io_error {
                        counters_arc.increment_write_errors();
                        counters_arc.increment_read_errors();
                        log_error(&log_f_opt, Some(&pb_arc), 0, msg.abs_start_sector, "IO Error", &e.to_string(), None, None, Some(file_path_owned.clone()));
                    } else if let Some(diff_offset) = msg.diff {
                        counters_arc.increment_mismatches();
                        let detail = if let (Some(exp_b), Some(act_b)) = (msg.expected_byte, msg.actual_byte) {
                            format!("First mismatch at byte offset {} in batch (wrote {:02X} vs read {:02X})", diff_offset, exp_b, act_b)
                        } else {
                            format!("First mismatch at byte offset {} in batch", diff_offset)
                        };
                        log_error(&log_f_opt, Some(&pb_arc), 0, msg.abs_start_sector, "Data Mismatch", &detail, msg.expected_byte.as_ref().map(|b| std::slice::from_ref(b)), msg.actual_byte.as_ref().map(|b| std::slice::from_ref(b)), Some(file_path_owned.clone()));
                    }
                    buffer_pool.push(msg.buf);
                }
                Err(_) => {
                    if jobs_in_flight > 0 {
                        log_simple(log_f_opt, Some(&pb_arc), "Result channel closed; workers may have panicked.");
                        HAS_FATAL_ERROR.store(true, Ordering::SeqCst);
                    }
                    break 'immediate_loop;
                }
            }
        }

        // Graceful shutdown
        for _ in 0..num_threads {
            req_tx.send(IoJob::Terminate).ok();
        }
        drop(req_tx);
        while let Ok(msg) = res_rx.try_recv() {
            pb_arc.inc(msg.sector_count as u64);
        }
        for handle in workers {
            handle.join().expect("worker thread panicked");
        }
        if HAS_FATAL_ERROR.load(Ordering::SeqCst) || STOP_REQUESTED.load(Ordering::SeqCst) {
            pb_arc.abandon_with_message("Test aborted.");
        } else {
            pb_arc.finish_with_message("Test scan completed.");
        }
    }

    let duration = start_time.elapsed();
    log_simple(
        log_f_opt,
        None,
        format!("Full reliability test scan phase completed in {:.2?}.", duration),
    );
    if HAS_FATAL_ERROR.load(Ordering::SeqCst) {
        return Err(io::Error::new(
            ErrorKind::Other,
            "Fatal error occurred in one or more threads. Check logs.",
        ));
    }
    Ok(())
}

const fn format_bytes_int(bytes: u64) -> (u64, &'static str) {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    const TIB: u64 = GIB * 1024;

    match bytes {
        b if b < KIB => (b, "Bytes"),
        b if b < MIB => (b / KIB, "KiB"),
        b if b < GIB => (b / MIB, "MiB"),
        b if b < TIB => (b / GIB, "GiB"),
        b => (b / TIB, "TiB"),
    }
}

fn format_bytes_float(bytes: u64) -> (f64, &'static str) {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;

    let b = bytes as f64;
    if b < KIB {
        (b, "Bytes")
    } else if b < MIB {
        (b / KIB, "KiB")
    } else if b < GIB {
        (b / MIB, "MiB")
    } else if b < TIB {
        (b / GIB, "GiB")
    } else {
        (b / TIB, "TiB")
    }
}

fn simple_resolve(cli_path: Option<PathBuf>) -> PathBuf {
    let base = cli_path.unwrap_or_else(|| PathBuf::from("."));
    if base.is_dir() {
        base.join(TEST_FILE_NAME)
    } else {
        base
    }
}

fn resolve_file_path(
    cli_path: Option<PathBuf>,
    log_f: &Option<Arc<Mutex<File>>>,
) -> io::Result<PathBuf> {
    let path_arg = cli_path.unwrap_or_else(|| PathBuf::from(".")); // Default to current dir if no path provided
    let mut file_path_intermediate =
        if path_arg.is_dir() || path_arg.as_os_str() == "." || path_arg.as_os_str().is_empty() {
            let current_dir = env::current_dir()?;
            // If path_arg is "." or empty, join with current_dir. If path_arg is a specific dir, use it.
            let base_dir = if path_arg.as_os_str() == "." || path_arg.as_os_str().is_empty() {
                current_dir
            } else {
                path_arg
            };
            base_dir.join(TEST_FILE_NAME)
        } else {
            // Assumed to be a file path or a path ending in what should be the file
            if let Some(parent) = path_arg.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    log_simple(
                        log_f,
                        None,
                        format!("Creating parent directory: {}", parent.display()),
                    );
                    fs::create_dir_all(parent).map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("Failed to create dir {}: {}", parent.display(), e),
                        )
                    })?;
                }
            }
            if path_arg.is_absolute() {
                path_arg
            } else {
                env::current_dir()?.join(path_arg)
            }
        };

    // Attempt to canonicalize. If it's NotFound, it means the file doesn't exist yet, which is fine.
    // We still want an absolute path.
    match file_path_intermediate.canonicalize() {
        Ok(canonical_path) => {
            log_simple(
                log_f,
                None,
                format!(
                    "Resolved and canonicalized test file path: {}",
                    canonical_path.display()
                ),
            );
            Ok(canonical_path)
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // If not absolute, make it absolute relative to current_dir.
            if !file_path_intermediate.is_absolute() {
                file_path_intermediate = env::current_dir()?.join(file_path_intermediate);
            }
            log_simple(
                log_f,
                None,
                format!(
                    "Resolved test file path (will be created if needed): {}",
                    file_path_intermediate.display()
                ),
            );
            Ok(file_path_intermediate)
        }
        Err(e) => {
            log_simple(
                log_f,
                None,
                format!(
                    "Error resolving/canonicalizing file path '{}': {}",
                    file_path_intermediate.display(),
                    e
                ),
            );
            Err(e)
        }
    }
}

fn main() {
    let log_file_path = "disk_test.log";
    let log_file_arc_opt: Option<Arc<Mutex<File>>> = match OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(log_file_path)
    {
        Ok(f) => Some(Arc::new(Mutex::new(f))),
        Err(e) => {
            eprintln!(
                "[{}] Failed to open log file '{}': {}. Further logs will only go to stderr.",
                current_timestamp(),
                log_file_path,
                e
            );
            None
        }
    };
    let main_result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        main_logic(log_file_arc_opt.clone())
    }));
    let exit_code = match main_result {
        Ok(Ok(())) => {
            log_simple(&log_file_arc_opt, None, "Operation completed successfully.");
            0
        }
        Ok(Err(e)) => {
            log_simple(
                &log_file_arc_opt,
                None,
                format!("Operation failed with an error: {}", e),
            );
            1
        }
        Err(panic_payload) => {
            let mut panic_msg = format!(
                "[{}] A critical error occurred: Test panicked!",
                current_timestamp()
            );
            if let Some(s) = panic_payload.downcast_ref::<String>() {
                panic_msg.push_str(&format!("\nPanic message: {}", s));
            } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                panic_msg.push_str(&format!("\nPanic message: {}", s));
            } else {
                panic_msg.push_str("\nPanic payload: (type not recognized as string)");
            }
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
    if let Commands::Bench {
        path,
        mode,
        json: true,
        direct_io,
    } = &cli.command
    {
        let file_path = resolve_file_path(path.clone(), &log_file_arc_opt)?;
        let test: LeanTest = mode.clone().into();
        let result = run_lean_test(&file_path, test, *direct_io)?;
        println!("{}", result.to_json());
        return Ok(());
    }
    log_simple(&log_file_arc_opt, None, "Starting Disk Test Tool...");
    log_simple(
        &log_file_arc_opt,
        None,
        format!("Running Version {}", env!("CARGO_PKG_VERSION")),
    );
    if cli.verbose {
        log_simple(&log_file_arc_opt, None, format!("CLI Command: {:?}", cli));
    }
    if let Ok(info) = get_host_info() {
        log_simple(
            &log_file_arc_opt,
            None,
            format!("Host Information: {}", info),
        );
    } else {
        log_simple(
            &log_file_arc_opt,
            None,
            "Could not retrieve host information.",
        );
    }

    let initial_path_for_disk_info = match &cli.command {
        Commands::FullTest { path, .. } | Commands::Bench { path, .. } => {
            path.as_ref().map(|p| p.as_path()).unwrap_or_else(|| Path::new("."))
        }
        Commands::ReadSector { path, .. }
        | Commands::WriteSector { path, .. }
        | Commands::RangeRead { path, .. }
        | Commands::RangeWrite { path, .. }
        | Commands::VerifyRange { path, .. } => path.as_path(),
    };
    if let Ok(info) = get_disk_info(initial_path_for_disk_info) {
        log_simple(&log_file_arc_opt, None, &info);
    } else {
        log_simple(
            &log_file_arc_opt,
            None,
            format!(
                "Could not retrieve disk info for path: {}",
                initial_path_for_disk_info.display()
            ),
        );
    }

    if let Some(path_str) = initial_path_for_disk_info.to_str() {
        if let Ok(dinfo) = hardware_info::get_disk_info(path_str) {
            log_simple(
                &log_file_arc_opt,
                None,
                format!("Detailed Disk Info: {}", dinfo),
            );
        } else {
            log_simple(
                &log_file_arc_opt,
                None,
                "Could not retrieve detailed disk info.",
            );
        }

        if let Ok(serial) = hardware_info::get_disk_serial_number(path_str) {
            log_simple(
                &log_file_arc_opt,
                None,
                format!("Disk Serial Number: {}", serial),
            );
        } else {
            log_simple(&log_file_arc_opt, None, "Disk serial number unavailable.");
        }

        #[cfg(target_os = "windows")]
        {
            if let Ok(bsize) = hardware_info::get_block_size_windows(path_str) {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Block Size: {} bytes", bsize),
                );
            }
            if let Ok(usb) = hardware_info::get_usb_controller_info_windows(path_str) {
                log_simple(&log_file_arc_opt, None, usb);
            } else {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "USB controller information unavailable.",
                );
            }
            match hardware_info::get_usb_serial_numbers() {
                Ok(serials) => log_simple(&log_file_arc_opt, None, serials),
                Err(_) => log_simple(&log_file_arc_opt, None, "No USB disk serial numbers found."),
            }
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(bsize) = hardware_info::get_block_size_macos(path_str) {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Block Size: {} bytes", bsize),
                );
            }
            if let Some(bsd) = hardware_info::get_bsd_name_from_path(path_str) {
                if let Ok(smart) = hardware_info::smart_metrics(&bsd) {
                    log_simple(&log_file_arc_opt, None, format!("SMART {:?}", smart));
                }
            }
            match mac_usb_report::usb_storage_summary(path_str) {
                Ok(s) => log_simple(&log_file_arc_opt, None, s),
                Err(_) => log_simple(
                    &log_file_arc_opt,
                    None,
                    "USB controller information unavailable.",
                ),
            }
            match hardware_info::get_usb_serial_numbers() {
                Ok(serials) => log_simple(&log_file_arc_opt, None, serials),
                Err(_) => log_simple(&log_file_arc_opt, None, "No USB disk serial numbers found."),
            }
            if cli.verbose {
                if let Ok(tree) = mac_usb_report::usb_storage_report(path_str) {
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        format!("USB / Controller Tree (incl. power) \u{2193}\n{tree}"),
                    );
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Ok(usb) = hardware_info::get_usb_controller_info_linux(path_str) {
                log_simple(&log_file_arc_opt, None, usb);
            } else {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "USB controller information unavailable.",
                );
            }
            match hardware_info::get_usb_serial_numbers() {
                Ok(serials) => log_simple(&log_file_arc_opt, None, serials),
                Err(_) => log_simple(&log_file_arc_opt, None, "No USB disk serial numbers found."),
            }
        }
    }

    match cli.command {
        Commands::FullTest {
            path,
            test_size,
            resume_from_sector,
            block_size,
            threads: threads_opt,
            queue_depth: queue_depth_opt,
            batch_size: batch_size_opt,
            data_type,
            data_file,
            #[cfg(feature = "direct")]
            direct_io,
            preallocate,
            dual_pattern,
            deferred_verify,
            passes,
        } => {
            #[cfg(feature = "direct")]
            let use_direct_io = direct_io;
            #[cfg(not(feature = "direct"))]
            let use_direct_io = false;

            let file_path = resolve_file_path(path, &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Block size 0 specified for FullTest, defaulting to 4096 bytes.",
                );
                actual_block_size_u64 = 4096;
            }
            #[cfg(feature = "direct")]
            if use_direct_io && actual_block_size_u64 % 512 != 0 {
                let msg = format!(
                    "ERROR: Direct I/O requires block size (currently {}) to be a multiple of 512.",
                    actual_block_size_u64
                );
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }

            if cli.verbose {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Effective block size: {} bytes", actual_block_size_u64),
                );
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Preallocate: {}", preallocate),
                );
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Deferred Verify: {}", deferred_verify),
                );
            }
            if use_direct_io {
                #[cfg(feature = "direct")]
                {
                    #[cfg(target_os = "linux")]
                    log_simple(&log_file_arc_opt, None, "Direct I/O Mode: O_DIRECT (Linux)");
                    #[cfg(target_os = "windows")]
                    log_simple(&log_file_arc_opt, None, "Direct I/O Mode: FILE_FLAG_NO_BUFFERING (Windows)");
                    #[cfg(target_os = "macos")]
                    log_simple(&log_file_arc_opt, None, "Direct I/O Mode: F_NOCACHE (macOS)");
                    #[cfg(not(any(target_os="linux", target_os="windows", target_os="macos")))]
                    log_simple(&log_file_arc_opt, None, "Direct I/O requested but not supported on this OS. Ignored.");
                }
                #[cfg(not(feature = "direct"))]
                log_simple(&log_file_arc_opt, None, "Direct I/O not enabled in this build. Using standard buffered I/O.");
            }

            let pattern = match data_type {
                DataTypeChoice::Hex => DataTypePattern::Hex,
                DataTypeChoice::Text => DataTypePattern::Text,
                DataTypeChoice::Binary => DataTypePattern::Binary,
                DataTypeChoice::Random => DataTypePattern::Random,
                DataTypeChoice::File => {
                    let df_path = data_file.ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            "--data-file required for --data-type=file",
                        )
                    })?;
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        format!("Loading data pattern from file: {}", df_path.display()),
                    );
                    let data_bytes = fs::read(&df_path).map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("Failed to read data_file {}: {}", df_path.display(), e),
                        )
                    })?;
                    if data_bytes.len() > 1024 * 1024 * 100 {
                        log_simple(
                            &log_file_arc_opt,
                            None,
                            format!("WARNING: Data file is large ({} bytes).", data_bytes.len()),
                        );
                    }
                    DataTypePattern::File(data_bytes)
                }
            };
            if cli.verbose {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Data pattern type: {:?}", data_type),
                );
            }

            // --- Auto-tune --------------------------------------------------------
            let (threads, queue_depth, batch_bytes) = auto_tune::decide(
                &file_path,
                threads_opt,
                queue_depth_opt,
                batch_size_opt,
                actual_block_size_u64,
            );
            log_simple(
                &log_file_arc_opt,
                None,
                format!("\u{27f3} auto-tune: threads={}  qd={}  batch={:.1} MiB",
                        threads, queue_depth, batch_bytes as f64 / 1_048_576.0)
            );
            let actual_batch_size_sectors =
                cmp::max(1, (batch_bytes / actual_block_size_u64) as usize);

            if passes == 0 || passes > 3 {
                let msg = format!("passes must be between 1 and 3 (got {})", passes);
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }

            for pass_idx in 0..passes {
                if passes > 1 {
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        format!("Starting pass {} of {}", pass_idx + 1, passes),
                    );
                }
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("Begin iteration {}", pass_idx + 1),
                );

                STOP_REQUESTED.store(false, Ordering::SeqCst);
                HAS_FATAL_ERROR.store(false, Ordering::SeqCst);

                let counters_arc = Arc::new(ErrorCounters::new());
                full_reliability_test(
                    &file_path,
                    &log_file_arc_opt,
                    &counters_arc,
                    test_size,
                    resume_from_sector,
                    actual_block_size_u64,
                    threads,
                    queue_depth,
                    pattern.clone(),
                    actual_batch_size_sectors,
                    use_direct_io,
                    preallocate,
                    dual_pattern,
                    deferred_verify,
                    cli.verbose,
                )?;

                let write_errs = counters_arc.write_errors.load(Ordering::Relaxed);
                let read_errs = counters_arc.read_errors.load(Ordering::Relaxed);
                let mismatches = counters_arc.mismatches.load(Ordering::Relaxed);
                let total_errors = write_errs + read_errs + mismatches;

                log_simple(&log_file_arc_opt, None, "--- Full Test Summary ---");
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("  Write Errors: {}", write_errs),
                );
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("  Read Errors: {}", read_errs),
                );
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("  Mismatches:   {}", mismatches),
                );
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!("  Total Non-Fatal Errors Reported: {}", total_errors),
                );

                if total_errors == 0 && !HAS_FATAL_ERROR.load(Ordering::SeqCst) {
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        "All checks passed. No errors detected.",
                    );
                } else {
                    let mut error_summary_msg =
                        format!("Test completed with {} non-fatal errors.", total_errors);
                    if HAS_FATAL_ERROR.load(Ordering::SeqCst) {
                        error_summary_msg
                            .push_str(" A fatal error was also encountered during the test.");
                    }
                    log_simple(&log_file_arc_opt, None, &error_summary_msg);
                    // Remove the test file even when errors are encountered
                    match fs::remove_file(&file_path) {
                        Ok(_) => log_simple(
                            &log_file_arc_opt,
                            None,
                            format!(
                                "Deleted test file '{}' after pass {}",
                                file_path.display(),
                                pass_idx + 1
                            ),
                        ),
                        Err(e) => log_simple(
                            &log_file_arc_opt,
                            None,
                            format!(
                                "Failed to delete test file '{}' after pass {}: {}",
                                file_path.display(),
                                pass_idx + 1,
                                e
                            ),
                        ),
                    }
                    return Err(io::Error::new(ErrorKind::Other, error_summary_msg));
                }

                // Clean up the test file before the next iteration
                match fs::remove_file(&file_path) {
                    Ok(_) => log_simple(
                        &log_file_arc_opt,
                        None,
                        format!(
                            "Deleted test file '{}' after pass {}",
                            file_path.display(),
                            pass_idx + 1
                        ),
                    ),
                    Err(e) => log_simple(
                        &log_file_arc_opt,
                        None,
                        format!(
                            "Failed to delete test file '{}' after pass {}: {}",
                            file_path.display(),
                            pass_idx + 1,
                            e
                        ),
                    ),
                }
            }
        }
        Commands::Bench { path, mode, json, direct_io } => {
            let file_path = resolve_file_path(path, &log_file_arc_opt)?;
            let test: LeanTest = mode.into();
            let result = run_lean_test(&file_path, test, direct_io)?;
            if json {
                println!("{}", result.to_json());
            } else {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    format!(
                        "{} Write {:.2} MiB/s, Read {:.2} MiB/s",
                        result.label, result.write_mib_s, result.read_mib_s
                    ),
                );
            }
            let _ = fs::remove_file(&file_path);
        }
        Commands::ReadSector {
            path,
            sector,
            block_size,
            #[cfg(feature = "direct")]
            direct_io,
        } => {
            #[cfg(feature = "direct")]
            let use_direct_io = direct_io;
            #[cfg(not(feature = "direct"))]
            let use_direct_io = false;

            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Block size 0 for ReadSector, defaulting to 4096.",
                );
                actual_block_size_u64 = 4096;
            }
            #[cfg(feature = "direct")]
            if use_direct_io && actual_block_size_u64 % 512 != 0 {
                let msg = format!(
                    "ERROR: Direct I/O for ReadSector, block size {} not multiple of 512.",
                    actual_block_size_u64
                );
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            single_sector_read(
                &log_file_arc_opt,
                &file_path,
                sector,
                actual_block_size_u64 as usize,
                use_direct_io,
            )?;
        }
        Commands::WriteSector {
            path,
            sector,
            block_size,
            data_type,
            data_file,
            #[cfg(feature = "direct")]
            direct_io,
        } => {
            #[cfg(feature = "direct")]
            let use_direct_io = direct_io;
            #[cfg(not(feature = "direct"))]
            let use_direct_io = false;

            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Block size 0 for WriteSector, defaulting to 4096.",
                );
                actual_block_size_u64 = 4096;
            }
            #[cfg(feature = "direct")]
            if use_direct_io && actual_block_size_u64 % 512 != 0 {
                let msg = format!(
                    "ERROR: Direct I/O for WriteSector, block size {} not multiple of 512.",
                    actual_block_size_u64
                );
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            let pattern = match data_type {
                DataTypeChoice::Hex => DataTypePattern::Hex,
                DataTypeChoice::Text => DataTypePattern::Text,
                DataTypeChoice::Binary => DataTypePattern::Binary,
                DataTypeChoice::Random => DataTypePattern::Random,
                DataTypeChoice::File => {
                    let df_path = data_file.ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            "--data-file required for --data-type=file for WriteSector",
                        )
                    })?;
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        format!(
                            "WriteSector: Loading data pattern from file: {}",
                            df_path.display()
                        ),
                    );
                    DataTypePattern::File(fs::read(df_path)?)
                }
            };
            single_sector_write(
                &log_file_arc_opt,
                &file_path,
                sector,
                actual_block_size_u64 as usize,
                &pattern,
                use_direct_io,
            )?;
        }
        Commands::RangeRead {
            path,
            start_sector,
            end_sector,
            block_size,
            #[cfg(feature = "direct")]
            direct_io,
        } => {
            #[cfg(feature = "direct")]
            let use_direct_io = direct_io;
            #[cfg(not(feature = "direct"))]
            let use_direct_io = false;

            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Block size 0 for RangeRead, defaulting to 4096.",
                );
                actual_block_size_u64 = 4096;
            }
            #[cfg(feature = "direct")]
            if use_direct_io && actual_block_size_u64 % 512 != 0 {
                let msg = format!(
                    "ERROR: Direct I/O for RangeRead, block size {} not multiple of 512.",
                    actual_block_size_u64
                );
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            range_read(
                &log_file_arc_opt,
                &file_path,
                start_sector,
                end_sector,
                actual_block_size_u64 as usize,
                use_direct_io,
                cli.verbose,
            )?;
        }
        Commands::RangeWrite {
            path,
            start_sector,
            end_sector,
            block_size,
            data_type,
            data_file,
            #[cfg(feature = "direct")]
            direct_io,
        } => {
            #[cfg(feature = "direct")]
            let use_direct_io = direct_io;
            #[cfg(not(feature = "direct"))]
            let use_direct_io = false;

            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Block size 0 for RangeWrite, defaulting to 4096.",
                );
                actual_block_size_u64 = 4096;
            }
            #[cfg(feature = "direct")]
            if use_direct_io && actual_block_size_u64 % 512 != 0 {
                let msg = format!(
                    "ERROR: Direct I/O for RangeWrite, block size {} not multiple of 512.",
                    actual_block_size_u64
                );
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            let pattern = match data_type {
                DataTypeChoice::Hex => DataTypePattern::Hex,
                DataTypeChoice::Text => DataTypePattern::Text,
                DataTypeChoice::Binary => DataTypePattern::Binary,
                DataTypeChoice::Random => DataTypePattern::Random,
                DataTypeChoice::File => {
                    let df_path = data_file.ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            "--data-file required for --data-type=file for RangeWrite",
                        )
                    })?;
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        format!(
                            "RangeWrite: Loading data pattern from file: {}",
                            df_path.display()
                        ),
                    );
                    DataTypePattern::File(fs::read(df_path)?)
                }
            };
            range_write(
                &log_file_arc_opt,
                &file_path,
                start_sector,
                end_sector,
                actual_block_size_u64 as usize,
                &pattern,
                use_direct_io,
            )?;
        }
        Commands::VerifyRange {
            path,
            start_sector,
            end_sector,
            block_size,
            data_type,
            data_file,
            #[cfg(feature = "direct")]
            direct_io,
        } => {
            #[cfg(feature = "direct")]
            let use_direct_io = direct_io;
            #[cfg(not(feature = "direct"))]
            let use_direct_io = false;

            let file_path = resolve_file_path(Some(path), &log_file_arc_opt)?;
            let mut actual_block_size_u64 = block_size;
            if actual_block_size_u64 == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Block size 0 for VerifyRange, defaulting to 4096.",
                );
                actual_block_size_u64 = 4096;
            }
            #[cfg(feature = "direct")]
            if use_direct_io && actual_block_size_u64 % 512 != 0 {
                let msg = format!(
                    "ERROR: Direct I/O for VerifyRange, block size {} not multiple of 512.",
                    actual_block_size_u64
                );
                log_simple(&log_file_arc_opt, None, &msg);
                return Err(io::Error::new(ErrorKind::InvalidInput, msg));
            }
            let pattern = match data_type {
                DataTypeChoice::Hex => DataTypePattern::Hex,
                DataTypeChoice::Text => DataTypePattern::Text,
                DataTypeChoice::Binary => DataTypePattern::Binary,
                DataTypeChoice::Random => DataTypePattern::Random,
                DataTypeChoice::File => {
                    let df_path = data_file.ok_or_else(|| {
                        io::Error::new(
                            ErrorKind::InvalidInput,
                            "--data-file required for --data-type=file for VerifyRange",
                        )
                    })?;
                    log_simple(
                        &log_file_arc_opt,
                        None,
                        format!(
                            "VerifyRange: Loading data pattern from file: {}",
                            df_path.display()
                        ),
                    );
                    DataTypePattern::File(fs::read(df_path)?)
                }
            };
            let counters_arc = Arc::new(ErrorCounters::new());
            range_verify(
                &log_file_arc_opt,
                &counters_arc,
                &file_path,
                start_sector,
                end_sector,
                actual_block_size_u64 as usize,
                &pattern,
                use_direct_io,
            )?;

            let mismatches = counters_arc.mismatches.load(Ordering::Relaxed);
            let read_errors = counters_arc.read_errors.load(Ordering::Relaxed);
            log_simple(&log_file_arc_opt, None, "--- Verify Range Summary ---");
            log_simple(
                &log_file_arc_opt,
                None,
                format!("  Mismatches Found: {}", mismatches),
            );
            log_simple(
                &log_file_arc_opt,
                None,
                format!("  Read/Seek Errors Encountered: {}", read_errors),
            );
            if mismatches == 0 && read_errors == 0 {
                log_simple(
                    &log_file_arc_opt,
                    None,
                    "Verification successful. No errors or mismatches detected in the specified range.",
                );
            } else {
                let total_verify_issues = mismatches + read_errors;
                let summary_msg = format!(
                    "Verification completed with {} issues ({} mismatches, {} read/seek errors).",
                    total_verify_issues, mismatches, read_errors
                );
                log_simple(&log_file_arc_opt, None, &summary_msg);
                return Err(io::Error::new(ErrorKind::InvalidData, summary_msg));
            }
        }
    }
    Ok(())
}
