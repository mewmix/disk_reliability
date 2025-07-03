//! NOTE: This implementation requires the `aligned_vec` crate.
//! Add the following to your Cargo.toml:
//! aligned_vec = "0.5"

use aligned_vec::AVec;
use rand::{thread_rng, Rng};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use crossbeam_channel::{bounded, unbounded, Receiver};

// Platform-specific helpers for positioned I/O
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

#[cfg(unix)]
fn pwrite_all(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    file.write_all_at(buf, offset)
}

#[cfg(unix)]
fn pread_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    file.read_exact_at(buf, offset)
}

#[cfg(windows)]
fn pwrite_all(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    file.seek_write(buf, offset).map(|_| ())
}

#[cfg(windows)]
fn pread_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    file.seek_read(buf, offset).map(|_| ())
}

/// Enum describing the preset disk tests.
#[derive(Clone, Copy, Debug)]
pub enum LeanTest {
    /// Sequential read/write using 1MiB blocks with a queue depth of 8.
    Seq1Mq8t1,
    /// Sequential read/write using 1MiB blocks with a single queue.
    Seq1Mq1t1,
    /// Random 4KiB read/write with queue depth 32 and 1 thread.
    Rnd4kQ32T1,
    /// Random 4KiB read/write with a single queue/thread.
    Rnd4kQ1t1,
}

impl LeanTest {
    pub fn params(self) -> (usize, usize, bool, &'static str) {
        match self {
            LeanTest::Seq1Mq8t1 => (1 * 1024 * 1024, 8, false, "SEQ1M Q8T1"),
            LeanTest::Seq1Mq1t1 => (1 * 1024 * 1024, 1, false, "SEQ1M Q1T1"),
            LeanTest::Rnd4kQ32T1 => (4 * 1024, 32, true, "RND4K Q32T1"),
            LeanTest::Rnd4kQ1t1 => (4 * 1024, 1, true, "RND4K Q1T1"),
        }
    }
}

/// Result summary returned by [`run_lean_test`].
#[derive(Debug, Clone)]
pub struct TestResult {
    pub label: &'static str,
    pub bytes_processed: u64,
    pub write_seconds: f64,
    pub read_seconds: f64,
    pub write_mib_s: f64,
    pub read_mib_s: f64,
}

impl TestResult {
    /// Convert to JSON representation using `serde_json`.
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "label": self.label,
            "bytes_processed": self.bytes_processed,
            "write_seconds": self.write_seconds,
            "read_seconds": self.read_seconds,
            "write_mib_s": self.write_mib_s,
            "read_mib_s": self.read_mib_s,
        })
    }
}

/// Dispatches I/O jobs to a pool of worker threads.
fn run_io_phase(
    file: &Arc<File>,
    offsets: &[u64],
    block_size: usize,
    queue_depth: usize,
    is_write: bool,
    is_random: bool,
) -> io::Result<()> {
    // A channel for dispatching jobs (offsets) to workers.
    let (job_tx, job_rx) = bounded::<u64>(queue_depth);
    // A channel for workers to send their I/O results (or errors) back.
    let (result_tx, result_rx) = unbounded::<io::Result<()>>();

    thread::scope(|s| {
        // --- Spawn Worker Threads ---
        for _ in 0..queue_depth {
            let worker_job_rx: Receiver<u64> = job_rx.clone();
            let worker_result_tx = result_tx.clone();
            let file_clone = file.clone();

            s.spawn(move || {
                // FIX: Allocate buffer once per thread.
                // FIX: Use an aligned vector to meet O_DIRECT/NO_BUFFERING requirements.
                // The API for aligned_vec changed in v0.5.
                // 4096-byte alignment satisfies FILE_FLAG_NO_BUFFERING / O_DIRECT.
                let mut buffer = AVec::<u8>::from_iter(
                    4096,
                    std::iter::repeat(0u8).take(block_size)
                );


                let mut rng = if is_random { Some(thread_rng()) } else { None };

                // Worker loop: pull a job (offset) from the channel and process it.
                while let Ok(offset) = worker_job_rx.recv() {
                    let res = if is_write {
                        if let Some(ref mut rng) = rng {
                            rng.fill(&mut buffer[..]);
                        }
                        pwrite_all(&file_clone, &buffer, offset)
                    } else {
                        pread_exact_at(&file_clone, &mut buffer, offset)
                    };

                    // FIX: Propagate errors by sending the `io::Result` back.
                    // If send fails, the main thread has already terminated, so we can exit.
                    if worker_result_tx.send(res).is_err() {
                        break;
                    }
                }
            });
        }

        // Drop the main thread's sender handle so the result channel can close properly.
        drop(result_tx);
        
        // --- Main Thread: Producer ---
        for &offset in offsets {
            if job_tx.send(offset).is_err() {
                // All receivers have hung up, likely due to a worker panic.
                // The error will be caught below when we check the result channel.
                break;
            }
        }
        // Drop the job sender to signal that no more jobs are coming. Workers will exit their loops.
        drop(job_tx);

        // --- Result Aggregation ---
        // Collect a result for every job we dispatched.
        for _ in 0..offsets.len() {
            // recv() will fail if all worker threads have panicked.
            let worker_result = result_rx.recv()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "A worker thread panicked and disconnected"))?;

            // Check the actual io::Result from the worker. The first I/O error is returned.
            // This is equivalent to `worker_result?` but bubbles up the specific I/O error.
            if let Err(e) = worker_result {
                return Err(e);
            }
        }

        Ok(())
    }) // Scope automatically joins all threads, ensuring all I/O is complete.
}


/// Execute one of the preset tests against `path`.
pub fn run_lean_test<P: AsRef<Path>>(path: P, test: LeanTest, direct_io: bool) -> io::Result<TestResult> {
    let (block_size, queue_depth, random, label) = test.params();
    let blocks = queue_depth * 32;
    let total_bytes = (blocks * block_size) as u64;

    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);

    if direct_io {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECT);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_NO_BUFFERING: u32 = 0x20000000;
            options.custom_flags(FILE_FLAG_NO_BUFFERING);
        }
    }

    let file = Arc::new(options.open(&path)?);
    file.set_len(total_bytes)?;

    // --- Prepare I/O Offsets ---
    let mut offsets = Vec::with_capacity(blocks);
    if random {
        let mut rng = thread_rng();
        for _ in 0..blocks {
            offsets.push(rng.gen_range(0..blocks) as u64 * block_size as u64);
        }
    } else {
        for i in 0..blocks {
            offsets.push(i as u64 * block_size as u64);
        }
    }

    // --- Write Phase ---
    let start_write = Instant::now();
    run_io_phase(&file, &offsets, block_size, queue_depth, true, random)?;
    file.sync_all()?;
    let write_secs = start_write.elapsed().as_secs_f64();

    // --- Read Phase ---
    let start_read = Instant::now();
    run_io_phase(&file, &offsets, block_size, queue_depth, false, random)?;
    let read_secs = start_read.elapsed().as_secs_f64();

    let write_mib_s = (total_bytes as f64 / (1024.0 * 1024.0)) / write_secs;
    let read_mib_s = (total_bytes as f64 / (1024.0 * 1024.0)) / read_secs;

    let result = TestResult {
        label,
        bytes_processed: total_bytes * 2,
        write_seconds: write_secs,
        read_seconds: read_secs,
        write_mib_s,
        read_mib_s,
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn json_output() {
        let tmp = NamedTempFile::new().unwrap();
        let result = run_lean_test(tmp.path(), LeanTest::Seq1Mq1t1, false).unwrap();
        let v = result.to_json();
        assert_eq!(v["label"], "SEQ1M Q1T1");
        assert!(v["write_mib_s"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn q8_runs_concurrently() {
        // This is a smoke test to ensure Q>1 doesn't crash and completes successfully.
        let tmp = NamedTempFile::new().unwrap();
        let result = run_lean_test(tmp.path(), LeanTest::Rnd4kQ32T1, false).unwrap();
        let v = result.to_json();
        assert_eq!(v["label"], "RND4K Q32T1");
        assert!(v["read_mib_s"].as_f64().unwrap() > 0.0);
    }

    // This test will only run on Unix-like systems and requires root or specific capabilities
    // to succeed on some systems, but it serves to validate that O_DIRECT doesn't fail
    // due to alignment issues. We wrap it in a feature flag to avoid breaking CI.
    #[test]
    #[cfg_attr(not(feature = "direct_io_test"), ignore)]
    fn o_direct_succeeds_with_alignment() {
        let tmp = NamedTempFile::new().unwrap();
        // This will panic if the aligned allocation or I/O fails.
        let result = run_lean_test(tmp.path(), LeanTest::Rnd4kQ1t1, true).unwrap();
        assert_eq!(result.label, "RND4K Q1T1");
    }
}