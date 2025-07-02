use rand::{thread_rng, Rng};
use serde_json::json;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;

/// Enum describing the preset disk tests.
#[derive(Clone, Copy, Debug)]
pub enum LeanTest {
    /// Sequential read/write using 1MiB blocks with a queue depth of 8.
    Seq1Mq8t1,
    /// Sequential read/write using 1MiB blocks with a single queue.
    Seq1Mq1t1,
    /// Random 4KiB read/write with queue depth 32 and 16 threads (simulated).
    Rnd4kQ32T16,
    /// Random 4KiB read/write with a single queue/thread.
    Rnd4kQ1t1,
}

impl LeanTest {
    fn params(self) -> (usize, usize, bool, &'static str) {
        match self {
            LeanTest::Seq1Mq8t1 => (1 * 1024 * 1024, 8, false, "SEQ1M Q8T1"),
            LeanTest::Seq1Mq1t1 => (1 * 1024 * 1024, 1, false, "SEQ1M Q1T1"),
            LeanTest::Rnd4kQ32T16 => (4 * 1024, 32, true, "RND4K Q32T16"),
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

/// Execute one of the preset tests against `path`.
///
/// The test writes and then reads a small amount of data using
/// parameters derived from [`LeanTest`]. The return value is either a
/// formatted string or a JSON string if `as_json` is `true`.
pub fn run_lean_test<P: AsRef<Path>>(path: P, test: LeanTest) -> io::Result<TestResult> {
    let (block_size, queue_depth, random, label) = test.params();
    // Use a very small footprint to keep the test quick.
    let blocks = queue_depth * 32; // 32 batches of the queue depth
    let total_bytes = (blocks * block_size) as u64;

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&path)?;
    file.set_len(total_bytes)?;

    let mut buffer = vec![0u8; block_size];
    let mut rng = thread_rng();

    let start_write = Instant::now();
    // Write phase
    for i in 0..blocks {
        if random {
            rng.fill(&mut buffer[..]);
            let off = rng.gen_range(0..blocks) as u64 * block_size as u64;
            file.seek(SeekFrom::Start(off))?;
        } else {
            let off = i as u64 * block_size as u64;
            file.seek(SeekFrom::Start(off))?;
        }
        file.write_all(&buffer)?;
    }
    file.sync_all()?;
    let write_secs = start_write.elapsed().as_secs_f64();

    let start_read = Instant::now();
    // Read phase
    for i in 0..blocks {
        if random {
            let off = rng.gen_range(0..blocks) as u64 * block_size as u64;
            file.seek(SeekFrom::Start(off))?;
        } else {
            let off = i as u64 * block_size as u64;
            file.seek(SeekFrom::Start(off))?;
        }
        file.read_exact(&mut buffer)?;
    }
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
        let result = run_lean_test(tmp.path(), LeanTest::Seq1Mq1t1).unwrap();
        let v = result.to_json();
        assert_eq!(v["label"], "SEQ1M Q1T1");
    }
}
