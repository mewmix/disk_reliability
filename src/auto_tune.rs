// src/auto_tune.rs
//! Decide sensible defaults when the user did **not** override them.

use crate::hardware_info::{detect_bus_type, Bus};
use std::cmp;

/// Returns `(threads, queue_depth, batch_size_bytes)`.
pub fn decide<P: AsRef<std::path::Path> + AsRef<std::ffi::OsStr>>(
    path: P,
    user_threads: Option<usize>,
    user_qd: Option<usize>,
    user_batch: Option<u64>,
    block_size: u64,
) -> (usize, usize, u64) {
    // First honour any explicit override -------------------------------
    let threads = user_threads.unwrap_or(0);
    let qd_in   = user_qd.unwrap_or(0);
    let batch   = user_batch.unwrap_or(0);

    if threads > 0 && qd_in > 0 && batch > 0 {
        return (threads, qd_in, batch);
    }

    // Otherwise pick presets based on the bus --------------------------
    let bus = detect_bus_type(path).unwrap_or(Bus::Unknown);
    let (def_thr, def_qd, def_batch_mb) = match bus {
        Bus::UsbBulkOnly => (1, 1,   64),   // keep BOT bridges happy
        Bus::UsbUasp     => (1, 8,  128),
        Bus::SataAHCI    => (1, 8,  256),
        Bus::Nvme        => (1, 32, 512),
        _                => (1, 4,  128),
    };

    let threads = if threads == 0 { def_thr } else { threads };
    let qd      = if qd_in  == 0 { def_qd  } else { qd_in  };
    let batch_b = if batch   == 0 { def_batch_mb * 1_048_576 } else { batch };

    // Never let batch be < 2 x block-size so the progress meter isn't spammy
    (threads, qd, cmp::max(batch_b, 2 * block_size))
}
