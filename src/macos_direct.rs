// src/macos_direct.rs
//! macOS "direct I/O" shim – compiled only when the direct feature is
//! enabled.  Uses F_NOCACHE + F_RDAHEAD to bypass the page-cache.

#[cfg(all(target_os = "macos", feature = "direct"))]
use std::{io, os::unix::io::AsRawFd};

#[cfg(all(target_os = "macos", feature = "direct"))]
pub fn enable_nocache(file: &std::fs::File) -> io::Result<()> {
    use libc::{fcntl, F_NOCACHE, F_RDAHEAD};

    let fd = file.as_raw_fd();

    // 1. Stop the readahead heuristic (must come *first*).
    if unsafe { fcntl(fd, F_RDAHEAD, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // 2. Tell the VFS to avoid the buffer-cache for this FD.
    if unsafe { fcntl(fd, F_NOCACHE, 1) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
