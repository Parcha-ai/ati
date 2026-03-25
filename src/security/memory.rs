//! Secure memory helpers: mlock, madvise, zeroize.
//!
//! These prevent secrets from being swapped to disk or included in core dumps.
//! All functions are best-effort on non-Linux platforms.

/// Lock a memory region to prevent it from being swapped to disk.
/// Returns Ok(()) on success, Err with a warning message on failure.
#[cfg(target_os = "linux")]
pub fn mlock(ptr: *const u8, len: usize) -> Result<(), String> {
    let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!(
            "mlock failed (errno {}): secrets may be swappable",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn mlock(_ptr: *const u8, _len: usize) -> Result<(), String> {
    // mlock is not critical on non-Linux; warn and continue
    Ok(())
}

/// Advise the kernel to exclude this memory from core dumps.
#[cfg(target_os = "linux")]
pub fn madvise_dontdump(ptr: *const u8, len: usize) -> Result<(), String> {
    let ret = unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) };
    if ret == 0 {
        Ok(())
    } else {
        Err("madvise(DONTDUMP) failed: secrets may appear in core dumps".to_string())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn madvise_dontdump(_ptr: *const u8, _len: usize) -> Result<(), String> {
    Ok(())
}

/// Unlock a previously locked memory region.
#[cfg(target_os = "linux")]
pub fn munlock(ptr: *const u8, len: usize) {
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn munlock(_ptr: *const u8, _len: usize) {}
