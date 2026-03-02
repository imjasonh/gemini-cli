// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

//! Landlock sandbox implementation for Gemini CLI
//!
//! This module provides unprivileged filesystem sandboxing using Linux Landlock LSM.
//! Requires Linux kernel 5.13+ with Landlock enabled.

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::io::AsRawFd;

// Landlock syscall numbers (platform-specific type)
#[cfg(target_os = "linux")]
type SyscallNum = libc::c_long;
#[cfg(not(target_os = "linux"))]
type SyscallNum = libc::c_int;

const LANDLOCK_CREATE_RULESET: SyscallNum = 444;
const LANDLOCK_ADD_RULE: SyscallNum = 445;
const LANDLOCK_RESTRICT_SELF: SyscallNum = 446;

// Landlock access flags
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// ABI version access masks
const ACCESS_ABI_V1: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

const ACCESS_ABI_V2: u64 = ACCESS_ABI_V1 | LANDLOCK_ACCESS_FS_REFER;
const ACCESS_ABI_V3: u64 = ACCESS_ABI_V2 | LANDLOCK_ACCESS_FS_TRUNCATE;

// Convenience access groups
const ACCESS_RO: u64 = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
const ACCESS_RX: u64 = ACCESS_RO | LANDLOCK_ACCESS_FS_EXECUTE;

// Landlock rule type
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Seccomp constants (Linux only)
#[cfg(target_os = "linux")]
const SECCOMP_SET_MODE_FILTER: i32 = 1;
#[cfg(target_os = "linux")]
const PR_SET_NO_NEW_PRIVS: i32 = 38;
#[cfg(target_os = "linux")]
const PR_SET_SECCOMP: i32 = 22;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const u8,
}

/// Information about Landlock availability and capabilities
#[napi(object)]
pub struct LandlockInfo {
    /// Whether Landlock is available on this system
    pub available: bool,
    /// ABI version (1, 2, or 3) if available
    pub abi_version: u32,
    /// Error message if not available
    pub error: Option<String>,
}

/// Configuration for applying Landlock sandbox
#[napi(object)]
pub struct LandlockConfig {
    /// Paths with read-only access (non-fatal if missing)
    pub ro_paths: Vec<String>,
    /// Paths with read-write access (must exist)
    pub rw_paths: Vec<String>,
    /// Paths with read-execute access (non-fatal if missing)
    pub rx_paths: Vec<String>,
    /// Path to seccomp BPF filter file (optional)
    pub seccomp_filter_path: Option<String>,
}

/// Check if Landlock is available and detect ABI version
#[napi]
pub fn check_landlock() -> LandlockInfo {
    match detect_abi() {
        Ok(abi) => LandlockInfo {
            available: true,
            abi_version: abi,
            error: None,
        },
        Err(e) => LandlockInfo {
            available: false,
            abi_version: 0,
            error: Some(e),
        },
    }
}

/// Apply Landlock sandbox to the current process
#[napi]
pub fn apply_landlock(config: LandlockConfig) -> Result<()> {
    // Detect ABI version
    let abi = detect_abi().map_err(|e| {
        Error::new(Status::GenericFailure, format!("Landlock not available: {}", e))
    })?;

    // Get access mask for this ABI version
    let access_mask = match abi {
        1 => ACCESS_ABI_V1,
        2 => ACCESS_ABI_V2,
        3 => ACCESS_ABI_V3,
        _ => {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Unsupported Landlock ABI version: {}", abi),
            ))
        }
    };

    // Create ruleset
    let ruleset_fd = create_ruleset(access_mask).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to create Landlock ruleset: {}", e),
        )
    })?;

    // Add read-write paths (fatal if missing)
    for path in &config.rw_paths {
        add_path_rule(ruleset_fd, path, access_mask, true).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to add RW path '{}': {}", path, e),
            )
        })?;
    }

    // Add read-only paths (non-fatal if missing)
    for path in &config.ro_paths {
        let _ = add_path_rule(ruleset_fd, path, ACCESS_RO, false);
    }

    // Add read-execute paths (non-fatal if missing)
    for path in &config.rx_paths {
        let _ = add_path_rule(ruleset_fd, path, ACCESS_RX, false);
    }

    // Apply seccomp filter if provided
    if let Some(seccomp_path) = &config.seccomp_filter_path {
        apply_seccomp_filter(seccomp_path).map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to apply seccomp filter: {}", e),
            )
        })?;
    }

    // Restrict the current process
    restrict_self(ruleset_fd).map_err(|e| {
        Error::new(
            Status::GenericFailure,
            format!("Failed to restrict process: {}", e),
        )
    })?;

    // Close ruleset fd
    unsafe {
        libc::close(ruleset_fd);
    }

    Ok(())
}

/// Detect the supported Landlock ABI version
fn detect_abi() -> std::result::Result<u32, String> {
    // Try ABI v3
    match create_ruleset(ACCESS_ABI_V3) {
        Ok(fd) => {
            unsafe { libc::close(fd) };
            return Ok(3);
        }
        Err(_) => {}
    }

    // Try ABI v2
    match create_ruleset(ACCESS_ABI_V2) {
        Ok(fd) => {
            unsafe { libc::close(fd) };
            return Ok(2);
        }
        Err(_) => {}
    }

    // Try ABI v1
    match create_ruleset(ACCESS_ABI_V1) {
        Ok(fd) => {
            unsafe { libc::close(fd) };
            return Ok(1);
        }
        Err(e) => Err(format!("Landlock not supported: {}", e)),
    }
}

/// Create a Landlock ruleset
fn create_ruleset(access_mask: u64) -> std::result::Result<i32, String> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: access_mask,
        handled_access_net: 0,
    };

    let fd = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if fd < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(fd as i32)
    }
}

/// Add a path rule to the ruleset
fn add_path_rule(
    ruleset_fd: i32,
    path: &str,
    access: u64,
    fatal: bool,
) -> std::result::Result<(), String> {
    // Open the path to get a file descriptor
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|e| format!("Failed to open path '{}': {}", path, e))?;

    let parent_fd = file.as_raw_fd();

    let attr = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd,
    };

    let ret = unsafe {
        libc::syscall(
            LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const _,
            0u32,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error().to_string();
        if fatal {
            return Err(err);
        }
    }

    Ok(())
}

/// Restrict the current process with the ruleset
fn restrict_self(ruleset_fd: i32) -> std::result::Result<(), String> {
    let ret = unsafe { libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };

    if ret != 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

/// Apply seccomp filter from a BPF file
fn apply_seccomp_filter(filter_path: &str) -> std::result::Result<(), String> {
    // Read BPF filter from file
    let mut file = File::open(filter_path)
        .map_err(|e| format!("Failed to open seccomp filter file: {}", e))?;

    let mut filter_data = Vec::new();
    file.read_to_end(&mut filter_data)
        .map_err(|e| format!("Failed to read seccomp filter: {}", e))?;

    if filter_data.is_empty() {
        return Err("Seccomp filter file is empty".to_string());
    }

    // Set NO_NEW_PRIVS
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(format!(
                "Failed to set NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Apply seccomp filter
        let prog = SockFprog {
            len: (filter_data.len() / 8) as u16,
            filter: filter_data.as_ptr(),
        };

        let ret = unsafe { libc::prctl(PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, &prog as *const _) };
        if ret != 0 {
            return Err(format!(
                "Failed to apply seccomp filter: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    return Err("Seccomp is only available on Linux".to_string());

    #[cfg(target_os = "linux")]
    Ok(())
}
