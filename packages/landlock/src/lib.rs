// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

//! Landlock sandbox implementation for Gemini CLI
//!
//! This module provides unprivileged filesystem sandboxing using Linux Landlock LSM.
//! Requires Linux kernel 5.13+ with Landlock enabled.

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

#[cfg(target_os = "linux")]
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};

/// Information about Landlock availability and capabilities
#[napi(object)]
pub struct LandlockInfo {
    pub available: bool,
    pub abi_version: u32,
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
    #[cfg(target_os = "linux")]
    {
        let abi = detect_abi();
        if abi == ABI::Unsupported {
            return LandlockInfo {
                available: false,
                abi_version: 0,
                error: Some("Landlock not supported by this kernel".to_string()),
            };
        }
        LandlockInfo {
            available: true,
            abi_version: abi as u32,
            error: None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    LandlockInfo {
        available: false,
        abi_version: 0,
        error: Some("Landlock is only available on Linux".to_string()),
    }
}

/// Apply Landlock sandbox to the current process
#[napi]
pub fn apply_landlock(config: LandlockConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let abi = detect_abi();
        if abi == ABI::Unsupported {
            return Err(Error::new(
                Status::GenericFailure,
                "Landlock not supported by this kernel",
            ));
        }

        let access_all = AccessFs::from_all(abi);
        let access_read = AccessFs::from_read(abi);

        let mut ruleset = Ruleset::default()
            .handle_access(access_all)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to create ruleset: {e}")))?
            .create()
            .map_err(|e| Error::new(Status::GenericFailure, format!("Failed to create ruleset: {e}")))?;

        // Add read-write paths (all access, silently ignores missing paths)
        ruleset = ruleset
            .add_rules(path_beneath_rules(&config.rw_paths, access_all))
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to add RW path rules: {e}"),
                )
            })?;

        // Add read-only paths (silently ignores missing paths)
        ruleset = ruleset
            .add_rules(path_beneath_rules(&config.ro_paths, access_read))
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to add RO path rules: {e}"),
                )
            })?;

        // Add read-execute paths (read + execute access)
        let access_rx = access_read | AccessFs::Execute;
        ruleset = ruleset
            .add_rules(path_beneath_rules(&config.rx_paths, access_rx))
            .map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to add RX path rules: {e}"),
                )
            })?;

        // Apply seccomp filter before restricting (seccomp is independent of landlock)
        if let Some(seccomp_path) = &config.seccomp_filter_path {
            apply_seccomp_filter(seccomp_path).map_err(|e| {
                Error::new(
                    Status::GenericFailure,
                    format!("Failed to apply seccomp filter: {e}"),
                )
            })?;
        }

        // Restrict the current process
        let status = ruleset.restrict_self().map_err(|e| {
            Error::new(
                Status::GenericFailure,
                format!("Failed to restrict process: {e}"),
            )
        })?;

        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(Error::new(
                Status::GenericFailure,
                format!("Landlock not fully enforced: {:?}", status.ruleset),
            ));
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Err(Error::new(
            Status::GenericFailure,
            "Landlock is only available on Linux",
        ))
    }
}

/// Detect the best supported Landlock ABI version
#[cfg(target_os = "linux")]
fn detect_abi() -> ABI {
    // Try from newest to oldest
    for abi in [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1] {
        let access = AccessFs::from_all(abi);
        if Ruleset::default()
            .handle_access(access)
            .and_then(|r| r.create())
            .is_ok()
        {
            return abi;
        }
    }
    ABI::Unsupported
}

/// Apply seccomp filter from a BPF file
#[cfg(target_os = "linux")]
fn apply_seccomp_filter(filter_path: &str) -> std::result::Result<(), String> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(filter_path)
        .map_err(|e| format!("Failed to open seccomp filter file: {e}"))?;

    let mut filter_data = Vec::new();
    file.read_to_end(&mut filter_data)
        .map_err(|e| format!("Failed to read seccomp filter: {e}"))?;

    if filter_data.is_empty() {
        return Err("Seccomp filter file is empty".to_string());
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const u8,
    }

    // NO_NEW_PRIVS is set by landlock's restrict_self(), but we need it
    // before seccomp too. Setting it again is harmless.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(format!(
            "Failed to set NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }

    let prog = SockFprog {
        len: (filter_data.len() / 8) as u16,
        filter: filter_data.as_ptr(),
    };

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const _,
        )
    };
    if ret != 0 {
        return Err(format!(
            "Failed to apply seccomp filter: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}
