/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Information about Landlock availability and capabilities
 */
export interface LandlockInfo {
  /** Whether Landlock is available on this system */
  available: boolean;
  /** ABI version (1, 2, or 3) if available */
  abiVersion: number;
  /** Error message if not available */
  error?: string;
}

/**
 * Configuration for applying Landlock sandbox
 */
export interface LandlockConfig {
  /** Paths with read-only access (non-fatal if missing) */
  roPaths: Array<string>;
  /** Paths with read-write access (must exist) */
  rwPaths: Array<string>;
  /** Paths with read-execute access (non-fatal if missing) */
  rxPaths: Array<string>;
  /** Path to seccomp BPF filter file (optional) */
  seccompFilterPath?: string;
}

/**
 * Check if Landlock is available and detect ABI version
 */
export function checkLandlock(): LandlockInfo;

/**
 * Apply Landlock sandbox to the current process
 * @throws {Error} If Landlock is not available or sandboxing fails
 */
export function applyLandlock(config: LandlockConfig): void;
