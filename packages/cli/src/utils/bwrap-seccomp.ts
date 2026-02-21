/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// BPF instruction codes
const BPF_LD_W_ABS = 0x20; // Load 32-bit word at absolute offset
const BPF_JMP_JEQ_K = 0x15; // Jump if A == k
const BPF_RET_K = 0x06; // Return immediate value

// Seccomp data offsets (struct seccomp_data)
const OFFSET_NR = 0; // Syscall number
const OFFSET_ARCH = 4; // Architecture

// Architecture audit values
const AUDIT_ARCH_X86_64 = 0xc000003e;
const AUDIT_ARCH_AARCH64 = 0xc00000b7;

// Seccomp return values
const SECCOMP_RET_ALLOW = 0x7fff0000;
const SECCOMP_RET_ERRNO_EPERM = 0x00050001; // SECCOMP_RET_ERRNO | EPERM

// Syscall numbers for x86_64 (from arch/x86/entry/syscalls/syscall_64.tbl)
const SYSCALLS_X86_64: Record<string, number> = {
  ptrace: 101,
  personality: 135,
  adjtimex: 159,
  settimeofday: 164,
  mount: 165,
  umount2: 166,
  reboot: 169,
  init_module: 175,
  delete_module: 176,
  clock_settime: 227,
  kexec_load: 246,
  add_key: 248,
  request_key: 249,
  keyctl: 250,
  unshare: 272,
  setns: 308,
  process_vm_readv: 310,
  process_vm_writev: 311,
  finit_module: 313,
  kexec_file_load: 320,
};

// Syscall numbers for aarch64 (from include/uapi/asm-generic/unistd.h)
const SYSCALLS_AARCH64: Record<string, number> = {
  umount2: 39,
  mount: 40,
  personality: 92,
  unshare: 97,
  kexec_load: 104,
  init_module: 105,
  delete_module: 106,
  clock_settime: 112,
  ptrace: 117,
  reboot: 142,
  settimeofday: 170,
  adjtimex: 171,
  add_key: 217,
  request_key: 218,
  keyctl: 219,
  setns: 268,
  process_vm_readv: 270,
  process_vm_writev: 271,
  finit_module: 273,
  kexec_file_load: 294,
};

// Syscalls blocked by the seccomp filter
const BLOCKED_SYSCALLS = [
  // Debugging/tracing (container escape vector)
  'ptrace',
  'process_vm_readv',
  'process_vm_writev',

  // Kernel module operations
  'init_module',
  'finit_module',
  'delete_module',

  // Key management (potential privilege escalation)
  'keyctl',
  'add_key',
  'request_key',

  // Personality (can disable ASLR)
  'personality',

  // Namespace manipulation from within sandbox
  'setns',
  'unshare',

  // Mount operations (belt-and-suspenders with mount namespace)
  'mount',
  'umount2',

  // Reboot/power operations
  'reboot',
  'kexec_load',
  'kexec_file_load',

  // Clock manipulation
  'clock_settime',
  'settimeofday',
  'adjtimex',
];

interface BpfInstruction {
  code: number;
  jt: number;
  jf: number;
  k: number;
}

function getSyscallTable(): {
  table: Record<string, number>;
  auditArch: number;
} {
  if (process.arch === 'x64') {
    return { table: SYSCALLS_X86_64, auditArch: AUDIT_ARCH_X86_64 };
  }
  if (process.arch === 'arm64') {
    return { table: SYSCALLS_AARCH64, auditArch: AUDIT_ARCH_AARCH64 };
  }
  return { table: {}, auditArch: 0 };
}

/**
 * Builds a compiled BPF deny-list filter for seccomp.
 *
 * Program layout:
 *   [0]       Load arch
 *   [1]       If arch != target, jump to ALLOW
 *   [2]       Load syscall number
 *   [3..N+2]  For each blocked syscall: if match, jump to DENY
 *   [N+3]     ALLOW
 *   [N+4]     DENY (return EPERM)
 */
export function buildBpfFilter(
  auditArch: number,
  blockedNumbers: number[],
): Buffer {
  const N = blockedNumbers.length;
  const instructions: BpfInstruction[] = [];

  // Load architecture
  instructions.push({ code: BPF_LD_W_ABS, jt: 0, jf: 0, k: OFFSET_ARCH });

  // Check architecture: if match continue, else skip to ALLOW
  instructions.push({
    code: BPF_JMP_JEQ_K,
    jt: 0,
    jf: N + 1,
    k: auditArch,
  });

  // Load syscall number
  instructions.push({ code: BPF_LD_W_ABS, jt: 0, jf: 0, k: OFFSET_NR });

  // Check each blocked syscall
  for (let i = 0; i < N; i++) {
    instructions.push({
      code: BPF_JMP_JEQ_K,
      jt: N - i, // Forward to DENY
      jf: 0, // Fall through to next check
      k: blockedNumbers[i],
    });
  }

  // Default: ALLOW
  instructions.push({ code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });

  // DENY: return EPERM
  instructions.push({
    code: BPF_RET_K,
    jt: 0,
    jf: 0,
    k: SECCOMP_RET_ERRNO_EPERM,
  });

  // Serialize to binary (each sock_filter is 8 bytes, little-endian)
  const buf = Buffer.alloc(instructions.length * 8);
  for (let i = 0; i < instructions.length; i++) {
    const inst = instructions[i];
    const off = i * 8;
    buf.writeUInt16LE(inst.code, off);
    buf.writeUInt8(inst.jt, off + 2);
    buf.writeUInt8(inst.jf, off + 3);
    buf.writeUInt32LE(inst.k, off + 4);
  }

  return buf;
}

/**
 * Builds the BPF seccomp filter buffer for the current architecture.
 * Returns null if the architecture is unsupported.
 */
export function generateSeccompFilterBuffer(): Buffer | null {
  const { table, auditArch } = getSyscallTable();
  if (auditArch === 0) {
    return null;
  }

  const blockedNumbers = BLOCKED_SYSCALLS.map((name) => table[name]).filter(
    (n): n is number => n !== undefined,
  );

  if (blockedNumbers.length === 0) {
    return null;
  }

  return buildBpfFilter(auditArch, blockedNumbers);
}

/**
 * Generates a compiled BPF seccomp filter that blocks dangerous syscalls.
 *
 * Returns null if seccomp is disabled via BWRAP_SECCOMP=off or the
 * host architecture is unsupported.
 */
export function generateSeccompFilter(): Buffer | null {
  if (process.env['BWRAP_SECCOMP'] === 'off') {
    return null;
  }
  return generateSeccompFilterBuffer();
}

/**
 * Writes the seccomp filter to a temp file and returns the open
 * file descriptor (for reading) and the path for cleanup.
 *
 * Returns null if no filter should be applied.
 */
export function prepareSeccompFd(): { fd: number; path: string } | null {
  const filter = generateSeccompFilter();
  if (!filter) {
    return null;
  }

  const tmpFile = path.join(
    os.tmpdir(),
    `bwrap-seccomp-${process.pid}-${Date.now()}.bpf`,
  );
  fs.writeFileSync(tmpFile, filter);
  const fd = fs.openSync(tmpFile, 'r');
  return { fd, path: tmpFile };
}

/**
 * Cleans up the seccomp temp file and closes the fd.
 */
export function cleanupSeccomp(seccomp: { fd: number; path: string }): void {
  try {
    fs.closeSync(seccomp.fd);
  } catch {
    // fd may already be closed
  }
  try {
    fs.unlinkSync(seccomp.path);
  } catch {
    // file may already be removed
  }
}

/**
 * Writes the seccomp filter to a temp file and returns the path.
 * Unlike prepareSeccompFd(), this does not open an fd — the caller
 * passes the path to the child process (e.g. landlock-helper --seccomp FILE).
 *
 * Returns null if the filter is disabled or unsupported.
 */
export function prepareSeccompFile(): { path: string } | null {
  const filter = generateSeccompFilterBuffer();
  if (!filter) {
    return null;
  }

  const tmpFile = path.join(
    os.tmpdir(),
    `seccomp-${process.pid}-${Date.now()}.bpf`,
  );
  fs.writeFileSync(tmpFile, filter);
  return { path: tmpFile };
}

/**
 * Cleans up a seccomp temp file (no fd to close).
 */
export function cleanupSeccompFile(seccomp: { path: string }): void {
  try {
    fs.unlinkSync(seccomp.path);
  } catch {
    // file may already be removed
  }
}

// Exported for testing
export const _testing = {
  BLOCKED_SYSCALLS,
  SYSCALLS_X86_64,
  SYSCALLS_AARCH64,
  AUDIT_ARCH_X86_64,
  AUDIT_ARCH_AARCH64,
  SECCOMP_RET_ALLOW,
  SECCOMP_RET_ERRNO_EPERM,
  BPF_LD_W_ABS,
  BPF_JMP_JEQ_K,
  BPF_RET_K,
  OFFSET_NR,
  OFFSET_ARCH,
};
