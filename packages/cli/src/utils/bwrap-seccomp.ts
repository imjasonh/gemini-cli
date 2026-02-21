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
const SECCOMP_RET_ERRNO_ENOSYS = 0x00050026; // SECCOMP_RET_ERRNO | ENOSYS

// Syscall numbers for x86_64 (from arch/x86/entry/syscalls/syscall_64.tbl)
const SYSCALLS_X86_64: Record<string, number> = {
  chroot: 161,
  pivot_root: 155,
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
  perf_event_open: 298,
  setns: 308,
  process_vm_readv: 310,
  process_vm_writev: 311,
  finit_module: 313,
  kexec_file_load: 320,
  bpf: 321,
  userfaultfd: 323,
  clone3: 435,
};

// Syscall numbers for aarch64 (from include/uapi/asm-generic/unistd.h)
const SYSCALLS_AARCH64: Record<string, number> = {
  pivot_root: 41,
  chroot: 51,
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
  perf_event_open: 241,
  setns: 268,
  process_vm_readv: 270,
  process_vm_writev: 271,
  finit_module: 273,
  bpf: 280,
  userfaultfd: 282,
  kexec_file_load: 294,
  clone3: 435,
};

// Syscalls blocked by the seccomp filter
const BLOCKED_SYSCALLS = [
  // Debugging/tracing (container escape vector)
  'ptrace',
  'process_vm_readv',
  'process_vm_writev',
  'perf_event_open',

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

  // Mount/root operations (belt-and-suspenders with mount namespace)
  'mount',
  'umount2',
  'pivot_root',
  'chroot',

  // Reboot/power operations
  'reboot',
  'kexec_load',
  'kexec_file_load',

  // Clock manipulation
  'clock_settime',
  'settimeofday',
  'adjtimex',

  // Advanced kernel features (often used in exploits)
  'bpf',
  'userfaultfd',
];

// Syscalls blocked with ENOSYS instead of EPERM. glibc 2.34+ uses clone3
// for thread/process creation and treats EPERM as fatal. Returning ENOSYS
// triggers glibc's fallback to clone(), which works normally.
const ENOSYS_SYSCALLS = ['clone3'];

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
 * Supports two deny groups with different return values. ENOSYS entries
 * are checked first so glibc can fall back to older syscalls (e.g.
 * clone3 → clone). EPERM entries are checked next.
 *
 * Program layout:
 *   [0]           Load arch
 *   [1]           If arch != target, jump to ALLOW
 *   [2]           Load syscall number
 *   [3..2+E]      ENOSYS checks: if match, jump to ENOSYS return
 *   [3+E..2+E+P]  EPERM checks: if match, jump to EPERM return
 *   [3+E+P]       ALLOW
 *   [4+E+P]       ENOSYS return (if E > 0)
 *   [4/5+E+P]     EPERM return
 */
export function buildBpfFilter(
  auditArch: number,
  blockedNumbers: number[],
  enosysNumbers: number[] = [],
): Buffer {
  const E = enosysNumbers.length;
  const P = blockedNumbers.length;
  const instructions: BpfInstruction[] = [];

  // Load architecture
  instructions.push({ code: BPF_LD_W_ABS, jt: 0, jf: 0, k: OFFSET_ARCH });

  // Check architecture: if match continue, else skip to ALLOW
  instructions.push({
    code: BPF_JMP_JEQ_K,
    jt: 0,
    jf: E + P + 1,
    k: auditArch,
  });

  // Load syscall number
  instructions.push({ code: BPF_LD_W_ABS, jt: 0, jf: 0, k: OFFSET_NR });

  // ENOSYS checks (checked first)
  for (let i = 0; i < E; i++) {
    // Target: ENOSYS return at [3+E+P+1] from here at [3+i]
    // jt = (3+E+P+1) - (3+i) - 1 = E+P-i
    instructions.push({
      code: BPF_JMP_JEQ_K,
      jt: E + P - i,
      jf: 0,
      k: enosysNumbers[i],
    });
  }

  // EPERM checks
  for (let i = 0; i < P; i++) {
    // Target: EPERM return at [3+E+P+1+(E>0?1:0)] from here at [3+E+i]
    // With ENOSYS block: jt = (3+E+P+2) - (3+E+i) - 1 = P-i+1
    // Without: jt = (3+E+P+1) - (3+E+i) - 1 = P-i
    const jt = E > 0 ? P - i + 1 : P - i;
    instructions.push({
      code: BPF_JMP_JEQ_K,
      jt,
      jf: 0,
      k: blockedNumbers[i],
    });
  }

  // Default: ALLOW
  instructions.push({ code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW });

  // ENOSYS return (only emitted when there are ENOSYS entries)
  if (E > 0) {
    instructions.push({
      code: BPF_RET_K,
      jt: 0,
      jf: 0,
      k: SECCOMP_RET_ERRNO_ENOSYS,
    });
  }

  // EPERM return
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

  const enosysNumbers = ENOSYS_SYSCALLS.map((name) => table[name]).filter(
    (n): n is number => n !== undefined,
  );

  if (blockedNumbers.length === 0 && enosysNumbers.length === 0) {
    return null;
  }

  return buildBpfFilter(auditArch, blockedNumbers, enosysNumbers);
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
  ENOSYS_SYSCALLS,
  SYSCALLS_X86_64,
  SYSCALLS_AARCH64,
  AUDIT_ARCH_X86_64,
  AUDIT_ARCH_AARCH64,
  SECCOMP_RET_ALLOW,
  SECCOMP_RET_ERRNO_EPERM,
  SECCOMP_RET_ERRNO_ENOSYS,
  BPF_LD_W_ABS,
  BPF_JMP_JEQ_K,
  BPF_RET_K,
  OFFSET_NR,
  OFFSET_ARCH,
};
