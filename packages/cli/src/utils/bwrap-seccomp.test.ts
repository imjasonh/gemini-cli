/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import {
  buildBpfFilter,
  generateSeccompFilter,
  generateSeccompFilterBuffer,
  prepareSeccompFd,
  prepareSeccompFile,
  cleanupSeccomp,
  cleanupSeccompFile,
  _testing,
} from './bwrap-seccomp.js';

vi.mock('node:fs');

describe('bwrap-seccomp', () => {
  const originalEnv = process.env;
  const originalArch = process.arch;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    // Default to x64 for deterministic tests
    Object.defineProperty(process, 'arch', {
      value: 'x64',
      configurable: true,
    });
  });

  afterEach(() => {
    process.env = originalEnv;
    Object.defineProperty(process, 'arch', {
      value: originalArch,
      configurable: true,
    });
  });

  describe('buildBpfFilter', () => {
    it('should produce correct number of bytes', () => {
      const blocked = [101, 175]; // ptrace, init_module
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, blocked);
      // 3 header + N checks + 2 returns = 3 + 2 + 2 = 7 instructions × 8 bytes
      expect(buf.length).toBe(7 * 8);
    });

    it('should start with load-arch instruction', () => {
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, [101]);
      expect(buf.readUInt16LE(0)).toBe(_testing.BPF_LD_W_ABS);
      expect(buf.readUInt32LE(4)).toBe(_testing.OFFSET_ARCH);
    });

    it('should have arch check as second instruction', () => {
      const blocked = [101, 175];
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, blocked);
      // Instruction [1]: JEQ arch
      expect(buf.readUInt16LE(8)).toBe(_testing.BPF_JMP_JEQ_K);
      expect(buf.readUInt8(10)).toBe(0); // jt: continue
      expect(buf.readUInt8(11)).toBe(blocked.length + 1); // jf: skip to ALLOW
      expect(buf.readUInt32LE(12)).toBe(_testing.AUDIT_ARCH_X86_64);
    });

    it('should load syscall number as third instruction', () => {
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, [101]);
      expect(buf.readUInt16LE(16)).toBe(_testing.BPF_LD_W_ABS);
      expect(buf.readUInt32LE(20)).toBe(_testing.OFFSET_NR);
    });

    it('should check each blocked syscall', () => {
      const blocked = [101, 175, 176];
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, blocked);
      // Instructions [3..5] should be JEQ checks for each syscall
      for (let i = 0; i < blocked.length; i++) {
        const off = (3 + i) * 8;
        expect(buf.readUInt16LE(off)).toBe(_testing.BPF_JMP_JEQ_K);
        expect(buf.readUInt32LE(off + 4)).toBe(blocked[i]);
        expect(buf.readUInt8(off + 2)).toBe(blocked.length - i); // jt → DENY
        expect(buf.readUInt8(off + 3)).toBe(0); // jf → next
      }
    });

    it('should end with ALLOW then DENY return instructions', () => {
      const blocked = [101];
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, blocked);
      const total = 3 + blocked.length + 2; // 6 instructions
      // ALLOW (second-to-last)
      const allowOff = (total - 2) * 8;
      expect(buf.readUInt16LE(allowOff)).toBe(_testing.BPF_RET_K);
      expect(buf.readUInt32LE(allowOff + 4)).toBe(_testing.SECCOMP_RET_ALLOW);
      // DENY (last)
      const denyOff = (total - 1) * 8;
      expect(buf.readUInt16LE(denyOff)).toBe(_testing.BPF_RET_K);
      expect(buf.readUInt32LE(denyOff + 4)).toBe(
        _testing.SECCOMP_RET_ERRNO_EPERM,
      );
    });

    it('should produce valid jump targets for single blocked syscall', () => {
      const buf = buildBpfFilter(_testing.AUDIT_ARCH_X86_64, [101]);
      // [1] arch check: jf should skip to ALLOW = 1+1 = 2 instructions ahead
      expect(buf.readUInt8(11)).toBe(2); // N+1 = 1+1
      // [3] syscall check: jt should reach DENY = 1 instruction ahead
      expect(buf.readUInt8(26)).toBe(1); // N-i = 1-0
    });
  });

  describe('generateSeccompFilter', () => {
    it('should return a buffer on x64', () => {
      const filter = generateSeccompFilter();
      expect(filter).toBeInstanceOf(Buffer);
      expect(filter!.length).toBeGreaterThan(0);
    });

    it('should return a buffer on arm64', () => {
      Object.defineProperty(process, 'arch', {
        value: 'arm64',
        configurable: true,
      });
      const filter = generateSeccompFilter();
      expect(filter).toBeInstanceOf(Buffer);
      expect(filter!.length).toBeGreaterThan(0);
    });

    it('should return null when BWRAP_SECCOMP=off', () => {
      process.env['BWRAP_SECCOMP'] = 'off';
      expect(generateSeccompFilter()).toBeNull();
    });

    it('should return null for unsupported architecture', () => {
      Object.defineProperty(process, 'arch', {
        value: 's390x',
        configurable: true,
      });
      expect(generateSeccompFilter()).toBeNull();
    });

    it('should block all expected syscalls', () => {
      const filter = generateSeccompFilter()!;
      // Total instructions: 3 (header) + N (checks) + 2 (allow/deny)
      const N = _testing.BLOCKED_SYSCALLS.length;
      expect(filter.length).toBe((3 + N + 2) * 8);
    });

    it('should use x86_64 arch value on x64', () => {
      const filter = generateSeccompFilter()!;
      // Instruction [1] k field should be x86_64 audit arch
      expect(filter.readUInt32LE(12)).toBe(_testing.AUDIT_ARCH_X86_64);
    });

    it('should use aarch64 arch value on arm64', () => {
      Object.defineProperty(process, 'arch', {
        value: 'arm64',
        configurable: true,
      });
      const filter = generateSeccompFilter()!;
      expect(filter.readUInt32LE(12)).toBe(_testing.AUDIT_ARCH_AARCH64);
    });
  });

  describe('syscall tables', () => {
    it('should have the same syscall names in both tables', () => {
      const x64Names = Object.keys(_testing.SYSCALLS_X86_64).sort();
      const arm64Names = Object.keys(_testing.SYSCALLS_AARCH64).sort();
      expect(x64Names).toEqual(arm64Names);
    });

    it('should have all blocked syscalls in x86_64 table', () => {
      for (const name of _testing.BLOCKED_SYSCALLS) {
        expect(_testing.SYSCALLS_X86_64).toHaveProperty(name);
      }
    });

    it('should have all blocked syscalls in aarch64 table', () => {
      for (const name of _testing.BLOCKED_SYSCALLS) {
        expect(_testing.SYSCALLS_AARCH64).toHaveProperty(name);
      }
    });

    it('should have different syscall numbers per architecture', () => {
      // ptrace is a well-known syscall with different numbers
      expect(_testing.SYSCALLS_X86_64['ptrace']).not.toBe(
        _testing.SYSCALLS_AARCH64['ptrace'],
      );
    });
  });

  describe('prepareSeccompFd', () => {
    it('should write filter to temp file and open fd', () => {
      vi.mocked(fs.writeFileSync).mockImplementation(() => {});
      vi.mocked(fs.openSync).mockReturnValue(42);

      const result = prepareSeccompFd();
      expect(result).not.toBeNull();
      expect(result!.fd).toBe(42);
      expect(result!.path).toMatch(/bwrap-seccomp-.*\.bpf$/);
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        result!.path,
        expect.any(Buffer),
      );
      expect(fs.openSync).toHaveBeenCalledWith(result!.path, 'r');
    });

    it('should return null when BWRAP_SECCOMP=off', () => {
      process.env['BWRAP_SECCOMP'] = 'off';
      expect(prepareSeccompFd()).toBeNull();
    });
  });

  describe('cleanupSeccomp', () => {
    it('should close fd and unlink file', () => {
      vi.mocked(fs.closeSync).mockImplementation(() => {});
      vi.mocked(fs.unlinkSync).mockImplementation(() => {});

      cleanupSeccomp({ fd: 42, path: '/tmp/test.bpf' });
      expect(fs.closeSync).toHaveBeenCalledWith(42);
      expect(fs.unlinkSync).toHaveBeenCalledWith('/tmp/test.bpf');
    });

    it('should not throw if close or unlink fails', () => {
      vi.mocked(fs.closeSync).mockImplementation(() => {
        throw new Error('already closed');
      });
      vi.mocked(fs.unlinkSync).mockImplementation(() => {
        throw new Error('not found');
      });

      expect(() =>
        cleanupSeccomp({ fd: 42, path: '/tmp/test.bpf' }),
      ).not.toThrow();
    });
  });

  describe('generateSeccompFilterBuffer', () => {
    it('should return a buffer on x64 regardless of BWRAP_SECCOMP env', () => {
      process.env['BWRAP_SECCOMP'] = 'off';
      const filter = generateSeccompFilterBuffer();
      expect(filter).toBeInstanceOf(Buffer);
      expect(filter!.length).toBeGreaterThan(0);
    });

    it('should return null for unsupported architecture', () => {
      Object.defineProperty(process, 'arch', {
        value: 's390x',
        configurable: true,
      });
      expect(generateSeccompFilterBuffer()).toBeNull();
    });
  });

  describe('prepareSeccompFile', () => {
    it('should write filter to temp file and return path', () => {
      vi.mocked(fs.writeFileSync).mockImplementation(() => {});

      const result = prepareSeccompFile();
      expect(result).not.toBeNull();
      expect(result!.path).toMatch(/seccomp-.*\.bpf$/);
      expect(fs.writeFileSync).toHaveBeenCalledWith(
        result!.path,
        expect.any(Buffer),
      );
    });

    it('should return null for unsupported architecture', () => {
      Object.defineProperty(process, 'arch', {
        value: 's390x',
        configurable: true,
      });
      expect(prepareSeccompFile()).toBeNull();
    });
  });

  describe('cleanupSeccompFile', () => {
    it('should unlink file', () => {
      vi.mocked(fs.unlinkSync).mockImplementation(() => {});

      cleanupSeccompFile({ path: '/tmp/test.bpf' });
      expect(fs.unlinkSync).toHaveBeenCalledWith('/tmp/test.bpf');
    });

    it('should not throw if unlink fails', () => {
      vi.mocked(fs.unlinkSync).mockImplementation(() => {
        throw new Error('not found');
      });

      expect(() => cleanupSeccompFile({ path: '/tmp/test.bpf' })).not.toThrow();
    });
  });
});
