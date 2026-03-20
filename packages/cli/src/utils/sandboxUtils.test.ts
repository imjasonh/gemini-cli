/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import os from 'node:os';
import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import commandExists from 'command-exists';
import {
  detectContainerEnvironment,
  getContainerPath,
  parseImageName,
  ports,
  entrypoint,
  shouldUseCurrentUserInSandbox,
  isMacOSContainerAvailable,
  isBwrapAvailable,
  isLandlockAvailable,
  isWSL,
  isWSL2,
} from './sandboxUtils.js';

vi.mock('node:os');
vi.mock('node:fs');
vi.mock('node:fs/promises');
vi.mock('node:child_process');
vi.mock('command-exists', () => {
  const sync = vi.fn();
  return {
    sync,
    default: { sync },
  };
});
const { mockedCheckLandlock } = vi.hoisted(() => ({
  mockedCheckLandlock: vi.fn(),
}));

vi.mock('@google/gemini-cli-core', () => ({
  debugLogger: {
    log: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  },
  GEMINI_DIR: '.gemini',
}));

vi.mock('@google/gemini-cli-landlock', () => ({
  default: {
    checkLandlock: mockedCheckLandlock,
    applyLandlock: vi.fn(),
  },
  checkLandlock: mockedCheckLandlock,
  applyLandlock: vi.fn(),
}));

// Mock execFile used by isMacOSContainerAvailable via promisify
vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

import { execFile } from 'node:child_process';

const mockedExecFile = vi.mocked(execFile);
const mockedCommandExistsSync = vi.mocked(commandExists.sync);
const mockedReadFile = vi.mocked(readFile);

describe('sandboxUtils', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    // Clean up these env vars that might affect tests
    delete process.env['NODE_ENV'];
    delete process.env['DEBUG'];
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('detectContainerEnvironment', () => {
    it('should detect Gemini sandbox via SANDBOX env var', () => {
      process.env['SANDBOX'] = 'my-container';
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'unknown',
        isGeminiSandbox: true,
      });
    });

    it('should detect Docker via /.dockerenv', () => {
      vi.mocked(fs.existsSync).mockImplementation((p) => p === '/.dockerenv');
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'docker',
        isGeminiSandbox: false,
      });
    });

    it('should detect Podman via /run/.containerenv', () => {
      vi.mocked(fs.existsSync).mockImplementation(
        (p) => p === '/run/.containerenv',
      );
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'podman',
        isGeminiSandbox: false,
      });
    });

    it('should detect Kubernetes via KUBERNETES_SERVICE_HOST', () => {
      process.env['KUBERNETES_SERVICE_HOST'] = '10.0.0.1';
      vi.mocked(fs.existsSync).mockReturnValue(false);
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'kubernetes',
        isGeminiSandbox: false,
      });
    });

    it('should detect WSL1 as container via WSL_DISTRO_NAME', () => {
      process.env['WSL_DISTRO_NAME'] = 'Ubuntu';
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(os.release).mockReturnValue('4.4.0-19041-Microsoft');
      vi.mocked(fs.existsSync).mockReturnValue(false);
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'wsl1',
        isGeminiSandbox: false,
      });
    });

    it('should NOT detect WSL2 as container (WSL2 supports sandboxing)', () => {
      process.env['WSL_DISTRO_NAME'] = 'Ubuntu';
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(os.release).mockReturnValue(
        '5.15.153.1-microsoft-standard-WSL2',
      );
      vi.mocked(fs.existsSync).mockReturnValue(false);
      vi.mocked(fs.readFileSync).mockImplementation(() => {
        throw new Error('ENOENT');
      });
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: false,
        type: 'none',
        isGeminiSandbox: false,
      });
    });

    it('should detect systemd-nspawn', () => {
      process.env['container'] = 'systemd-nspawn';
      vi.mocked(fs.existsSync).mockReturnValue(false);
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'systemd-nspawn',
        isGeminiSandbox: false,
      });
    });

    it('should detect container via cgroups', () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);
      vi.mocked(fs.readFileSync).mockReturnValue('12:devices:/docker/abc123\n');
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: true,
        type: 'unknown',
        isGeminiSandbox: false,
      });
    });

    it('should return none when not in any container', () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);
      vi.mocked(fs.readFileSync).mockImplementation(() => {
        throw new Error('ENOENT');
      });
      const result = detectContainerEnvironment();
      expect(result).toEqual({
        detected: false,
        type: 'none',
        isGeminiSandbox: false,
      });
    });
  });

  describe('getContainerPath', () => {
    it('should return same path on non-Windows', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      expect(getContainerPath('/home/user')).toBe('/home/user');
    });

    it('should convert Windows path to container path', () => {
      vi.mocked(os.platform).mockReturnValue('win32');
      expect(getContainerPath('C:\\Users\\user')).toBe('/c/Users/user');
    });

    it('should handle Windows path without drive letter', () => {
      vi.mocked(os.platform).mockReturnValue('win32');
      expect(getContainerPath('\\Users\\user')).toBe('/Users/user');
    });
  });

  describe('parseImageName', () => {
    it('should parse image name with tag', () => {
      expect(parseImageName('my-image:latest')).toBe('my-image-latest');
    });

    it('should parse image name without tag', () => {
      expect(parseImageName('my-image')).toBe('my-image');
    });

    it('should handle registry path', () => {
      expect(parseImageName('gcr.io/my-project/my-image:v1')).toBe(
        'my-image-v1',
      );
    });
  });

  describe('ports', () => {
    it('should return empty array if SANDBOX_PORTS is not set', () => {
      delete process.env['SANDBOX_PORTS'];
      expect(ports()).toEqual([]);
    });

    it('should parse comma-separated ports', () => {
      process.env['SANDBOX_PORTS'] = '8080, 3000 , 9000';
      expect(ports()).toEqual(['8080', '3000', '9000']);
    });
  });

  describe('entrypoint', () => {
    beforeEach(() => {
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(fs.existsSync).mockReturnValue(false);
    });

    it('should generate default entrypoint', () => {
      const args = entrypoint('/work', ['node', 'gemini', 'arg1']);
      expect(args).toEqual(['bash', '-c', 'gemini arg1']);
    });

    it('should include PATH and PYTHONPATH if set', () => {
      process.env['PATH'] = '/work/bin:/usr/bin';
      process.env['PYTHONPATH'] = '/work/lib';
      const args = entrypoint('/work', ['node', 'gemini', 'arg1']);
      expect(args[2]).toContain('export PATH="$PATH:/work/bin"');
      expect(args[2]).toContain('export PYTHONPATH="$PYTHONPATH:/work/lib"');
    });

    it('should source sandbox.bashrc if exists', () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      const args = entrypoint('/work', ['node', 'gemini', 'arg1']);
      expect(args[2]).toContain('source .gemini/sandbox.bashrc');
    });

    it('should include socat commands for ports', () => {
      process.env['SANDBOX_PORTS'] = '8080';
      const args = entrypoint('/work', ['node', 'gemini', 'arg1']);
      expect(args[2]).toContain('socat TCP4-LISTEN:8080');
    });

    it('should use development command if NODE_ENV is development', () => {
      process.env['NODE_ENV'] = 'development';
      const args = entrypoint('/work', ['node', 'gemini', 'arg1']);
      expect(args[2]).toContain('npm rebuild && npm run start --');
    });
  });

  describe('shouldUseCurrentUserInSandbox', () => {
    it('should return true if SANDBOX_SET_UID_GID is 1', async () => {
      process.env['SANDBOX_SET_UID_GID'] = '1';
      expect(await shouldUseCurrentUserInSandbox()).toBe(true);
    });

    it('should return false if SANDBOX_SET_UID_GID is 0', async () => {
      process.env['SANDBOX_SET_UID_GID'] = '0';
      expect(await shouldUseCurrentUserInSandbox()).toBe(false);
    });

    it('should return true on Debian Linux', async () => {
      delete process.env['SANDBOX_SET_UID_GID'];
      vi.mocked(os.platform).mockReturnValue('linux');
      mockedReadFile.mockResolvedValue('ID=debian\n');
      expect(await shouldUseCurrentUserInSandbox()).toBe(true);
    });

    it('should return false on non-Linux', async () => {
      delete process.env['SANDBOX_SET_UID_GID'];
      vi.mocked(os.platform).mockReturnValue('darwin');
      expect(await shouldUseCurrentUserInSandbox()).toBe(false);
    });
  });

  describe('isMacOSContainerAvailable', () => {
    beforeEach(() => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      // Default: sw_vers returns macOS 15
      mockedExecFile.mockImplementation((_cmd, _args, callback) => {
        (
          callback as (
            err: Error | null,
            result: { stdout: string; stderr: string },
          ) => void
        )(null, { stdout: '15.0\n', stderr: '' });
        return {} as ReturnType<typeof execFile>;
      });
      mockedCommandExistsSync.mockReturnValue(true);
    });

    it('should return false on non-macOS', async () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      expect(await isMacOSContainerAvailable()).toBe(false);
    });

    it('should return true on macOS 15 with container CLI', async () => {
      expect(await isMacOSContainerAvailable()).toBe(true);
    });

    it('should return false on macOS 14', async () => {
      mockedExecFile.mockImplementation((_cmd, _args, callback) => {
        (
          callback as (
            err: Error | null,
            result: { stdout: string; stderr: string },
          ) => void
        )(null, { stdout: '14.5\n', stderr: '' });
        return {} as ReturnType<typeof execFile>;
      });
      expect(await isMacOSContainerAvailable()).toBe(false);
    });

    it('should return false when container CLI is not found', async () => {
      mockedCommandExistsSync.mockReturnValue(false);
      expect(await isMacOSContainerAvailable()).toBe(false);
    });

    it('should return false when sw_vers fails', async () => {
      mockedExecFile.mockImplementation((_cmd, _args, callback) => {
        (callback as (err: Error | null, result: null, stderr: null) => void)(
          new Error('command not found'),
          null,
          null,
        );
        return {} as ReturnType<typeof execFile>;
      });
      expect(await isMacOSContainerAvailable()).toBe(false);
    });
  });

  describe('isBwrapAvailable', () => {
    beforeEach(() => {
      vi.mocked(os.platform).mockReturnValue('linux');
      mockedCommandExistsSync.mockReturnValue(true);
      // Default: user namespaces enabled (file does not exist / resolves to non-zero)
      mockedReadFile.mockRejectedValue(new Error('ENOENT'));
    });

    it('should return false on non-Linux', async () => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      expect(await isBwrapAvailable()).toBe(false);
    });

    it('should return true when bwrap exists and user namespaces are enabled', async () => {
      expect(await isBwrapAvailable()).toBe(true);
    });

    it('should return false when bwrap binary is not found', async () => {
      mockedCommandExistsSync.mockReturnValue(false);
      expect(await isBwrapAvailable()).toBe(false);
    });

    it('should return false when unprivileged_userns_clone is 0', async () => {
      mockedReadFile.mockResolvedValue('0\n');
      expect(await isBwrapAvailable()).toBe(false);
    });

    it('should return true when unprivileged_userns_clone is 1', async () => {
      mockedReadFile.mockResolvedValue('1\n');
      expect(await isBwrapAvailable()).toBe(true);
    });

    it('should return true when /proc/sys/kernel/unprivileged_userns_clone does not exist', async () => {
      mockedReadFile.mockRejectedValue({ code: 'ENOENT' });
      expect(await isBwrapAvailable()).toBe(true);
    });
  });

  describe('isWSL', () => {
    it('should return false on non-Linux', () => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      expect(isWSL()).toBe(false);
    });

    it('should return true when WSL_DISTRO_NAME is set', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      process.env['WSL_DISTRO_NAME'] = 'Ubuntu';
      vi.mocked(fs.existsSync).mockReturnValue(false);
      expect(isWSL()).toBe(true);
    });

    it('should return true when WSLInterop exists', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(fs.existsSync).mockImplementation(
        (p) => p === '/proc/sys/fs/binfmt_misc/WSLInterop',
      );
      expect(isWSL()).toBe(true);
    });

    it('should return false on plain Linux', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(fs.existsSync).mockReturnValue(false);
      delete process.env['WSL_DISTRO_NAME'];
      expect(isWSL()).toBe(false);
    });
  });

  describe('isWSL2', () => {
    it('should return false when not in WSL', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(fs.existsSync).mockReturnValue(false);
      delete process.env['WSL_DISTRO_NAME'];
      expect(isWSL2()).toBe(false);
    });

    it('should return true for WSL2 kernel string', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      process.env['WSL_DISTRO_NAME'] = 'Ubuntu';
      vi.mocked(os.release).mockReturnValue(
        '5.15.153.1-microsoft-standard-WSL2',
      );
      vi.mocked(fs.existsSync).mockReturnValue(false);
      expect(isWSL2()).toBe(true);
    });

    it('should return true for WSL2 based on kernel version >= 5', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      process.env['WSL_DISTRO_NAME'] = 'Ubuntu';
      vi.mocked(os.release).mockReturnValue('6.1.0-microsoft-standard');
      vi.mocked(fs.existsSync).mockReturnValue(false);
      expect(isWSL2()).toBe(true);
    });

    it('should return false for WSL1 (kernel 4.4.x)', () => {
      vi.mocked(os.platform).mockReturnValue('linux');
      process.env['WSL_DISTRO_NAME'] = 'Ubuntu';
      vi.mocked(os.release).mockReturnValue('4.4.0-19041-Microsoft');
      vi.mocked(fs.existsSync).mockReturnValue(false);
      expect(isWSL2()).toBe(false);
    });
  });

  describe('isLandlockAvailable', () => {
    beforeEach(() => {
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(os.release).mockReturnValue('6.1.0-21-amd64');
      mockedReadFile.mockResolvedValue(
        'lockdown,capability,landlock,yama,apparmor\n',
      );
      mockedCommandExistsSync.mockReturnValue(true);
      mockedCheckLandlock.mockReturnValue({
        available: true,
        abiVersion: 3,
        error: undefined,
      });
    });

    it('should return false on non-Linux', async () => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      expect(await isLandlockAvailable()).toBe(false);
    });

    it('should return true on Linux 6.1 with Landlock LSM and helper binary', async () => {
      expect(await isLandlockAvailable()).toBe(true);
    });

    it('should return true on Linux 5.13 (minimum supported)', async () => {
      vi.mocked(os.release).mockReturnValue('5.13.0-1-generic');
      expect(await isLandlockAvailable()).toBe(true);
    });

    it('should return false on Linux 5.12 (too old)', async () => {
      vi.mocked(os.release).mockReturnValue('5.12.0-1-generic');
      mockedCheckLandlock.mockReturnValue({
        available: false,
        abiVersion: 0,
        error: 'Landlock not supported',
      });
      expect(await isLandlockAvailable()).toBe(false);
    });

    it('should return false on Linux 4.x', async () => {
      vi.mocked(os.release).mockReturnValue('4.19.0-1-amd64');
      mockedCheckLandlock.mockReturnValue({
        available: false,
        abiVersion: 0,
        error: 'Landlock not supported',
      });
      expect(await isLandlockAvailable()).toBe(false);
    });

    it('should return false when landlock is not in LSM list', async () => {
      mockedReadFile.mockResolvedValue('lockdown,capability,yama,apparmor\n');
      mockedCheckLandlock.mockReturnValue({
        available: false,
        abiVersion: 0,
        error: 'Landlock not supported',
      });
      expect(await isLandlockAvailable()).toBe(false);
    });

    it('should return false when /sys/kernel/security/lsm is not readable', async () => {
      mockedReadFile.mockRejectedValue(new Error('ENOENT'));
      mockedCheckLandlock.mockReturnValue({
        available: false,
        abiVersion: 0,
        error: 'Landlock not supported',
      });
      expect(await isLandlockAvailable()).toBe(false);
    });

    it('should return false when landlock native module is not available', async () => {
      mockedCheckLandlock.mockReturnValue({
        available: false,
        abiVersion: 0,
        error: 'Landlock not supported',
      });
      expect(await isLandlockAvailable()).toBe(false);
    });
  });
});
