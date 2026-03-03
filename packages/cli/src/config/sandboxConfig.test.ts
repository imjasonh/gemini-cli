/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { getPackageJson } from '@google/gemini-cli-core';
import commandExists from 'command-exists';
import * as os from 'node:os';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { loadSandboxConfig } from './sandboxConfig.js';

// Mock dependencies
vi.mock('@google/gemini-cli-core', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...(actual as object),
    getPackageJson: vi.fn(),
    FatalSandboxError: class extends Error {
      constructor(message: string) {
        super(message);
        this.name = 'FatalSandboxError';
      }
    },
  };
});

vi.mock('command-exists', () => {
  const sync = vi.fn();
  return {
    sync,
    default: {
      sync,
    },
  };
});

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...(actual as object),
    platform: vi.fn(),
    release: vi.fn().mockReturnValue('6.1.0-21-amd64'),
  };
});

vi.mock('../utils/sandboxUtils.js', () => ({
  detectContainerEnvironment: vi.fn().mockReturnValue({
    detected: false,
    type: 'none',
    isGeminiSandbox: false,
  }),
  isBwrapAvailable: vi.fn().mockResolvedValue(false),
  isLandlockAvailable: vi.fn().mockResolvedValue(false),
  isMacOSContainerAvailable: vi.fn().mockResolvedValue(false),
}));

import {
  detectContainerEnvironment,
  isBwrapAvailable,
  isLandlockAvailable,
  isMacOSContainerAvailable,
} from '../utils/sandboxUtils.js';

const mockedGetPackageJson = vi.mocked(getPackageJson);
const mockedCommandExistsSync = vi.mocked(commandExists.sync);
const mockedOsPlatform = vi.mocked(os.platform);
const mockedDetectContainerEnvironment = vi.mocked(detectContainerEnvironment);
const mockedIsBwrapAvailable = vi.mocked(isBwrapAvailable);
const mockedIsLandlockAvailable = vi.mocked(isLandlockAvailable);
const mockedIsMacOSContainerAvailable = vi.mocked(isMacOSContainerAvailable);

describe('loadSandboxConfig', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    vi.resetAllMocks();
    process.env = { ...originalEnv };
    delete process.env['SANDBOX'];
    delete process.env['GEMINI_SANDBOX'];
    mockedGetPackageJson.mockResolvedValue({
      config: { sandboxImageUri: 'default/image' },
    });
    mockedDetectContainerEnvironment.mockReturnValue({
      detected: false,
      type: 'none',
      isGeminiSandbox: false,
    });
    mockedIsBwrapAvailable.mockResolvedValue(false);
    mockedIsLandlockAvailable.mockResolvedValue(false);
    mockedIsMacOSContainerAvailable.mockResolvedValue(false);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('should return undefined if sandbox is explicitly disabled via argv', async () => {
    const config = await loadSandboxConfig({}, { sandbox: false });
    expect(config).toBeUndefined();
  });

  it('should return undefined if sandbox is explicitly disabled via settings', async () => {
    const config = await loadSandboxConfig({ tools: { sandbox: false } }, {});
    expect(config).toBeUndefined();
  });

  it('should return undefined if sandbox is not configured', async () => {
    const config = await loadSandboxConfig({}, {});
    expect(config).toBeUndefined();
  });

  it('should return undefined if already inside a sandbox (SANDBOX env var is set)', async () => {
    mockedDetectContainerEnvironment.mockReturnValue({
      detected: true,
      type: 'unknown',
      isGeminiSandbox: true,
    });
    const config = await loadSandboxConfig({}, { sandbox: true });
    expect(config).toBeUndefined();
  });

  describe('with GEMINI_SANDBOX environment variable', () => {
    it('should use docker if GEMINI_SANDBOX=docker and it exists', async () => {
      process.env['GEMINI_SANDBOX'] = 'docker';
      mockedCommandExistsSync.mockReturnValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({ command: 'docker', image: 'default/image' });
      expect(mockedCommandExistsSync).toHaveBeenCalledWith('docker');
    });

    it('should throw if GEMINI_SANDBOX is an invalid command', async () => {
      process.env['GEMINI_SANDBOX'] = 'invalid-command';
      await expect(loadSandboxConfig({}, {})).rejects.toThrow(
        "Invalid sandbox command 'invalid-command'. Must be one of docker, podman, sandbox-exec, bwrap, macos-container, landlock",
      );
    });

    it('should throw if GEMINI_SANDBOX command does not exist', async () => {
      process.env['GEMINI_SANDBOX'] = 'docker';
      mockedCommandExistsSync.mockReturnValue(false);
      await expect(loadSandboxConfig({}, {})).rejects.toThrow(
        "Missing sandbox command 'docker' (from GEMINI_SANDBOX)",
      );
    });

    it('should use bwrap if GEMINI_SANDBOX=bwrap and it is available', async () => {
      process.env['GEMINI_SANDBOX'] = 'bwrap';
      mockedIsBwrapAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({ command: 'bwrap', image: 'default/image' });
    });

    it('should throw if GEMINI_SANDBOX=bwrap but bwrap is not available', async () => {
      process.env['GEMINI_SANDBOX'] = 'bwrap';
      mockedIsBwrapAvailable.mockResolvedValue(false);
      await expect(loadSandboxConfig({}, {})).rejects.toThrow(
        `Sandbox command 'bwrap' is not available: install bubblewrap and ensure user namespaces are enabled`,
      );
    });

    it('should use landlock if GEMINI_SANDBOX=landlock and it is available', async () => {
      process.env['GEMINI_SANDBOX'] = 'landlock';
      mockedIsLandlockAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({ command: 'landlock', image: 'default/image' });
    });

    it('should throw if GEMINI_SANDBOX=landlock but landlock is not available', async () => {
      process.env['GEMINI_SANDBOX'] = 'landlock';
      mockedIsLandlockAvailable.mockResolvedValue(false);
      await expect(loadSandboxConfig({}, {})).rejects.toThrow(
        `Sandbox command 'landlock' is not available: requires Linux kernel 5.13+ with Landlock support`,
      );
    });

    it('should use macos-container if GEMINI_SANDBOX=macos-container and it is available', async () => {
      process.env['GEMINI_SANDBOX'] = 'macos-container';
      mockedIsMacOSContainerAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({
        command: 'macos-container',
        image: 'default/image',
      });
    });

    it('should throw if GEMINI_SANDBOX=macos-container but it is not available', async () => {
      process.env['GEMINI_SANDBOX'] = 'macos-container';
      mockedIsMacOSContainerAvailable.mockResolvedValue(false);
      await expect(loadSandboxConfig({}, {})).rejects.toThrow(
        `Sandbox command 'macos-container' is not available: requires macOS 26+ and the 'container' CLI`,
      );
    });
  });

  describe('with sandbox: true', () => {
    it('should use sandbox-exec on darwin if available', async () => {
      mockedOsPlatform.mockReturnValue('darwin');
      mockedCommandExistsSync.mockImplementation(
        (cmd) => cmd === 'sandbox-exec',
      );
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toEqual({
        command: 'sandbox-exec',
        image: 'default/image',
      });
    });

    it('should prefer sandbox-exec over docker on darwin', async () => {
      mockedOsPlatform.mockReturnValue('darwin');
      mockedCommandExistsSync.mockReturnValue(true); // all commands exist
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toEqual({
        command: 'sandbox-exec',
        image: 'default/image',
      });
    });

    it('should prefer landlock over bwrap and docker on linux', async () => {
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(true);
      mockedIsBwrapAvailable.mockResolvedValue(true);
      mockedCommandExistsSync.mockImplementation((cmd) => cmd === 'docker');
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toEqual({ command: 'landlock', image: 'default/image' });
    });

    it('should prefer bwrap over docker on linux when landlock is unavailable', async () => {
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(false);
      mockedIsBwrapAvailable.mockResolvedValue(true);
      mockedCommandExistsSync.mockImplementation((cmd) => cmd === 'docker');
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toEqual({ command: 'bwrap', image: 'default/image' });
    });

    it('should use docker if available and sandbox is true (landlock and bwrap unavailable)', async () => {
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(false);
      mockedIsBwrapAvailable.mockResolvedValue(false);
      mockedCommandExistsSync.mockImplementation((cmd) => cmd === 'docker');
      const config = await loadSandboxConfig({ tools: { sandbox: true } }, {});
      expect(config).toEqual({ command: 'docker', image: 'default/image' });
    });

    it('should use podman if available and docker is not (landlock and bwrap unavailable)', async () => {
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(false);
      mockedIsBwrapAvailable.mockResolvedValue(false);
      mockedCommandExistsSync.mockImplementation((cmd) => cmd === 'podman');
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toEqual({ command: 'podman', image: 'default/image' });
    });

    it('should throw if sandbox: true but no command is found', async () => {
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(false);
      mockedIsBwrapAvailable.mockResolvedValue(false);
      mockedCommandExistsSync.mockReturnValue(false);
      await expect(loadSandboxConfig({}, { sandbox: true })).rejects.toThrow(
        'GEMINI_SANDBOX is true but failed to determine command for sandbox; ' +
          'install bubblewrap (bwrap), docker, or podman, or specify a command in GEMINI_SANDBOX',
      );
    });
  });

  describe("with sandbox: 'command'", () => {
    it('should use the specified command if it exists', async () => {
      mockedCommandExistsSync.mockReturnValue(true);
      const config = await loadSandboxConfig({}, { sandbox: 'podman' });
      expect(config).toEqual({ command: 'podman', image: 'default/image' });
      expect(mockedCommandExistsSync).toHaveBeenCalledWith('podman');
    });

    it('should throw if the specified command does not exist', async () => {
      mockedCommandExistsSync.mockReturnValue(false);
      await expect(
        loadSandboxConfig({}, { sandbox: 'podman' }),
      ).rejects.toThrow(
        "Missing sandbox command 'podman' (from GEMINI_SANDBOX)",
      );
    });

    it('should throw if the specified command is invalid', async () => {
      await expect(
        loadSandboxConfig({}, { sandbox: 'invalid-command' }),
      ).rejects.toThrow(
        "Invalid sandbox command 'invalid-command'. Must be one of docker, podman, sandbox-exec, bwrap, macos-container, landlock",
      );
    });

    it('should use bwrap when specified and available', async () => {
      mockedIsBwrapAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, { sandbox: 'bwrap' });
      expect(config).toEqual({ command: 'bwrap', image: 'default/image' });
    });

    it('should use landlock when specified and available', async () => {
      mockedIsLandlockAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, { sandbox: 'landlock' });
      expect(config).toEqual({ command: 'landlock', image: 'default/image' });
    });

    it('should use macos-container when specified and available', async () => {
      mockedIsMacOSContainerAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig(
        {},
        { sandbox: 'macos-container' },
      );
      expect(config).toEqual({
        command: 'macos-container',
        image: 'default/image',
      });
    });
  });

  describe('image configuration', () => {
    it('should use image from GEMINI_SANDBOX_IMAGE env var if set', async () => {
      process.env['GEMINI_SANDBOX_IMAGE'] = 'env/image';
      process.env['GEMINI_SANDBOX'] = 'docker';
      mockedCommandExistsSync.mockReturnValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({ command: 'docker', image: 'env/image' });
    });

    it('should use image from package.json if env var is not set', async () => {
      process.env['GEMINI_SANDBOX'] = 'docker';
      mockedCommandExistsSync.mockReturnValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({ command: 'docker', image: 'default/image' });
    });

    it('should return undefined if command is found but no image is configured', async () => {
      mockedGetPackageJson.mockResolvedValue({}); // no sandboxImageUri
      process.env['GEMINI_SANDBOX'] = 'docker';
      mockedCommandExistsSync.mockReturnValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toBeUndefined();
    });
  });

  describe('nested container detection', () => {
    it('should return undefined when inside Gemini sandbox (isGeminiSandbox)', async () => {
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: true,
        type: 'unknown',
        isGeminiSandbox: true,
      });
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toBeUndefined();
    });

    it('should skip sandboxing when inside Docker with sandbox: true', async () => {
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: true,
        type: 'docker',
        isGeminiSandbox: false,
      });
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toBeUndefined();
    });

    it('should allow explicit sandbox command inside Docker', async () => {
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: true,
        type: 'docker',
        isGeminiSandbox: false,
      });
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsBwrapAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, { sandbox: 'bwrap' });
      expect(config).toEqual({ command: 'bwrap', image: 'default/image' });
    });

    it('should force sandbox inside container with GEMINI_SANDBOX=force', async () => {
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: true,
        type: 'docker',
        isGeminiSandbox: false,
      });
      process.env['GEMINI_SANDBOX'] = 'force';
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, {});
      expect(config).toEqual({ command: 'landlock', image: 'default/image' });
    });

    it('should skip sandboxing inside Kubernetes with sandbox: true', async () => {
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: true,
        type: 'kubernetes',
        isGeminiSandbox: false,
      });
      const config = await loadSandboxConfig({ tools: { sandbox: true } }, {});
      expect(config).toBeUndefined();
    });

    it('should skip sandboxing inside WSL1 with sandbox: true', async () => {
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: true,
        type: 'wsl1',
        isGeminiSandbox: false,
      });
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toBeUndefined();
    });

    it('should allow sandboxing in WSL2 (not detected as container)', async () => {
      // WSL2 is not reported as a container environment
      mockedDetectContainerEnvironment.mockReturnValue({
        detected: false,
        type: 'none',
        isGeminiSandbox: false,
      });
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(true);
      const config = await loadSandboxConfig({}, { sandbox: true });
      expect(config).toEqual({ command: 'landlock', image: 'default/image' });
    });
  });

  describe('truthy/falsy sandbox values', () => {
    beforeEach(() => {
      mockedOsPlatform.mockReturnValue('linux');
      mockedIsLandlockAvailable.mockResolvedValue(false);
      mockedIsBwrapAvailable.mockResolvedValue(false);
      mockedCommandExistsSync.mockImplementation((cmd) => cmd === 'docker');
    });

    it.each([true, 'true', '1'])(
      'should enable sandbox for value: %s',
      async (value) => {
        const config = await loadSandboxConfig({}, { sandbox: value });
        expect(config).toEqual({ command: 'docker', image: 'default/image' });
      },
    );

    it.each([false, 'false', '0', undefined, null, ''])(
      'should disable sandbox for value: %s',
      async (value) => {
        // `null` is not a valid type for the arg, but good to test falsiness
        const config = await loadSandboxConfig({}, { sandbox: value });
        expect(config).toBeUndefined();
      },
    );
  });
});
