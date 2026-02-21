/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn, exec, execSync } from 'node:child_process';
import os from 'node:os';
import fs from 'node:fs';
import { start_sandbox } from './sandbox.js';
import { FatalSandboxError, type SandboxConfig } from '@google/gemini-cli-core';
import { EventEmitter } from 'node:events';

const {
  mockedHomedir,
  mockedGetContainerPath,
  mockedGetLandlockHelperPath,
  mockedPrepareSeccompFd,
  mockedCleanupSeccomp,
  mockedPrepareSeccompFile,
  mockedCleanupSeccompFile,
} = vi.hoisted(() => ({
  mockedHomedir: vi.fn().mockReturnValue('/home/user'),
  mockedGetContainerPath: vi.fn().mockImplementation((p: string) => p),
  mockedGetLandlockHelperPath: vi.fn().mockReturnValue('landlock-helper'),
  mockedPrepareSeccompFd: vi
    .fn()
    .mockReturnValue({ fd: 99, path: '/tmp/bwrap-seccomp-test.bpf' }),
  mockedCleanupSeccomp: vi.fn(),
  mockedPrepareSeccompFile: vi
    .fn()
    .mockReturnValue({ path: '/tmp/seccomp-test.bpf' }),
  mockedCleanupSeccompFile: vi.fn(),
}));

vi.mock('./sandboxUtils.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./sandboxUtils.js')>();
  return {
    ...actual,
    getContainerPath: mockedGetContainerPath,
    getLandlockHelperPath: mockedGetLandlockHelperPath,
  };
});

vi.mock('./bwrap-seccomp.js', () => ({
  prepareSeccompFd: mockedPrepareSeccompFd,
  cleanupSeccomp: mockedCleanupSeccomp,
  prepareSeccompFile: mockedPrepareSeccompFile,
  cleanupSeccompFile: mockedCleanupSeccompFile,
}));

vi.mock('node:child_process');
vi.mock('node:os');
vi.mock('node:fs');
// Default image inspect response; tests can override via mockImageInspectResponse
let mockImageInspectResponse = JSON.stringify({
  Architecture: 'amd64',
});

vi.mock('node:util', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:util')>();
  return {
    ...actual,
    promisify: (fn: (...args: unknown[]) => unknown) => {
      if (fn === exec) {
        return async (cmd: string) => {
          if (cmd === 'id -u' || cmd === 'id -g') {
            return { stdout: '1000', stderr: '' };
          }
          if (cmd.includes('curl')) {
            return { stdout: '', stderr: '' };
          }
          if (cmd.includes('getconf DARWIN_USER_CACHE_DIR')) {
            return { stdout: '/tmp/cache', stderr: '' };
          }
          if (cmd.includes('ps -a --format')) {
            return { stdout: 'existing-container', stderr: '' };
          }
          if (cmd.includes('container image inspect')) {
            return { stdout: mockImageInspectResponse, stderr: '' };
          }
          return { stdout: '', stderr: '' };
        };
      }
      return actual.promisify(fn);
    },
  };
});

vi.mock('@google/gemini-cli-core', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('@google/gemini-cli-core')>();
  return {
    ...actual,
    debugLogger: {
      log: vi.fn(),
      debug: vi.fn(),
      warn: vi.fn(),
    },
    coreEvents: {
      emitFeedback: vi.fn(),
    },
    FatalSandboxError: class extends Error {
      constructor(message: string) {
        super(message);
        this.name = 'FatalSandboxError';
      }
    },
    GEMINI_DIR: '.gemini',
    homedir: mockedHomedir,
  };
});

describe('sandbox', () => {
  const originalEnv = process.env;
  const originalArgv = process.argv;
  let mockProcessIn: {
    pause: ReturnType<typeof vi.fn>;
    resume: ReturnType<typeof vi.fn>;
    isTTY: boolean;
  };

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
    process.argv = [...originalArgv];
    mockImageInspectResponse = JSON.stringify({ Architecture: 'amd64' });
    mockProcessIn = {
      pause: vi.fn(),
      resume: vi.fn(),
      isTTY: true,
    };
    Object.defineProperty(process, 'stdin', {
      value: mockProcessIn,
      writable: true,
    });
    vi.mocked(os.platform).mockReturnValue('linux');
    vi.mocked(os.homedir).mockReturnValue('/home/user');
    vi.mocked(os.tmpdir).mockReturnValue('/tmp');
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.realpathSync).mockImplementation((p) => p as string);
    vi.mocked(execSync).mockReturnValue(Buffer.from(''));
  });

  afterEach(() => {
    process.env = originalEnv;
    process.argv = originalArgv;
  });

  describe('start_sandbox', () => {
    it('should handle macOS seatbelt (sandbox-exec)', async () => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      const config: SandboxConfig = {
        command: 'sandbox-exec',
        image: 'some-image',
      };

      interface MockProcess extends EventEmitter {
        stdout: EventEmitter;
        stderr: EventEmitter;
      }
      const mockSpawnProcess = new EventEmitter() as MockProcess;
      mockSpawnProcess.stdout = new EventEmitter();
      mockSpawnProcess.stderr = new EventEmitter();
      vi.mocked(spawn).mockReturnValue(
        mockSpawnProcess as unknown as ReturnType<typeof spawn>,
      );

      const promise = start_sandbox(config, [], undefined, ['arg1']);

      setTimeout(() => {
        mockSpawnProcess.emit('close', 0);
      }, 10);

      await expect(promise).resolves.toBe(0);
      expect(spawn).toHaveBeenCalledWith(
        'sandbox-exec',
        expect.arrayContaining([
          '-f',
          expect.stringContaining('sandbox-macos-permissive-open.sb'),
        ]),
        expect.objectContaining({ stdio: 'inherit' }),
      );
    });

    it('should throw FatalSandboxError if seatbelt profile is missing', async () => {
      vi.mocked(os.platform).mockReturnValue('darwin');
      vi.mocked(fs.existsSync).mockReturnValue(false);
      const config: SandboxConfig = {
        command: 'sandbox-exec',
        image: 'some-image',
      };

      await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
    });

    it('should handle Docker execution', async () => {
      const config: SandboxConfig = {
        command: 'docker',
        image: 'gemini-cli-sandbox',
      };

      // Mock image check to return true (image exists)
      interface MockProcessWithStdout extends EventEmitter {
        stdout: EventEmitter;
      }
      const mockImageCheckProcess = new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce((_cmd, args) => {
        if (args && args[0] === 'images') {
          setTimeout(() => {
            mockImageCheckProcess.stdout.emit('data', Buffer.from('image-id'));
            mockImageCheckProcess.emit('close', 0);
          }, 1);
          return mockImageCheckProcess as unknown as ReturnType<typeof spawn>;
        }
        return new EventEmitter() as unknown as ReturnType<typeof spawn>; // fallback
      });

      const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
        typeof spawn
      >;
      mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
        if (event === 'close') {
          setTimeout(() => cb(0), 10);
        }
        return mockSpawnProcess;
      });
      vi.mocked(spawn).mockImplementationOnce((cmd, args) => {
        if (cmd === 'docker' && args && args[0] === 'run') {
          return mockSpawnProcess;
        }
        return new EventEmitter() as unknown as ReturnType<typeof spawn>;
      });

      const promise = start_sandbox(config, [], undefined, ['arg1']);

      await expect(promise).resolves.toBe(0);
      expect(spawn).toHaveBeenCalledWith(
        'docker',
        expect.arrayContaining(['run', '-i', '--rm', '--init']),
        expect.objectContaining({ stdio: 'inherit' }),
      );
    });

    it('should pull image if missing', async () => {
      const config: SandboxConfig = {
        command: 'docker',
        image: 'missing-image',
      };

      // 1. Image check fails
      interface MockProcessWithStdout extends EventEmitter {
        stdout: EventEmitter;
      }
      const mockImageCheckProcess1 =
        new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess1.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockImageCheckProcess1.emit('close', 0);
        }, 1);
        return mockImageCheckProcess1 as unknown as ReturnType<typeof spawn>;
      });

      // 2. Pull image succeeds
      interface MockProcessWithStdoutStderr extends EventEmitter {
        stdout: EventEmitter;
        stderr: EventEmitter;
      }
      const mockPullProcess = new EventEmitter() as MockProcessWithStdoutStderr;
      mockPullProcess.stdout = new EventEmitter();
      mockPullProcess.stderr = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockPullProcess.emit('close', 0);
        }, 1);
        return mockPullProcess as unknown as ReturnType<typeof spawn>;
      });

      // 3. Image check succeeds
      const mockImageCheckProcess2 =
        new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess2.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockImageCheckProcess2.stdout.emit('data', Buffer.from('image-id'));
          mockImageCheckProcess2.emit('close', 0);
        }, 1);
        return mockImageCheckProcess2 as unknown as ReturnType<typeof spawn>;
      });

      // 4. Docker run
      const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
        typeof spawn
      >;
      mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
        if (event === 'close') {
          setTimeout(() => cb(0), 10);
        }
        return mockSpawnProcess;
      });
      vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

      const promise = start_sandbox(config, [], undefined, ['arg1']);

      await expect(promise).resolves.toBe(0);
      expect(spawn).toHaveBeenCalledWith(
        'docker',
        expect.arrayContaining(['pull', 'missing-image']),
        expect.any(Object),
      );
    });

    it('should throw if image pull fails', async () => {
      const config: SandboxConfig = {
        command: 'docker',
        image: 'missing-image',
      };

      // 1. Image check fails
      interface MockProcessWithStdout extends EventEmitter {
        stdout: EventEmitter;
      }
      const mockImageCheckProcess1 =
        new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess1.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockImageCheckProcess1.emit('close', 0);
        }, 1);
        return mockImageCheckProcess1 as unknown as ReturnType<typeof spawn>;
      });

      // 2. Pull image fails
      interface MockProcessWithStdoutStderr extends EventEmitter {
        stdout: EventEmitter;
        stderr: EventEmitter;
      }
      const mockPullProcess = new EventEmitter() as MockProcessWithStdoutStderr;
      mockPullProcess.stdout = new EventEmitter();
      mockPullProcess.stderr = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockPullProcess.emit('close', 1);
        }, 1);
        return mockPullProcess as unknown as ReturnType<typeof spawn>;
      });

      await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
    });

    it('should mount volumes correctly', async () => {
      const config: SandboxConfig = {
        command: 'docker',
        image: 'gemini-cli-sandbox',
      };
      process.env['SANDBOX_MOUNTS'] = '/host/path:/container/path:ro';
      vi.mocked(fs.existsSync).mockReturnValue(true); // For mount path check

      // Mock image check to return true
      interface MockProcessWithStdout extends EventEmitter {
        stdout: EventEmitter;
      }
      const mockImageCheckProcess = new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockImageCheckProcess.stdout.emit('data', Buffer.from('image-id'));
          mockImageCheckProcess.emit('close', 0);
        }, 1);
        return mockImageCheckProcess as unknown as ReturnType<typeof spawn>;
      });

      const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
        typeof spawn
      >;
      mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
        if (event === 'close') {
          setTimeout(() => cb(0), 10);
        }
        return mockSpawnProcess;
      });
      vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

      await start_sandbox(config);

      // The first call is 'docker images -q ...'
      expect(spawn).toHaveBeenNthCalledWith(
        1,
        'docker',
        expect.arrayContaining(['images', '-q']),
      );

      // The second call is 'docker run ...'
      expect(spawn).toHaveBeenNthCalledWith(
        2,
        'docker',
        expect.arrayContaining([
          'run',
          '--volume',
          '/host/path:/container/path:ro',
          '--volume',
          expect.stringMatching(/[\\/]home[\\/]user[\\/]\.gemini/),
        ]),
        expect.any(Object),
      );
    });

    it('should pass through GOOGLE_GEMINI_BASE_URL and GOOGLE_VERTEX_BASE_URL', async () => {
      const config: SandboxConfig = {
        command: 'docker',
        image: 'gemini-cli-sandbox',
      };
      process.env['GOOGLE_GEMINI_BASE_URL'] = 'http://gemini.proxy';
      process.env['GOOGLE_VERTEX_BASE_URL'] = 'http://vertex.proxy';

      // Mock image check to return true
      interface MockProcessWithStdout extends EventEmitter {
        stdout: EventEmitter;
      }
      const mockImageCheckProcess = new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockImageCheckProcess.stdout.emit('data', Buffer.from('image-id'));
          mockImageCheckProcess.emit('close', 0);
        }, 1);
        return mockImageCheckProcess as unknown as ReturnType<typeof spawn>;
      });

      const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
        typeof spawn
      >;
      mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
        if (event === 'close') {
          setTimeout(() => cb(0), 10);
        }
        return mockSpawnProcess;
      });
      vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

      await start_sandbox(config);

      expect(spawn).toHaveBeenCalledWith(
        'docker',
        expect.arrayContaining([
          '--env',
          'GOOGLE_GEMINI_BASE_URL=http://gemini.proxy',
          '--env',
          'GOOGLE_VERTEX_BASE_URL=http://vertex.proxy',
        ]),
        expect.any(Object),
      );
    });

    it('should handle user creation on Linux if needed', async () => {
      const config: SandboxConfig = {
        command: 'docker',
        image: 'gemini-cli-sandbox',
      };
      process.env['SANDBOX_SET_UID_GID'] = 'true';
      vi.mocked(os.platform).mockReturnValue('linux');
      vi.mocked(execSync).mockImplementation((cmd) => {
        if (cmd === 'id -u') return Buffer.from('1000');
        if (cmd === 'id -g') return Buffer.from('1000');
        return Buffer.from('');
      });

      // Mock image check to return true
      interface MockProcessWithStdout extends EventEmitter {
        stdout: EventEmitter;
      }
      const mockImageCheckProcess = new EventEmitter() as MockProcessWithStdout;
      mockImageCheckProcess.stdout = new EventEmitter();
      vi.mocked(spawn).mockImplementationOnce(() => {
        setTimeout(() => {
          mockImageCheckProcess.stdout.emit('data', Buffer.from('image-id'));
          mockImageCheckProcess.emit('close', 0);
        }, 1);
        return mockImageCheckProcess as unknown as ReturnType<typeof spawn>;
      });

      const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
        typeof spawn
      >;
      mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
        if (event === 'close') {
          setTimeout(() => cb(0), 10);
        }
        return mockSpawnProcess;
      });
      vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

      await start_sandbox(config);

      expect(spawn).toHaveBeenCalledWith(
        'docker',
        expect.arrayContaining(['--user', 'root', '--env', 'HOME=/home/user']),
        expect.any(Object),
      );
      // Check that the entrypoint command includes useradd/groupadd
      const args = vi.mocked(spawn).mock.calls[1][1] as string[];
      const entrypointCmd = args[args.length - 1];
      expect(entrypointCmd).toContain('groupadd');
      expect(entrypointCmd).toContain('useradd');
      expect(entrypointCmd).toContain('su -p gemini');
    });

    describe('macOS Container sandbox', () => {
      it('should route macos-container to the container CLI with amd64-only image', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        mockImageInspectResponse = JSON.stringify({
          Architecture: 'amd64',
        });
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'some-image',
        };

        // 1. container system info (via execAsync)
        // Already mocked by the promisify mock returning { stdout: '', stderr: '' }

        // 2. container image list -q (image exists check)
        interface MockProcessWithStdout extends EventEmitter {
          stdout: EventEmitter;
        }
        const mockImageListProcess =
          new EventEmitter() as MockProcessWithStdout;
        mockImageListProcess.stdout = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockImageListProcess.stdout.emit(
              'data',
              Buffer.from('some-image\n'),
            );
            mockImageListProcess.emit('close', 0);
          }, 1);
          return mockImageListProcess as unknown as ReturnType<typeof spawn>;
        });

        // 3. container run
        const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
          typeof spawn
        >;
        mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
          if (event === 'close') {
            setTimeout(() => cb(0), 10);
          }
          return mockSpawnProcess;
        });
        vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

        const promise = start_sandbox(config, [], undefined, ['arg1']);
        await expect(promise).resolves.toBe(0);

        // amd64-only image should use --rosetta --arch amd64
        expect(spawn).toHaveBeenCalledWith(
          'container',
          expect.arrayContaining([
            'run',
            '-i',
            '--rm',
            '--rosetta',
            '--arch',
            'amd64',
          ]),
          expect.objectContaining({ stdio: 'inherit' }),
        );
      });

      it('should run natively with arm64 image (no --rosetta)', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        mockImageInspectResponse = JSON.stringify({
          Manifests: [
            { Platform: { Architecture: 'amd64' } },
            { Platform: { Architecture: 'arm64' } },
          ],
        });
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'some-image',
        };

        interface MockProcessWithStdout extends EventEmitter {
          stdout: EventEmitter;
        }
        const mockImageListProcess =
          new EventEmitter() as MockProcessWithStdout;
        mockImageListProcess.stdout = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockImageListProcess.stdout.emit(
              'data',
              Buffer.from('some-image\n'),
            );
            mockImageListProcess.emit('close', 0);
          }, 1);
          return mockImageListProcess as unknown as ReturnType<typeof spawn>;
        });

        const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
          typeof spawn
        >;
        mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
          if (event === 'close') {
            setTimeout(() => cb(0), 10);
          }
          return mockSpawnProcess;
        });
        vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

        const promise = start_sandbox(config, [], undefined, ['arg1']);
        await expect(promise).resolves.toBe(0);

        // arm64-capable image should NOT have --rosetta
        const runCall = vi
          .mocked(spawn)
          .mock.calls.find(
            (call) =>
              call[0] === 'container' && (call[1] as string[])?.[0] === 'run',
          );
        expect(runCall).toBeDefined();
        const runArgs = runCall![1] as string[];
        expect(runArgs).not.toContain('--rosetta');
      });

      it('should throw FatalSandboxError if BUILD_SANDBOX is set', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        process.env['BUILD_SANDBOX'] = '1';
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'some-image',
        };

        await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
      });

      it('should throw FatalSandboxError if image cannot be obtained', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'missing-image',
        };

        // 1. container image list -q (image not found)
        interface MockProcessWithStdout extends EventEmitter {
          stdout: EventEmitter;
        }
        const mockImageListProcess =
          new EventEmitter() as MockProcessWithStdout;
        mockImageListProcess.stdout = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockImageListProcess.emit('close', 0);
          }, 1);
          return mockImageListProcess as unknown as ReturnType<typeof spawn>;
        });

        // 2. container image pull (fails)
        interface MockProcessWithStdoutStderr extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockPullProcess =
          new EventEmitter() as MockProcessWithStdoutStderr;
        mockPullProcess.stdout = new EventEmitter();
        mockPullProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockPullProcess.emit('close', 1);
          }, 1);
          return mockPullProcess as unknown as ReturnType<typeof spawn>;
        });

        await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
      });

      it('should pull image if not found locally', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'new-image',
        };

        // 1. container image list -q (image not found)
        interface MockProcessWithStdout extends EventEmitter {
          stdout: EventEmitter;
        }
        const mockImageListProcess =
          new EventEmitter() as MockProcessWithStdout;
        mockImageListProcess.stdout = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockImageListProcess.emit('close', 0);
          }, 1);
          return mockImageListProcess as unknown as ReturnType<typeof spawn>;
        });

        // 2. container image pull (succeeds)
        interface MockProcessWithStdoutStderr extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockPullProcess =
          new EventEmitter() as MockProcessWithStdoutStderr;
        mockPullProcess.stdout = new EventEmitter();
        mockPullProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockPullProcess.emit('close', 0);
          }, 1);
          return mockPullProcess as unknown as ReturnType<typeof spawn>;
        });

        // 3. container run
        const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
          typeof spawn
        >;
        mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
          if (event === 'close') {
            setTimeout(() => cb(0), 10);
          }
          return mockSpawnProcess;
        });
        vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

        await start_sandbox(config, [], undefined, ['arg1']);

        // Verify pull was called
        expect(spawn).toHaveBeenCalledWith(
          'container',
          ['image', 'pull', 'new-image'],
          expect.any(Object),
        );
      });

      it('should forward environment variables', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'some-image',
        };
        process.env['GEMINI_API_KEY'] = 'test-key';
        process.env['GOOGLE_GEMINI_BASE_URL'] = 'http://test.proxy';

        // 1. container image list -q (image exists)
        interface MockProcessWithStdout extends EventEmitter {
          stdout: EventEmitter;
        }
        const mockImageListProcess =
          new EventEmitter() as MockProcessWithStdout;
        mockImageListProcess.stdout = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockImageListProcess.stdout.emit(
              'data',
              Buffer.from('some-image\n'),
            );
            mockImageListProcess.emit('close', 0);
          }, 1);
          return mockImageListProcess as unknown as ReturnType<typeof spawn>;
        });

        // 2. container run
        const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
          typeof spawn
        >;
        mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
          if (event === 'close') {
            setTimeout(() => cb(0), 10);
          }
          return mockSpawnProcess;
        });
        vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

        await start_sandbox(config);

        expect(spawn).toHaveBeenCalledWith(
          'container',
          expect.arrayContaining([
            '-e',
            'GEMINI_API_KEY=test-key',
            '-e',
            'GOOGLE_GEMINI_BASE_URL=http://test.proxy',
          ]),
          expect.any(Object),
        );
      });

      it('should mount volumes correctly', async () => {
        vi.mocked(os.platform).mockReturnValue('darwin');
        const config: SandboxConfig = {
          command: 'macos-container',
          image: 'some-image',
        };
        process.env['SANDBOX_MOUNTS'] = '/host/path:/container/path:ro';

        // 1. container image list -q (image exists)
        interface MockProcessWithStdout extends EventEmitter {
          stdout: EventEmitter;
        }
        const mockImageListProcess =
          new EventEmitter() as MockProcessWithStdout;
        mockImageListProcess.stdout = new EventEmitter();
        vi.mocked(spawn).mockImplementationOnce(() => {
          setTimeout(() => {
            mockImageListProcess.stdout.emit(
              'data',
              Buffer.from('some-image\n'),
            );
            mockImageListProcess.emit('close', 0);
          }, 1);
          return mockImageListProcess as unknown as ReturnType<typeof spawn>;
        });

        // 2. container run
        const mockSpawnProcess = new EventEmitter() as unknown as ReturnType<
          typeof spawn
        >;
        mockSpawnProcess.on = vi.fn().mockImplementation((event, cb) => {
          if (event === 'close') {
            setTimeout(() => cb(0), 10);
          }
          return mockSpawnProcess;
        });
        vi.mocked(spawn).mockImplementationOnce(() => mockSpawnProcess);

        await start_sandbox(config);

        expect(spawn).toHaveBeenCalledWith(
          'container',
          expect.arrayContaining(['--volume', '/host/path:/container/path:ro']),
          expect.any(Object),
        );
      });
    });

    describe('Bubblewrap sandbox', () => {
      it('should route bwrap to bubblewrap with namespace args', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, [
          'gemini',
          '--prompt',
          'hello',
        ]);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(spawn).toHaveBeenCalledWith(
          'bwrap',
          expect.arrayContaining([
            '--unshare-user',

            '--unshare-pid',
            '--new-session',
            '--die-with-parent',
            '--dev',
            '/dev',
            '--proc',
            '/proc',
          ]),
          expect.objectContaining({
            stdio: ['inherit', 'inherit', 'inherit', 99],
          }),
        );
      });

      it('should include --seccomp arg when seccomp is enabled', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(spawn).toHaveBeenCalledWith(
          'bwrap',
          expect.arrayContaining(['--seccomp', '3']),
          expect.any(Object),
        );
      });

      it('should not include --seccomp when seccomp is disabled', async () => {
        mockedPrepareSeccompFd.mockReturnValueOnce(null);
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        const bwrapArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        expect(bwrapArgs).not.toContain('--seccomp');
        // Should use simple inherit array without extra fd
        expect(spawn).toHaveBeenCalledWith(
          'bwrap',
          expect.any(Array),
          expect.objectContaining({
            stdio: ['inherit', 'inherit', 'inherit'],
          }),
        );
      });

      it('should cleanup seccomp on process close', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(mockedCleanupSeccomp).toHaveBeenCalledWith({
          fd: 99,
          path: '/tmp/bwrap-seccomp-test.bpf',
        });
      });

      it('should set SANDBOX=bwrap env var', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(spawn).toHaveBeenCalledWith(
          'bwrap',
          expect.arrayContaining(['--setenv', 'SANDBOX', 'bwrap']),
          expect.any(Object),
        );
      });

      it('should forward environment variables via --setenv', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };
        process.env['GEMINI_API_KEY'] = 'test-key';
        process.env['GOOGLE_GEMINI_BASE_URL'] = 'http://test.proxy';

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(spawn).toHaveBeenCalledWith(
          'bwrap',
          expect.arrayContaining([
            '--setenv',
            'GEMINI_API_KEY',
            'test-key',
            '--setenv',
            'GOOGLE_GEMINI_BASE_URL',
            'http://test.proxy',
          ]),
          expect.any(Object),
        );
      });

      it('should include bind mounts from permissive profile', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);

        const bwrapArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        // Should have --ro-bind for system dirs
        const roBindIdx = bwrapArgs.indexOf('--ro-bind');
        expect(roBindIdx).toBeGreaterThan(-1);
        // Should have --bind for rw dirs (workdir)
        const bindIdx = bwrapArgs.indexOf('--bind');
        expect(bindIdx).toBeGreaterThan(-1);
      });

      it('should throw FatalSandboxError if BUILD_SANDBOX is set', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        process.env['BUILD_SANDBOX'] = '1';
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
      });

      it('should pass cliArgs after -- separator', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, [
          'gemini',
          '--prompt',
          'test',
        ]);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);

        const bwrapArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        const separatorIdx = bwrapArgs.indexOf('--');
        expect(separatorIdx).toBeGreaterThan(-1);
        expect(bwrapArgs.slice(separatorIdx + 1)).toEqual([
          'gemini',
          '--prompt',
          'test',
        ]);
      });

      it('should use custom profile from BWRAP_PROFILE env', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        process.env['BWRAP_PROFILE'] = 'strict';
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        // strict profile should NOT have ~/.gemini in bind mounts
        const bwrapArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        const argsStr = bwrapArgs.join(' ');
        expect(argsStr).not.toContain('.gemini');
      });

      it('should throw for invalid profile name', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        process.env['BWRAP_PROFILE'] = 'nonexistent';
        const config: SandboxConfig = {
          command: 'bwrap',
          image: 'some-image',
        };

        await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
      });
    });

    describe('Landlock sandbox', () => {
      it('should route landlock to landlock-helper with correct args', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, [
          'gemini',
          '--prompt',
          'hello',
        ]);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(spawn).toHaveBeenCalledWith(
          'landlock-helper',
          expect.arrayContaining([
            '--ro',
            '--rw',
            '--rx',
            '--seccomp',
            '/tmp/seccomp-test.bpf',
            '--',
            'gemini',
            '--prompt',
            'hello',
          ]),
          expect.objectContaining({
            stdio: 'inherit',
            env: expect.objectContaining({ SANDBOX: 'landlock' }),
          }),
        );
      });

      it('should include --seccomp when seccomp is enabled', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        const landlockArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        expect(landlockArgs).toContain('--seccomp');
        expect(landlockArgs).toContain('/tmp/seccomp-test.bpf');
      });

      it('should not include --seccomp when seccomp is disabled', async () => {
        mockedPrepareSeccompFile.mockReturnValueOnce(null);
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        const landlockArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        expect(landlockArgs).not.toContain('--seccomp');
      });

      it('should cleanup seccomp file on process close', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(mockedCleanupSeccompFile).toHaveBeenCalledWith({
          path: '/tmp/seccomp-test.bpf',
        });
      });

      it('should set SANDBOX=landlock in env', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        expect(spawn).toHaveBeenCalledWith(
          'landlock-helper',
          expect.any(Array),
          expect.objectContaining({
            env: expect.objectContaining({ SANDBOX: 'landlock' }),
          }),
        );
      });

      it('should throw FatalSandboxError if BUILD_SANDBOX is set', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        process.env['BUILD_SANDBOX'] = '1';
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
      });

      it('should use custom profile from LANDLOCK_PROFILE env', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        process.env['LANDLOCK_PROFILE'] = 'strict';
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, ['gemini']);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);
        // strict profile should NOT have ~/.gemini in args
        const landlockArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        const argsStr = landlockArgs.join(' ');
        expect(argsStr).not.toContain('.gemini');
      });

      it('should throw for invalid profile name', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        process.env['LANDLOCK_PROFILE'] = 'nonexistent';
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        await expect(start_sandbox(config)).rejects.toThrow(FatalSandboxError);
      });

      it('should pass cliArgs after -- separator', async () => {
        vi.mocked(os.platform).mockReturnValue('linux');
        const config: SandboxConfig = {
          command: 'landlock',
          image: 'some-image',
        };

        interface MockProcess extends EventEmitter {
          stdout: EventEmitter;
          stderr: EventEmitter;
        }
        const mockSpawnProcess = new EventEmitter() as MockProcess;
        mockSpawnProcess.stdout = new EventEmitter();
        mockSpawnProcess.stderr = new EventEmitter();
        vi.mocked(spawn).mockReturnValue(
          mockSpawnProcess as unknown as ReturnType<typeof spawn>,
        );

        const promise = start_sandbox(config, [], undefined, [
          'gemini',
          '--prompt',
          'test',
        ]);

        setTimeout(() => {
          mockSpawnProcess.emit('close', 0);
        }, 10);

        await expect(promise).resolves.toBe(0);

        const landlockArgs = vi.mocked(spawn).mock.calls[0][1] as string[];
        const separatorIdx = landlockArgs.indexOf('--');
        expect(separatorIdx).toBeGreaterThan(-1);
        expect(landlockArgs.slice(separatorIdx + 1)).toEqual([
          'gemini',
          '--prompt',
          'test',
        ]);
      });
    });
  });
});
