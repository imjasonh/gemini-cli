/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { TestRig } from './test-helper.js';
import { join } from 'node:path';
import fs from 'node:fs';

const sandbox = process.env['GEMINI_SANDBOX'];
const isContainer =
  sandbox === 'docker' || sandbox === 'podman' || sandbox === 'macos-container';
const isWSL = (() => {
  try {
    return fs
      .readFileSync('/proc/version', 'utf8')
      .toLowerCase()
      .includes('microsoft');
  } catch {
    return false;
  }
})();
const hasSeccomp = (sandbox === 'bwrap' || sandbox === 'landlock') && !isWSL;
const skipAll = !sandbox || sandbox === 'false';

describe.skipIf(skipAll)('sandbox verification', () => {
  // --- Group 1: Allowed operations (all sandbox types) ---
  // Verifies that shell commands, workdir writes, and system file reads
  // all work inside the sandbox.
  describe('allowed operations', () => {
    let rig: TestRig;

    beforeAll(async () => {
      rig = new TestRig();
      await rig.setup('sandbox-allowed', {
        settings: { tools: { core: ['run_shell_command'] } },
        fakeResponsesPath: join(
          import.meta.dirname,
          'sandbox-allowed.responses',
        ),
      });
      await rig.run({
        args: 'Test allowed operations',
      });
      await rig.waitForToolCall('run_shell_command', undefined, (args) =>
        args.includes('cat /etc/hosts'),
      );
    });

    afterAll(async () => {
      if (rig) await rig.cleanup();
    });

    it('should execute shell commands', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const echoCall = toolLogs.find((l) =>
        l.toolRequest.args.includes('echo sandbox-ok'),
      );
      expect(echoCall, 'Expected echo sandbox-ok tool call').toBeTruthy();
      expect(echoCall!.toolRequest.success).toBe(true);
    });

    it('should write and read files in workdir', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const writeCall = toolLogs.find((l) =>
        l.toolRequest.args.includes('sandbox-write.txt'),
      );
      expect(writeCall, 'Expected sandbox-write.txt tool call').toBeTruthy();
      expect(writeCall!.toolRequest.success).toBe(true);

      // Verify the file was actually created in the workdir
      const filePath = join(rig.testDir!, 'sandbox-write.txt');
      expect(
        fs.existsSync(filePath),
        `Expected ${filePath} to exist after write`,
      ).toBe(true);
    });

    it('should read system files', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const readCall = toolLogs.find((l) =>
        l.toolRequest.args.includes('cat /etc/hosts'),
      );
      expect(readCall, 'Expected cat /etc/hosts tool call').toBeTruthy();
      expect(readCall!.toolRequest.success).toBe(true);
    });
  });

  // --- Group 2: Filesystem restrictions (non-container sandboxes only) ---
  // Container sandboxes have isolated filesystems, so writes to host-
  // protected paths succeed inside the container. Filesystem write denial
  // only applies to non-container sandboxes (sandbox-exec, bwrap, landlock).
  describe.skipIf(isContainer)('filesystem restrictions', () => {
    let rig: TestRig;
    // Use a path writable by the current user but outside sandbox-allowed
    // write paths. /var/tmp resolves to /private/var/tmp on macOS, which is
    // not covered by the seatbelt's (subpath "/private/tmp") rule.
    // On Linux (bwrap/landlock), /var/tmp is outside the allowed mount points.
    const deniedFile = '/var/tmp/gemini-sandbox-test-denied';

    beforeAll(async () => {
      // Clean up any leftover file from previous runs
      try {
        fs.unlinkSync(deniedFile);
      } catch {
        // Ignore if doesn't exist
      }

      rig = new TestRig();
      await rig.setup('sandbox-denied', {
        settings: { tools: { core: ['run_shell_command'] } },
        fakeResponsesPath: join(
          import.meta.dirname,
          'sandbox-denied.responses',
        ),
      });
      await rig.run({
        args: 'Test filesystem restrictions',
      });
      await rig.waitForToolCall('run_shell_command', undefined, (args) =>
        args.includes('touch /var/tmp/gemini-sandbox-test-denied'),
      );
    });

    afterAll(async () => {
      if (rig) await rig.cleanup();
      // Clean up in case the sandbox was misconfigured and the file was created
      try {
        fs.unlinkSync(deniedFile);
      } catch {
        // Ignore
      }
    });

    it('should deny writes outside allowed paths', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const touchCall = toolLogs.find((l) =>
        l.toolRequest.args.includes(deniedFile),
      );
      expect(touchCall, `Expected touch ${deniedFile} tool call`).toBeTruthy();

      // The sandbox should have blocked the write — verify the file was not
      // created on the host filesystem.
      expect(
        fs.existsSync(deniedFile),
        `Expected ${deniedFile} to NOT exist (sandbox should have blocked the write)`,
      ).toBe(false);
    });
  });

  // --- Group 3: Container isolation (docker/podman/macos-container only) ---
  // Container sandboxes write to their own isolated filesystem. Writes to
  // non-mounted paths (like /var/tmp) succeed inside the container but must
  // NOT appear on the host.
  describe.skipIf(!isContainer)('container isolation', () => {
    let rig: TestRig;
    const containedFile = '/var/tmp/gemini-sandbox-test-contained';

    beforeAll(async () => {
      // Clean up any leftover file from previous runs
      try {
        fs.unlinkSync(containedFile);
      } catch {
        // Ignore if doesn't exist
      }

      rig = new TestRig();
      await rig.setup('sandbox-container', {
        settings: { tools: { core: ['run_shell_command'] } },
        fakeResponsesPath: join(
          import.meta.dirname,
          'sandbox-container.responses',
        ),
      });
      await rig.run({
        args: 'Test container isolation',
      });
      await rig.waitForToolCall('run_shell_command', undefined, (args) =>
        args.includes(containedFile),
      );
    });

    afterAll(async () => {
      if (rig) await rig.cleanup();
      try {
        fs.unlinkSync(containedFile);
      } catch {
        // Ignore
      }
    });

    it('should isolate container writes from the host', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const touchCall = toolLogs.find((l) =>
        l.toolRequest.args.includes(containedFile),
      );
      expect(
        touchCall,
        `Expected touch ${containedFile} tool call`,
      ).toBeTruthy();

      // The touch should have succeeded inside the container.
      expect(touchCall!.toolRequest.success).toBe(true);

      // But the file must NOT exist on the host — it was written to the
      // container's own /var/tmp, which is not mounted from the host.
      expect(
        fs.existsSync(containedFile),
        `Expected ${containedFile} to NOT exist on host (container should isolate writes)`,
      ).toBe(false);
    });
  });

  // --- Group 4: Seccomp restrictions (bwrap/landlock only) ---
  // Each test command attempts a blocked syscall, then writes a marker file
  // only if the syscall succeeds. We assert the marker does NOT exist.
  describe.skipIf(!hasSeccomp)('seccomp restrictions', () => {
    let rig: TestRig;

    const markers = [
      'unshare-marker',
      'mount-marker',
      'chroot-marker',
      'ptrace-marker',
    ];

    beforeAll(async () => {
      rig = new TestRig();
      await rig.setup('sandbox-seccomp', {
        settings: { tools: { core: ['run_shell_command'] } },
        fakeResponsesPath: join(
          import.meta.dirname,
          'sandbox-seccomp.responses',
        ),
      });
      await rig.run({
        args: 'Test seccomp restrictions',
      });
      // Wait for the last tool call (ptrace/strace)
      await rig.waitForToolCall('run_shell_command', undefined, (args) =>
        args.includes('strace'),
      );
    });

    afterAll(async () => {
      if (rig) {
        // Clean up markers in case seccomp was misconfigured
        for (const marker of markers) {
          try {
            fs.unlinkSync(join(rig.testDir!, marker));
          } catch {
            // Ignore
          }
        }
        await rig.cleanup();
      }
    });

    it('should deny unshare via seccomp', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const call = toolLogs.find((l) => l.toolRequest.args.includes('unshare'));
      expect(call, 'Expected unshare tool call').toBeTruthy();
      expect(
        fs.existsSync(join(rig.testDir!, 'unshare-marker')),
        'unshare should have been blocked by seccomp',
      ).toBe(false);
    });

    it('should deny mount via seccomp', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const call = toolLogs.find((l) =>
        l.toolRequest.args.includes('mount -t tmpfs'),
      );
      expect(call, 'Expected mount tool call').toBeTruthy();
      expect(
        fs.existsSync(join(rig.testDir!, 'mount-marker')),
        'mount should have been blocked by seccomp',
      ).toBe(false);
    });

    it('should deny chroot via seccomp', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const call = toolLogs.find((l) => l.toolRequest.args.includes('chroot'));
      expect(call, 'Expected chroot tool call').toBeTruthy();
      expect(
        fs.existsSync(join(rig.testDir!, 'chroot-marker')),
        'chroot should have been blocked by seccomp',
      ).toBe(false);
    });

    it('should deny ptrace via seccomp', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const call = toolLogs.find((l) => l.toolRequest.args.includes('strace'));
      expect(call, 'Expected strace tool call').toBeTruthy();
      expect(
        fs.existsSync(join(rig.testDir!, 'ptrace-marker')),
        'ptrace should have been blocked by seccomp',
      ).toBe(false);
    });
  });
});
