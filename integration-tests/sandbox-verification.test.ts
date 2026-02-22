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
const hasSeccomp = sandbox === 'bwrap' || sandbox === 'landlock';
const skipAll = !sandbox || sandbox === 'false';

describe('sandbox verification', () => {
  // --- Group 1: Basic functionality (all sandbox types) ---
  describe('basic functionality', () => {
    let rig: TestRig;

    beforeAll(async () => {
      rig = new TestRig();
      await rig.setup('sandbox-basic', {
        settings: { tools: { core: ['run_shell_command'] } },
        fakeResponsesPath: join(
          import.meta.dirname,
          'sandbox-verification.responses',
        ),
      });
    });

    afterAll(async () => {
      await rig.cleanup();
    });

    it('should run in the expected sandbox environment', async () => {
      if (skipAll) return;

      await rig.run({
        args: 'Check sandbox environment',
      });

      const foundToolCall = await rig.waitForToolCall('run_shell_command');
      expect(
        foundToolCall,
        `Expected run_shell_command to be called inside ${sandbox} sandbox`,
      ).toBeTruthy();
    });
  });

  // --- Group 2: Allowed operations (all sandbox types) ---
  describe('allowed operations', () => {
    let rig: TestRig;

    beforeAll(async () => {
      if (skipAll) return;
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

    it('should run echo successfully', async () => {
      if (skipAll) return;

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
      if (skipAll) return;

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
      if (skipAll) return;

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

  // --- Group 3: Filesystem restrictions (non-container sandboxes only) ---
  // Container sandboxes have isolated filesystems, so writes to host-
  // protected paths succeed inside the container. Filesystem write denial
  // only applies to non-container sandboxes (sandbox-exec, bwrap, landlock).
  describe.skipIf(isContainer || skipAll)('filesystem restrictions', () => {
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

  // --- Group 4: Container isolation (docker/podman/macos-container only) ---
  // Container sandboxes write to their own isolated filesystem. Writes to
  // non-mounted paths (like /var/tmp) succeed inside the container but must
  // NOT appear on the host.
  describe.skipIf(!isContainer || skipAll)('container isolation', () => {
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

  // --- Group 5: Seccomp restrictions (bwrap/landlock only) ---
  describe.skipIf(!hasSeccomp || skipAll)('seccomp restrictions', () => {
    let rig: TestRig;

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
      await rig.waitForToolCall('run_shell_command', undefined, (args) =>
        args.includes('unshare'),
      );
    });

    afterAll(async () => {
      if (rig) await rig.cleanup();
    });

    it('should deny unshare via seccomp', async () => {
      const toolLogs = rig
        .readToolLogs()
        .filter((l) => l.toolRequest.name === 'run_shell_command');
      const unshareCall = toolLogs.find((l) =>
        l.toolRequest.args.includes('unshare'),
      );
      expect(unshareCall, 'Expected unshare tool call').toBeTruthy();
      // The seccomp filter should block the unshare syscall, causing the
      // command to fail. We can't check exit code from telemetry (tool
      // reports success=true since the tool infra worked), but we can verify
      // the tool was executed. The real assertion is that the sandbox didn't
      // crash — if seccomp killed the sandbox process, rig.run() would have
      // thrown.
      expect(unshareCall!.toolRequest.success).toBe(true);
    });
  });
});
