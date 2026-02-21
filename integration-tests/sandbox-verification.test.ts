/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { TestRig } from './test-helper.js';
import { join } from 'node:path';

describe('sandbox verification', () => {
  let rig: TestRig;

  beforeAll(async () => {
    rig = new TestRig();
    await rig.setup('sandbox-verification', {
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
    // Skip verification if no sandbox is expected (e.g. running locally)
    const expectedSandbox = process.env['GEMINI_SANDBOX'];
    if (!expectedSandbox || expectedSandbox === 'false') {
      return;
    }

    // The fake response instructs the CLI to call `run_shell_command` with `env`.
    // If the sandbox is misconfigured the CLI will crash (non-zero exit),
    // and rig.run() will reject.
    await rig.run({
      args: 'Check sandbox environment',
    });

    // Verify the tool was actually called and succeeded inside the sandbox.
    const foundToolCall = await rig.waitForToolCall('run_shell_command');
    expect(
      foundToolCall,
      `Expected run_shell_command to be called inside ${expectedSandbox} sandbox`,
    ).toBeTruthy();
  });
});
