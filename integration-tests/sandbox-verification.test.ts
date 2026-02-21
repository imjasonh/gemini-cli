/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, beforeAll, afterAll } from 'vitest';
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

    // The fake response instructs the CLI to call `run_shell_command` with `env`
    const result = await rig.run({
      args: 'Check sandbox environment',
    });

    // The tool output (which contains the env vars) should be present in the CLI's stdout
    const expectedVar = `SANDBOX=${expectedSandbox}`;
    if (!result.includes(expectedVar)) {
      console.error(
        `Failed to find '${expectedVar}' in output. Full output:\n${result}`,
      );
      throw new Error(
        `Expected sandbox environment variable '${expectedVar}' not found in output.`,
      );
    }
  });
});
