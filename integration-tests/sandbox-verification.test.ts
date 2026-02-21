/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, beforeAll, afterAll } from 'vitest';
import { TestRig } from './test-helper.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);

describe('sandbox verification', () => {
  let rig: TestRig;

  beforeAll(async () => {
    rig = new TestRig();
    await rig.setup(path.basename(__filename, '.test.ts'));
  });

  afterAll(async () => {
    await rig.cleanup();
  });

  it('should run in the expected sandbox environment', async () => {
    // Skip verification if no sandbox is expected (e.g. running locally)
    // The test rig now correctly propagates GEMINI_SANDBOX
    const expectedSandbox = process.env['GEMINI_SANDBOX'];
    if (!expectedSandbox || expectedSandbox === 'false') {
      return;
    }

    // This runs the CLI, which uses the fake response from sandbox-verification.responses
    // The fake response instructs the CLI to call `run_shell_command` with `env`
    const result = await rig.run('sandbox-verification', {
      tools: {
        core: ['run_shell_command'],
      },
    });

    // The tool output (which contains the env vars) should be present in the CLI's stdout
    const expectedVar = `SANDBOX=${expectedSandbox}`;
    if (!result.stdout.includes(expectedVar)) {
      console.error(
        `Failed to find '${expectedVar}' in output. Full output:\n${result.stdout}`,
      );
      throw new Error(
        `Expected sandbox environment variable '${expectedVar}' not found in output.`,
      );
    }
  });
});
