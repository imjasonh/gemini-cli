/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  debugLogger,
  getPackageJson,
  type SandboxConfig,
  FatalSandboxError,
} from '@google/gemini-cli-core';
import commandExists from 'command-exists';
import * as os from 'node:os';
import type { Settings } from './settings.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  detectContainerEnvironment,
  isBwrapAvailable,
  isLandlockAvailable,
  isMacOSContainerAvailable,
} from '../utils/sandboxUtils.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// This is a stripped-down version of the CliArgs interface from config.ts
// to avoid circular dependencies.
interface SandboxCliArgs {
  sandbox?: boolean | string | null;
}
const VALID_SANDBOX_COMMANDS: ReadonlyArray<SandboxConfig['command']> = [
  'docker',
  'podman',
  'sandbox-exec',
  'bwrap',
  'macos-container',
  'landlock',
];

function isSandboxCommand(value: string): value is SandboxConfig['command'] {
  return (VALID_SANDBOX_COMMANDS as readonly string[]).includes(value);
}

async function getSandboxCommand(
  sandbox?: boolean | string | null,
): Promise<SandboxConfig['command'] | ''> {
  const containerEnv = detectContainerEnvironment();

  // Already in Gemini's own sandbox — never re-sandbox
  if (containerEnv.isGeminiSandbox) {
    return '';
  }

  // note environment variable takes precedence over argument (from command line or settings)
  const environmentConfiguredSandbox =
    process.env['GEMINI_SANDBOX']?.toLowerCase().trim() ?? '';
  sandbox =
    environmentConfiguredSandbox?.length > 0
      ? environmentConfiguredSandbox
      : sandbox;
  // Handle 'force' — used to override nested container detection
  const forceNested = sandbox === 'force';
  if (forceNested) {
    sandbox = true;
  }

  if (sandbox === '1' || sandbox === 'true') sandbox = true;
  else if (sandbox === '0' || sandbox === 'false' || !sandbox) sandbox = false;

  if (sandbox === false) {
    return '';
  }

  // Running inside an external container — skip sandboxing unless forced
  if (containerEnv.detected && !forceNested) {
    if (typeof sandbox === 'string') {
      // User explicitly requested a specific sandbox command, allow it
    } else {
      debugLogger.log(
        `Running inside ${containerEnv.type} container. ` +
          `Sandboxing disabled (outer container provides isolation). ` +
          `Set GEMINI_SANDBOX=force to override.`,
      );
      return '';
    }
  } else if (containerEnv.detected && forceNested) {
    debugLogger.warn(
      `Forcing sandbox inside ${containerEnv.type} container. This may not work correctly.`,
    );
  }

  if (typeof sandbox === 'string' && sandbox) {
    if (!isSandboxCommand(sandbox)) {
      throw new FatalSandboxError(
        `Invalid sandbox command '${sandbox}'. Must be one of ${VALID_SANDBOX_COMMANDS.join(
          ', ',
        )}`,
      );
    }

    // For landlock, check kernel support rather than a binary
    if (sandbox === 'landlock') {
      if (await isLandlockAvailable()) {
        return 'landlock';
      }
      throw new FatalSandboxError(
        `Sandbox command 'landlock' is not available: requires Linux kernel 5.13+ with Landlock support`,
      );
    }

    // For macos-container, check macOS version and 'container' CLI
    if (sandbox === 'macos-container') {
      if (await isMacOSContainerAvailable()) {
        return 'macos-container';
      }
      throw new FatalSandboxError(
        `Sandbox command 'macos-container' is not available: requires macOS 15+ and the 'container' CLI`,
      );
    }

    // For bwrap, check binary and user namespace support
    if (sandbox === 'bwrap') {
      if (await isBwrapAvailable()) {
        return 'bwrap';
      }
      throw new FatalSandboxError(
        `Sandbox command 'bwrap' is not available: install bubblewrap and ensure user namespaces are enabled`,
      );
    }

    // confirm that specified command exists (for docker, podman, sandbox-exec)
    if (commandExists.sync(sandbox)) {
      return sandbox;
    }
    throw new FatalSandboxError(
      `Missing sandbox command '${sandbox}' (from GEMINI_SANDBOX)`,
    );
  }

  // Auto-detection: look for the best available sandbox for the current platform.
  // On macOS, prefer sandbox-exec (Seatbelt). Container-based options require explicit opt-in.
  if (os.platform() === 'darwin' && commandExists.sync('sandbox-exec')) {
    return 'sandbox-exec';
  }

  // On Linux with sandbox: true, prefer landlock > bwrap > docker > podman
  if (os.platform() === 'linux' && sandbox === true) {
    if (await isLandlockAvailable()) {
      return 'landlock';
    }
    if (await isBwrapAvailable()) {
      return 'bwrap';
    }
  }

  if (commandExists.sync('docker') && sandbox === true) {
    return 'docker';
  } else if (commandExists.sync('podman') && sandbox === true) {
    return 'podman';
  }

  // throw an error if user requested sandbox but no command was found
  if (sandbox === true) {
    throw new FatalSandboxError(
      'GEMINI_SANDBOX is true but failed to determine command for sandbox; ' +
        'install bubblewrap (bwrap), docker, or podman, or specify a command in GEMINI_SANDBOX',
    );
  }

  return '';
}

export async function loadSandboxConfig(
  settings: Settings,
  argv: SandboxCliArgs,
): Promise<SandboxConfig | undefined> {
  const sandboxOption = argv.sandbox ?? settings.tools?.sandbox;
  const command = await getSandboxCommand(sandboxOption);

  const packageJson = await getPackageJson(__dirname);
  const image =
    process.env['GEMINI_SANDBOX_IMAGE'] ?? packageJson?.config?.sandboxImageUri;

  return command && image ? { command, image } : undefined;
}
