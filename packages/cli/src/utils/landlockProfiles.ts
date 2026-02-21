/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import path from 'node:path';
import { FatalSandboxError } from '@google/gemini-cli-core';

export interface LandlockProfile {
  name: string;
  // Directories with read-write access (--rw)
  rwPaths: string[];
  // Directories with read-only access (--ro)
  roPaths: string[];
  // Directories with read+execute access (--rx, for system dirs)
  rxPaths: string[];
  // Whether to apply the seccomp filter
  useSeccomp: boolean;
}

export const BUILTIN_LANDLOCK_PROFILES = [
  'permissive',
  'permissive-proxied',
  'restrictive',
  'restrictive-proxied',
  'strict',
  'strict-proxied',
];

/**
 * Builds a LandlockProfile for the given profile name and runtime context.
 *
 * Profiles control what directories are accessible inside the sandbox:
 * - permissive: rw to workspace, tmp, ~/.gemini, ~/.npm, ~/.cache; rx system dirs
 * - restrictive: rw to workspace and tmp only; ~/.gemini is read-only; rx system dirs
 * - strict: rw to workspace only; rx system dirs only
 *
 * The `-proxied` variants have the same filesystem access but are
 * intended for use with GEMINI_SANDBOX_PROXY_COMMAND.
 */
export function buildLandlockProfile(
  profileName: string,
  workdir: string,
  homeDir: string,
  tmpDir: string,
): LandlockProfile {
  if (!BUILTIN_LANDLOCK_PROFILES.includes(profileName)) {
    throw new FatalSandboxError(
      `Unknown landlock profile '${profileName}'. ` +
        `Available profiles: ${BUILTIN_LANDLOCK_PROFILES.join(', ')}`,
    );
  }

  const baseName = profileName.replace(/-proxied$/, '');

  // System directories need read+execute access
  const systemRxPaths = ['/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc'];

  switch (baseName) {
    case 'permissive':
      return {
        name: profileName,
        rwPaths: [
          workdir,
          tmpDir,
          path.join(homeDir, '.gemini'),
          path.join(homeDir, '.npm'),
          path.join(homeDir, '.cache'),
        ],
        roPaths: [
          path.join(homeDir, '.gitconfig'),
          path.join(homeDir, '.config', 'gcloud'),
        ],
        rxPaths: systemRxPaths,
        useSeccomp: true,
      };

    case 'restrictive':
      return {
        name: profileName,
        rwPaths: [workdir, tmpDir],
        roPaths: [
          path.join(homeDir, '.gemini'),
          path.join(homeDir, '.gitconfig'),
          path.join(homeDir, '.config', 'gcloud'),
        ],
        rxPaths: systemRxPaths,
        useSeccomp: true,
      };

    case 'strict':
      return {
        name: profileName,
        rwPaths: [workdir],
        roPaths: [],
        rxPaths: systemRxPaths,
        useSeccomp: true,
      };

    default:
      throw new FatalSandboxError(
        `Unknown landlock profile base '${baseName}'.`,
      );
  }
}
