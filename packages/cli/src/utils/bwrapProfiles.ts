/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import path from 'node:path';
import { FatalSandboxError } from '@google/gemini-cli-core';

export interface BwrapProfile {
  name: string;
  // Directories to bind read-write
  rwBinds: string[];
  // Directories to bind read-only
  roBinds: string[];
  // Whether to allow network access (false = --unshare-net)
  shareNetwork: boolean;
}

export const BUILTIN_BWRAP_PROFILES = [
  'permissive',
  'permissive-proxied',
  'restrictive',
  'restrictive-proxied',
  'strict',
  'strict-proxied',
];

/**
 * Builds a BwrapProfile for the given profile name and runtime context.
 *
 * Profiles control what directories are accessible inside the sandbox:
 * - permissive: rw to workspace, tmp, ~/.gemini, ~/.npm, ~/.cache
 * - restrictive: rw to workspace and tmp only; ~/.gemini is read-only
 * - strict: rw to workspace only; minimal system access
 *
 * The `-proxied` variants keep the same filesystem access but are
 * intended to be used with GEMINI_SANDBOX_PROXY_COMMAND (the proxy
 * env vars are set by the caller in startBwrapSandbox).
 */
export function buildBwrapProfile(
  profileName: string,
  workdir: string,
  homeDir: string,
  tmpDir: string,
): BwrapProfile {
  if (!BUILTIN_BWRAP_PROFILES.includes(profileName)) {
    throw new FatalSandboxError(
      `Unknown bwrap profile '${profileName}'. ` +
        `Available profiles: ${BUILTIN_BWRAP_PROFILES.join(', ')}`,
    );
  }

  const baseName = profileName.replace(/-proxied$/, '');

  // System directories to bind read-only (common to all profiles)
  const systemRoBinds = ['/usr', '/lib', '/lib64', '/bin', '/sbin', '/etc'];

  // Ensure the node binary's directory is accessible. On some systems
  // (e.g. GitHub Actions runners) node lives outside standard paths
  // like /opt/hostedtoolcache/.
  const nodeDir = path.dirname(process.execPath);
  if (!systemRoBinds.some((dir) => nodeDir.startsWith(dir))) {
    systemRoBinds.push(nodeDir);
  }

  switch (baseName) {
    case 'permissive':
      return {
        name: profileName,
        rwBinds: [
          workdir,
          tmpDir,
          path.join(homeDir, '.gemini'),
          path.join(homeDir, '.npm'),
          path.join(homeDir, '.cache'),
        ],
        roBinds: [
          ...systemRoBinds,
          path.join(homeDir, '.gitconfig'),
          path.join(homeDir, '.config', 'gcloud'),
        ],
        shareNetwork: true,
      };

    case 'restrictive':
      return {
        name: profileName,
        rwBinds: [workdir, tmpDir],
        roBinds: [
          ...systemRoBinds,
          path.join(homeDir, '.gemini'),
          path.join(homeDir, '.gitconfig'),
          path.join(homeDir, '.config', 'gcloud'),
        ],
        shareNetwork: true,
      };

    case 'strict':
      return {
        name: profileName,
        rwBinds: [workdir],
        roBinds: systemRoBinds,
        shareNetwork: true,
      };

    default:
      throw new FatalSandboxError(`Unknown bwrap profile base '${baseName}'.`);
  }
}
