/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import os from 'node:os';
import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { quote } from 'shell-quote';
import { debugLogger, GEMINI_DIR } from '@google/gemini-cli-core';
import commandExists from 'command-exists';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const execFileAsync = promisify(execFile);

export const LOCAL_DEV_SANDBOX_IMAGE_NAME = 'gemini-cli-sandbox';
export const BWRAP_PROFILE_DIR = '.gemini/bwrap-profiles';
export const DEFAULT_BWRAP_PROFILE = 'permissive';
export const SANDBOX_NETWORK_NAME = 'gemini-cli-sandbox';
export const SANDBOX_PROXY_NAME = 'gemini-cli-sandbox-proxy';
export const BUILTIN_SEATBELT_PROFILES = [
  'permissive-open',
  'permissive-proxied',
  'restrictive-open',
  'restrictive-proxied',
  'strict-open',
  'strict-proxied',
];

export type ContainerEnvironmentType =
  | 'docker'
  | 'podman'
  | 'kubernetes'
  | 'wsl1'
  | 'systemd-nspawn'
  | 'unknown'
  | 'none';

export interface ContainerEnvironment {
  detected: boolean;
  type: ContainerEnvironmentType;
  isGeminiSandbox: boolean;
}

/**
 * Detects whether we're running inside WSL (Windows Subsystem for Linux).
 * Checks for the WSL_DISTRO_NAME environment variable or WSLInterop in binfmt.
 */
export function isWSL(): boolean {
  if (os.platform() !== 'linux') {
    return false;
  }
  return !!(
    process.env['WSL_DISTRO_NAME'] ||
    fs.existsSync('/proc/sys/fs/binfmt_misc/WSLInterop')
  );
}

/**
 * Detects whether we're running inside WSL2 (as opposed to WSL1).
 * WSL2 uses a real Linux kernel (5.x+) with full namespace/seccomp support.
 * WSL1 uses NT kernel translation with a 4.4.x version string.
 */
export function isWSL2(): boolean {
  if (!isWSL()) {
    return false;
  }
  const release = os.release();
  // WSL2 kernel strings typically contain "WSL2"
  if (release.toLowerCase().includes('wsl2')) {
    return true;
  }
  // Fallback: WSL2 uses kernel 5.x+, WSL1 reports 4.4.x
  const [majorStr] = release.split('.');
  const major = parseInt(majorStr ?? '0', 10);
  return major >= 5;
}

/**
 * Detects whether we're running inside an existing container or sandbox.
 * Used to avoid nested sandboxing, which can fail or behave unexpectedly.
 *
 * WSL2 is NOT treated as a container — it has a real Linux kernel that
 * supports bwrap, landlock, and seccomp. Only WSL1 is treated as a
 * container environment because it cannot support user namespaces.
 */
export function detectContainerEnvironment(): ContainerEnvironment {
  // Already in Gemini's own sandbox
  if (process.env['SANDBOX']) {
    return { detected: true, type: 'unknown', isGeminiSandbox: true };
  }

  // Docker detection
  if (fs.existsSync('/.dockerenv')) {
    return { detected: true, type: 'docker', isGeminiSandbox: false };
  }

  // Podman detection
  if (fs.existsSync('/run/.containerenv')) {
    return { detected: true, type: 'podman', isGeminiSandbox: false };
  }

  // Kubernetes detection
  if (process.env['KUBERNETES_SERVICE_HOST']) {
    return { detected: true, type: 'kubernetes', isGeminiSandbox: false };
  }

  // WSL detection — only WSL1 is treated as a container environment.
  // WSL2 has a real Linux kernel and supports all sandbox mechanisms.
  if (isWSL() && !isWSL2()) {
    return { detected: true, type: 'wsl1', isGeminiSandbox: false };
  }

  // systemd-nspawn detection
  if (process.env['container'] === 'systemd-nspawn') {
    return { detected: true, type: 'systemd-nspawn', isGeminiSandbox: false };
  }

  // Cgroup-based detection (fallback)
  try {
    const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf8');
    if (
      cgroup.includes('docker') ||
      cgroup.includes('kubepods') ||
      cgroup.includes('lxc')
    ) {
      return { detected: true, type: 'unknown', isGeminiSandbox: false };
    }
  } catch {
    // Not in a container, or /proc/1/cgroup is not readable
  }

  return { detected: false, type: 'none', isGeminiSandbox: false };
}

export function getContainerPath(hostPath: string): string {
  if (os.platform() !== 'win32') {
    return hostPath;
  }

  const withForwardSlashes = hostPath.replace(/\\/g, '/');
  const match = withForwardSlashes.match(/^([A-Z]):\/(.*)/i);
  if (match) {
    return `/${match[1].toLowerCase()}/${match[2]}`;
  }
  return withForwardSlashes;
}

export async function shouldUseCurrentUserInSandbox(): Promise<boolean> {
  const envVar = process.env['SANDBOX_SET_UID_GID']?.toLowerCase().trim();

  if (envVar === '1' || envVar === 'true') {
    return true;
  }
  if (envVar === '0' || envVar === 'false') {
    return false;
  }

  // If environment variable is not explicitly set, check for Debian/Ubuntu Linux
  if (os.platform() === 'linux') {
    try {
      const osReleaseContent = await readFile('/etc/os-release', 'utf8');
      if (
        osReleaseContent.includes('ID=debian') ||
        osReleaseContent.includes('ID=ubuntu') ||
        osReleaseContent.match(/^ID_LIKE=.*debian.*/m) || // Covers derivatives
        osReleaseContent.match(/^ID_LIKE=.*ubuntu.*/m) // Covers derivatives
      ) {
        debugLogger.log(
          'Defaulting to use current user UID/GID for Debian/Ubuntu-based Linux.',
        );
        return true;
      }
    } catch (_err) {
      // Silently ignore if /etc/os-release is not found or unreadable.
      // The default (false) will be applied in this case.
      debugLogger.warn(
        'Warning: Could not read /etc/os-release to auto-detect Debian/Ubuntu for UID/GID default.',
      );
    }
  }
  return false; // Default to false if no other condition is met
}

export function parseImageName(image: string): string {
  const [fullName, tag] = image.split(':');
  const name = fullName.split('/').at(-1) ?? 'unknown-image';
  return tag ? `${name}-${tag}` : name;
}

export function ports(): string[] {
  return (process.env['SANDBOX_PORTS'] ?? '')
    .split(',')
    .filter((p) => p.trim())
    .map((p) => p.trim());
}

export function entrypoint(workdir: string, cliArgs: string[]): string[] {
  const isWindows = os.platform() === 'win32';
  const containerWorkdir = getContainerPath(workdir);
  const shellCmds = [];
  const pathSeparator = isWindows ? ';' : ':';

  let pathSuffix = '';
  if (process.env['PATH']) {
    const paths = process.env['PATH'].split(pathSeparator);
    for (const p of paths) {
      const containerPath = getContainerPath(p);
      if (
        containerPath.toLowerCase().startsWith(containerWorkdir.toLowerCase())
      ) {
        pathSuffix += `:${containerPath}`;
      }
    }
  }
  if (pathSuffix) {
    shellCmds.push(`export PATH="$PATH${pathSuffix}";`);
  }

  let pythonPathSuffix = '';
  if (process.env['PYTHONPATH']) {
    const paths = process.env['PYTHONPATH'].split(pathSeparator);
    for (const p of paths) {
      const containerPath = getContainerPath(p);
      if (
        containerPath.toLowerCase().startsWith(containerWorkdir.toLowerCase())
      ) {
        pythonPathSuffix += `:${containerPath}`;
      }
    }
  }
  if (pythonPathSuffix) {
    shellCmds.push(`export PYTHONPATH="$PYTHONPATH${pythonPathSuffix}";`);
  }

  const projectSandboxBashrc = `${GEMINI_DIR}/sandbox.bashrc`;
  if (fs.existsSync(projectSandboxBashrc)) {
    shellCmds.push(`source ${getContainerPath(projectSandboxBashrc)};`);
  }

  ports().forEach((p) =>
    shellCmds.push(
      `socat TCP4-LISTEN:${p},bind=$(hostname -i),fork,reuseaddr TCP4:127.0.0.1:${p} 2> /dev/null &`,
    ),
  );

  const quotedCliArgs = cliArgs.slice(2).map((arg) => quote([arg]));
  const isDebugMode =
    process.env['DEBUG'] === 'true' || process.env['DEBUG'] === '1';
  const cliCmd =
    process.env['NODE_ENV'] === 'development'
      ? isDebugMode
        ? 'npm run debug --'
        : 'npm rebuild && npm run start --'
      : isDebugMode
        ? `node --inspect-brk=0.0.0.0:${process.env['DEBUG_PORT'] || '9229'} $(which gemini)`
        : 'gemini';

  const args = [...shellCmds, cliCmd, ...quotedCliArgs];
  return ['bash', '-c', args.join(' ')];
}

/**
 * Checks whether the macOS Container Framework is available.
 * Requires macOS 15 (Sequoia) or later and the `container` CLI to be installed.
 */
export async function isMacOSContainerAvailable(): Promise<boolean> {
  if (os.platform() !== 'darwin') {
    return false;
  }

  // Check macOS version >= 15
  try {
    const { stdout } = await execFileAsync('sw_vers', ['-productVersion']);
    const version = stdout.trim();
    const major = parseInt(version.split('.')[0] ?? '0', 10);
    if (major < 15) {
      debugLogger.log(
        `isMacOSContainerAvailable: macOS version ${version} is < 15, not supported`,
      );
      return false;
    }
  } catch (err) {
    debugLogger.warn(
      `isMacOSContainerAvailable: failed to get macOS version: ${err}`,
    );
    return false;
  }

  // Check that the 'container' CLI exists
  if (!commandExists.sync('container')) {
    debugLogger.log(
      `isMacOSContainerAvailable: 'container' CLI not found in PATH`,
    );
    return false;
  }

  return true;
}

/**
 * Checks whether bubblewrap (`bwrap`) is available.
 * Requires the `bwrap` binary to exist and user namespaces to be enabled.
 */
export async function isBwrapAvailable(): Promise<boolean> {
  if (os.platform() !== 'linux') {
    return false;
  }

  if (!commandExists.sync('bwrap')) {
    debugLogger.log(`isBwrapAvailable: 'bwrap' binary not found in PATH`);
    return false;
  }

  // Check whether unprivileged user namespaces are enabled
  // (required for bwrap to work without setuid)
  try {
    const content = await readFile(
      '/proc/sys/kernel/unprivileged_userns_clone',
      'utf8',
    );
    if (content.trim() === '0') {
      debugLogger.log(
        `isBwrapAvailable: unprivileged user namespaces are disabled (/proc/sys/kernel/unprivileged_userns_clone=0)`,
      );
      return false;
    }
  } catch (_err) {
    // File may not exist on all kernels (e.g. upstream kernels without the Debian patch).
    // Absence of the file generally means user namespaces are allowed by default.
    debugLogger.log(
      `isBwrapAvailable: /proc/sys/kernel/unprivileged_userns_clone not found, assuming user namespaces are enabled`,
    );
  }

  return true;
}

/**
 * Checks whether Linux Landlock is available.
 * Requires Linux kernel 5.13+ with Landlock LSM support enabled.
 */
export async function isLandlockAvailable(): Promise<boolean> {
  if (os.platform() !== 'linux') {
    return false;
  }

  // Check kernel version >= 5.13
  try {
    const release = os.release(); // e.g. "6.1.0-21-amd64"
    const [majorStr, minorStr] = release.split('.');
    const major = parseInt(majorStr ?? '0', 10);
    const minor = parseInt(minorStr ?? '0', 10);
    if (major < 5 || (major === 5 && minor < 13)) {
      debugLogger.log(
        `isLandlockAvailable: kernel ${release} is older than 5.13, Landlock not supported`,
      );
      return false;
    }
  } catch (err) {
    debugLogger.warn(
      `isLandlockAvailable: failed to parse kernel version: ${err}`,
    );
    return false;
  }

  // Check that Landlock LSM is loaded by reading the active LSM list.
  // We read /sys/kernel/security/lsm instead of checking for the
  // /sys/kernel/security/landlock/ directory, because some kernels (e.g.
  // Azure-tuned) enable Landlock syscalls without exposing the securityfs
  // directory.
  try {
    const lsmList = await readFile('/sys/kernel/security/lsm', 'utf8');
    if (!lsmList.split(',').some((m) => m.trim() === 'landlock')) {
      debugLogger.log(
        `isLandlockAvailable: 'landlock' not found in LSM list: ${lsmList.trim()}`,
      );
      return false;
    }
  } catch (err) {
    debugLogger.log(
      `isLandlockAvailable: cannot read /sys/kernel/security/lsm: ${err}`,
    );
    return false;
  }

  // Check that the landlock-helper binary is available
  if (!getLandlockHelperPath()) {
    debugLogger.log(`isLandlockAvailable: 'landlock-helper' binary not found`);
    return false;
  }

  return true;
}

export function getLandlockHelperPath(): string | null {
  const possiblePaths = [
    // 1. Bundled binary (dist/utils/../landlock-helper)
    path.join(__dirname, '..', 'landlock-helper'),
    // 2. Dev binary relative to source (src/utils/../../native/landlock-helper)
    path.join(__dirname, '..', '..', 'native', 'landlock-helper'),
    // 3. Dev binary relative to CWD (useful for tests running from repo root)
    path.join(process.cwd(), 'packages', 'cli', 'native', 'landlock-helper'),
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // Check PATH as fallback
  if (commandExists.sync('landlock-helper')) {
    return 'landlock-helper';
  }

  return null;
}
