/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  exec,
  execFile,
  execSync,
  spawn,
  spawnSync,
  type ChildProcess,
} from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { quote, parse } from 'shell-quote';
import { promisify } from 'node:util';
import type { Config, SandboxConfig } from '@google/gemini-cli-core';
import {
  coreEvents,
  debugLogger,
  FatalSandboxError,
  GEMINI_DIR,
  homedir,
} from '@google/gemini-cli-core';
import { ConsolePatcher } from '../ui/utils/ConsolePatcher.js';
import { randomBytes } from 'node:crypto';
import {
  getContainerPath,
  shouldUseCurrentUserInSandbox,
  parseImageName,
  ports,
  entrypoint,
  LOCAL_DEV_SANDBOX_IMAGE_NAME,
  SANDBOX_NETWORK_NAME,
  SANDBOX_PROXY_NAME,
  BUILTIN_SEATBELT_PROFILES,
  DEFAULT_BWRAP_PROFILE,
  isWSL,
} from './sandboxUtils.js';
import { buildBwrapProfile, BUILTIN_BWRAP_PROFILES } from './bwrapProfiles.js';
import {
  prepareSeccompFd,
  cleanupSeccomp,
  prepareSeccompFile,
  cleanupSeccompFile,
} from './bwrap-seccomp.js';
import {
  buildLandlockProfile,
  BUILTIN_LANDLOCK_PROFILES,
} from './landlockProfiles.js';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

export async function start_sandbox(
  config: SandboxConfig,
  nodeArgs: string[] = [],
  cliConfig?: Config,
  cliArgs: string[] = [],
): Promise<number> {
  const patcher = new ConsolePatcher({
    debugMode: cliConfig?.getDebugMode() || !!process.env['DEBUG'],
    stderr: true,
  });
  patcher.patch();

  try {
    if (config.command === 'sandbox-exec') {
      // disallow BUILD_SANDBOX
      if (process.env['BUILD_SANDBOX']) {
        throw new FatalSandboxError(
          'Cannot BUILD_SANDBOX when using macOS Seatbelt',
        );
      }

      const profile = (process.env['SEATBELT_PROFILE'] ??= 'permissive-open');
      let profileFile = fileURLToPath(
        new URL(`sandbox-macos-${profile}.sb`, import.meta.url),
      );
      // if profile name is not recognized, then look for file under project settings directory
      if (!BUILTIN_SEATBELT_PROFILES.includes(profile)) {
        profileFile = path.join(GEMINI_DIR, `sandbox-macos-${profile}.sb`);
      }
      if (!fs.existsSync(profileFile)) {
        throw new FatalSandboxError(
          `Missing macos seatbelt profile file '${profileFile}'`,
        );
      }
      debugLogger.log(`using macos seatbelt (profile: ${profile}) ...`);
      // if DEBUG is set, convert to --inspect-brk in NODE_OPTIONS
      const nodeOptions = [
        ...(process.env['DEBUG'] ? ['--inspect-brk'] : []),
        ...nodeArgs,
      ].join(' ');

      const args = [
        '-D',
        `TARGET_DIR=${fs.realpathSync(process.cwd())}`,
        '-D',
        `TMP_DIR=${fs.realpathSync(os.tmpdir())}`,
        '-D',
        `HOME_DIR=${fs.realpathSync(homedir())}`,
        '-D',
        `CACHE_DIR=${fs.realpathSync((await execAsync('getconf DARWIN_USER_CACHE_DIR')).stdout.trim())}`,
      ];

      // Add included directories from the workspace context
      // Always add 5 INCLUDE_DIR parameters to ensure .sb files can reference them
      const MAX_INCLUDE_DIRS = 5;
      const targetDir = fs.realpathSync(cliConfig?.getTargetDir() || '');
      const includedDirs: string[] = [];

      if (cliConfig) {
        const workspaceContext = cliConfig.getWorkspaceContext();
        const directories = workspaceContext.getDirectories();

        // Filter out TARGET_DIR
        for (const dir of directories) {
          const realDir = fs.realpathSync(dir);
          if (realDir !== targetDir) {
            includedDirs.push(realDir);
          }
        }
      }

      // Add custom allowed paths from config
      if (config.allowedPaths) {
        for (const hostPath of config.allowedPaths) {
          if (
            hostPath &&
            path.isAbsolute(hostPath) &&
            fs.existsSync(hostPath)
          ) {
            const realDir = fs.realpathSync(hostPath);
            if (!includedDirs.includes(realDir) && realDir !== targetDir) {
              includedDirs.push(realDir);
            }
          }
        }
      }

      for (let i = 0; i < MAX_INCLUDE_DIRS; i++) {
        let dirPath = '/dev/null'; // Default to a safe path that won't cause issues

        if (i < includedDirs.length) {
          dirPath = includedDirs[i];
        }

        args.push('-D', `INCLUDE_DIR_${i}=${dirPath}`);
      }

      const finalArgv = cliArgs;

      args.push(
        '-f',
        profileFile,
        'sh',
        '-c',
        [
          `SANDBOX=sandbox-exec`,
          `NODE_OPTIONS="${nodeOptions}"`,
          ...finalArgv.map((arg) => quote([arg])),
        ].join(' '),
      );
      // start and set up proxy if GEMINI_SANDBOX_PROXY_COMMAND is set
      const proxyCommand = process.env['GEMINI_SANDBOX_PROXY_COMMAND'];
      let proxyProcess: ChildProcess | undefined = undefined;
      let sandboxProcess: ChildProcess | undefined = undefined;
      const sandboxEnv = { ...process.env };
      if (proxyCommand) {
        const proxy =
          process.env['HTTPS_PROXY'] ||
          process.env['https_proxy'] ||
          process.env['HTTP_PROXY'] ||
          process.env['http_proxy'] ||
          'http://localhost:8877';
        sandboxEnv['HTTPS_PROXY'] = proxy;
        sandboxEnv['https_proxy'] = proxy; // lower-case can be required, e.g. for curl
        sandboxEnv['HTTP_PROXY'] = proxy;
        sandboxEnv['http_proxy'] = proxy;
        const noProxy = process.env['NO_PROXY'] || process.env['no_proxy'];
        if (noProxy) {
          sandboxEnv['NO_PROXY'] = noProxy;
          sandboxEnv['no_proxy'] = noProxy;
        }
        proxyProcess = spawn(proxyCommand, {
          stdio: ['ignore', 'pipe', 'pipe'],
          shell: true,
          detached: true,
        });
        // install handlers to stop proxy on exit/signal
        const stopProxy = () => {
          debugLogger.log('stopping proxy ...');
          if (proxyProcess?.pid) {
            process.kill(-proxyProcess.pid, 'SIGTERM');
          }
        };
        process.off('exit', stopProxy);
        process.on('exit', stopProxy);
        process.off('SIGINT', stopProxy);
        process.on('SIGINT', stopProxy);
        process.off('SIGTERM', stopProxy);
        process.on('SIGTERM', stopProxy);

        // commented out as it disrupts ink rendering
        // proxyProcess.stdout?.on('data', (data) => {
        //   console.info(data.toString());
        // });
        proxyProcess.stderr?.on('data', (data) => {
          debugLogger.debug(`[PROXY STDERR]: ${data.toString().trim()}`);
        });
        proxyProcess.on('close', (code, signal) => {
          if (sandboxProcess?.pid) {
            process.kill(-sandboxProcess.pid, 'SIGTERM');
          }
          throw new FatalSandboxError(
            `Proxy command '${proxyCommand}' exited with code ${code}, signal ${signal}`,
          );
        });
        debugLogger.log('waiting for proxy to start ...');
        await execAsync(
          `until timeout 0.25 curl -s http://localhost:8877; do sleep 0.25; done`,
        );
      }
      // spawn child and let it inherit stdio
      process.stdin.pause();
      sandboxProcess = spawn(config.command, args, {
        stdio: 'inherit',
      });
      return await new Promise((resolve, reject) => {
        sandboxProcess?.on('error', reject);
        sandboxProcess?.on('close', (code) => {
          process.stdin.resume();
          resolve(code ?? 1);
        });
      });
    }

    if (config.command === 'lxc') {
      return await start_lxc_sandbox(config, nodeArgs, cliArgs);
    }

    if (config.command === 'macos-container') {
      return await startMacOSContainerSandbox(
        config,
        nodeArgs,
        cliConfig,
        cliArgs,
      );
    }

    if (config.command === 'bwrap') {
      return await startBwrapSandbox(config, nodeArgs, cliConfig, cliArgs);
    }

    if (config.command === 'landlock') {
      return await startLandlockSandbox(config, nodeArgs, cliConfig, cliArgs);
    }

    // runsc uses docker with --runtime=runsc
    const command = config.command === 'runsc' ? 'docker' : config.command;
    if (!command) throw new FatalSandboxError('Sandbox command is required');

    debugLogger.log(`hopping into sandbox (command: ${command}) ...`);

    // determine full path for gemini-cli to distinguish linked vs installed setting
    const gcPath = process.argv[1] ? fs.realpathSync(process.argv[1]) : '';

    const projectSandboxDockerfile = path.join(
      GEMINI_DIR,
      'sandbox.Dockerfile',
    );
    const isCustomProjectSandbox = fs.existsSync(projectSandboxDockerfile);

    const image = config.image;
    if (!image) throw new FatalSandboxError('Sandbox image is required');
    if (!/^[a-zA-Z0-9_.:/-]+$/.test(image))
      throw new FatalSandboxError('Invalid sandbox image name');
    const workdir = path.resolve(process.cwd());
    const containerWorkdir = getContainerPath(workdir);

    // if BUILD_SANDBOX is set, then call scripts/build_sandbox.js under gemini-cli repo
    //
    // note this can only be done with binary linked from gemini-cli repo
    if (process.env['BUILD_SANDBOX']) {
      if (!gcPath.includes('gemini-cli/packages/')) {
        throw new FatalSandboxError(
          'Cannot build sandbox using installed gemini binary; ' +
            'run `npm link ./packages/cli` under gemini-cli repo to switch to linked binary.',
        );
      } else {
        debugLogger.log('building sandbox ...');
        const gcRoot = gcPath.split('/packages/')[0];
        // if project folder has sandbox.Dockerfile under project settings folder, use that
        let buildArgs = '';
        const projectSandboxDockerfile = path.join(
          GEMINI_DIR,
          'sandbox.Dockerfile',
        );
        if (isCustomProjectSandbox) {
          debugLogger.log(`using ${projectSandboxDockerfile} for sandbox`);
          buildArgs += `-f ${path.resolve(projectSandboxDockerfile)} -i ${image}`;
        }
        execSync(
          `cd ${gcRoot} && node scripts/build_sandbox.js -s ${buildArgs}`,
          {
            stdio: 'inherit',
            env: {
              ...process.env,
              GEMINI_SANDBOX: command, // in case sandbox is enabled via flags (see config.ts under cli package)
            },
          },
        );
      }
    }

    // stop if image is missing
    if (!(await ensureSandboxImageIsPresent(command, image, cliConfig))) {
      const remedy =
        image === LOCAL_DEV_SANDBOX_IMAGE_NAME
          ? 'Try running `npm run build:all` or `npm run build:sandbox` under the gemini-cli repo to build it locally, or check the image name and your network connection.'
          : 'Please check the image name, your network connection, or notify gemini-cli-dev@google.com if the issue persists.';
      throw new FatalSandboxError(
        `Sandbox image '${image}' is missing or could not be pulled. ${remedy}`,
      );
    }

    // use interactive mode and auto-remove container on exit
    // run init binary inside container to forward signals & reap zombies
    const args = ['run', '-i', '--rm', '--init', '--workdir', containerWorkdir];

    // add runsc runtime if using runsc
    if (config.command === 'runsc') {
      args.push('--runtime=runsc');
    }

    // add custom flags from SANDBOX_FLAGS
    if (process.env['SANDBOX_FLAGS']) {
      const flags = parse(process.env['SANDBOX_FLAGS'], process.env).filter(
        (f): f is string => typeof f === 'string',
      );

      args.push(...flags);
    }

    // add TTY only if stdin is TTY as well, i.e. for piped input don't init TTY in container
    if (process.stdin.isTTY) {
      args.push('-t');
    }

    // allow access to host.docker.internal
    args.push('--add-host', 'host.docker.internal:host-gateway');

    // mount current directory as working directory in sandbox (set via --workdir)
    args.push('--volume', `${workdir}:${containerWorkdir}`);

    // mount user settings directory inside container, after creating if missing
    // note user/home changes inside sandbox and we mount at BOTH paths for consistency
    const userHomeDirOnHost = homedir();
    const userSettingsDirInSandbox = getContainerPath(
      `/home/node/${GEMINI_DIR}`,
    );
    if (!fs.existsSync(userHomeDirOnHost)) {
      fs.mkdirSync(userHomeDirOnHost, { recursive: true });
    }
    const userSettingsDirOnHost = path.join(userHomeDirOnHost, GEMINI_DIR);
    if (!fs.existsSync(userSettingsDirOnHost)) {
      fs.mkdirSync(userSettingsDirOnHost, { recursive: true });
    }

    args.push(
      '--volume',
      `${userSettingsDirOnHost}:${userSettingsDirInSandbox}`,
    );
    if (userSettingsDirInSandbox !== getContainerPath(userSettingsDirOnHost)) {
      args.push(
        '--volume',
        `${userSettingsDirOnHost}:${getContainerPath(userSettingsDirOnHost)}`,
      );
    }

    // mount os.tmpdir() as os.tmpdir() inside container
    args.push('--volume', `${os.tmpdir()}:${getContainerPath(os.tmpdir())}`);

    // mount homedir() as homedir() inside container
    if (userHomeDirOnHost !== os.homedir()) {
      args.push(
        '--volume',
        `${userHomeDirOnHost}:${getContainerPath(userHomeDirOnHost)}`,
      );
    }

    // mount gcloud config directory if it exists
    const gcloudConfigDir = path.join(homedir(), '.config', 'gcloud');
    if (fs.existsSync(gcloudConfigDir)) {
      args.push(
        '--volume',
        `${gcloudConfigDir}:${getContainerPath(gcloudConfigDir)}:ro`,
      );
    }

    // mount ADC file if GOOGLE_APPLICATION_CREDENTIALS is set
    if (process.env['GOOGLE_APPLICATION_CREDENTIALS']) {
      const adcFile = process.env['GOOGLE_APPLICATION_CREDENTIALS'];
      if (fs.existsSync(adcFile)) {
        args.push('--volume', `${adcFile}:${getContainerPath(adcFile)}:ro`);
        args.push(
          '--env',
          `GOOGLE_APPLICATION_CREDENTIALS=${getContainerPath(adcFile)}`,
        );
      }
    }

    // mount paths listed in SANDBOX_MOUNTS
    if (process.env['SANDBOX_MOUNTS']) {
      for (let mount of process.env['SANDBOX_MOUNTS'].split(',')) {
        if (mount.trim()) {
          // parse mount as from:to:opts
          let [from, to, opts] = mount.trim().split(':');
          to = to || from; // default to mount at same path inside container
          opts = opts || 'ro'; // default to read-only
          mount = `${from}:${to}:${opts}`;
          // check that from path is absolute
          if (!path.isAbsolute(from)) {
            throw new FatalSandboxError(
              `Path '${from}' listed in SANDBOX_MOUNTS must be absolute`,
            );
          }
          // check that from path exists on host
          if (!fs.existsSync(from)) {
            throw new FatalSandboxError(
              `Missing mount path '${from}' listed in SANDBOX_MOUNTS`,
            );
          }
          debugLogger.log(`SANDBOX_MOUNTS: ${from} -> ${to} (${opts})`);
          args.push('--volume', mount);
        }
      }
    }

    // mount paths listed in config.allowedPaths
    if (config.allowedPaths) {
      for (const hostPath of config.allowedPaths) {
        if (hostPath && path.isAbsolute(hostPath) && fs.existsSync(hostPath)) {
          const containerPath = getContainerPath(hostPath);
          debugLogger.log(
            `Config allowedPath: ${hostPath} -> ${containerPath} (ro)`,
          );
          args.push('--volume', `${hostPath}:${containerPath}:ro`);
        }
      }
    }

    // expose env-specified ports on the sandbox
    ports().forEach((p) => args.push('--publish', `${p}:${p}`));

    // if DEBUG is set, expose debugging port
    if (process.env['DEBUG']) {
      const debugPort = process.env['DEBUG_PORT'] || '9229';
      args.push(`--publish`, `${debugPort}:${debugPort}`);
    }

    // copy proxy environment variables, replacing localhost with SANDBOX_PROXY_NAME
    // copy as both upper-case and lower-case as is required by some utilities
    // GEMINI_SANDBOX_PROXY_COMMAND implies HTTPS_PROXY unless HTTP_PROXY is set
    const proxyCommand = process.env['GEMINI_SANDBOX_PROXY_COMMAND'];

    if (proxyCommand) {
      let proxy =
        process.env['HTTPS_PROXY'] ||
        process.env['https_proxy'] ||
        process.env['HTTP_PROXY'] ||
        process.env['http_proxy'] ||
        'http://localhost:8877';
      proxy = proxy.replace('localhost', SANDBOX_PROXY_NAME);
      if (proxy) {
        args.push('--env', `HTTPS_PROXY=${proxy}`);
        args.push('--env', `https_proxy=${proxy}`); // lower-case can be required, e.g. for curl
        args.push('--env', `HTTP_PROXY=${proxy}`);
        args.push('--env', `http_proxy=${proxy}`);
      }
      const noProxy = process.env['NO_PROXY'] || process.env['no_proxy'];
      if (noProxy) {
        args.push('--env', `NO_PROXY=${noProxy}`);
        args.push('--env', `no_proxy=${noProxy}`);
      }
    }

    // handle network access and proxy configuration
    if (!config.networkAccess || proxyCommand) {
      const isInternal = !config.networkAccess || !!proxyCommand;
      const networkFlags = isInternal ? '--internal' : '';

      execSync(
        `${command} network inspect ${SANDBOX_NETWORK_NAME} || ${command} network create ${networkFlags} ${SANDBOX_NETWORK_NAME}`,
        { stdio: 'ignore' },
      );
      args.push('--network', SANDBOX_NETWORK_NAME);

      if (proxyCommand) {
        // if proxy command is set, create a separate network w/ host access (i.e. non-internal)
        // we will run proxy in its own container connected to both host network and internal network
        // this allows proxy to work even on rootless podman on macos with host<->vm<->container isolation
        execSync(
          `${command} network inspect ${SANDBOX_PROXY_NAME} || ${command} network create ${SANDBOX_PROXY_NAME}`,
          { stdio: 'ignore' },
        );
      }
    }

    // name container after image, plus random suffix to avoid conflicts
    const imageName = parseImageName(image);
    const isIntegrationTest =
      process.env['GEMINI_CLI_INTEGRATION_TEST'] === 'true';
    let containerName;
    if (isIntegrationTest) {
      containerName = `gemini-cli-integration-test-${randomBytes(4).toString(
        'hex',
      )}`;
      debugLogger.log(`ContainerName: ${containerName}`);
    } else {
      let index = 0;
      const containerNameCheck = (
        await execAsync(`${command} ps -a --format "{{.Names}}"`)
      ).stdout.trim();
      while (containerNameCheck.includes(`${imageName}-${index}`)) {
        index++;
      }
      containerName = `${imageName}-${index}`;
      debugLogger.log(`ContainerName (regular): ${containerName}`);
    }
    args.push('--name', containerName, '--hostname', containerName);

    // Forward integration test env vars into the container
    for (const testVar of [
      'GEMINI_CLI_TEST_VAR',
      'GEMINI_CLI_INTEGRATION_TEST',
    ]) {
      if (process.env[testVar]) {
        args.push('--env', `${testVar}=${process.env[testVar]}`);
      }
    }

    // copy GEMINI_API_KEY(s)
    if (process.env['GEMINI_API_KEY']) {
      args.push('--env', `GEMINI_API_KEY=${process.env['GEMINI_API_KEY']}`);
    }
    if (process.env['GOOGLE_API_KEY']) {
      args.push('--env', `GOOGLE_API_KEY=${process.env['GOOGLE_API_KEY']}`);
    }

    // copy GOOGLE_GEMINI_BASE_URL and GOOGLE_VERTEX_BASE_URL
    // Set SANDBOX env var to docker or podman
    args.push('--env', `SANDBOX=${config.command}`);

    if (process.env['GOOGLE_GEMINI_BASE_URL']) {
      args.push(
        '--env',
        `GOOGLE_GEMINI_BASE_URL=${process.env['GOOGLE_GEMINI_BASE_URL']}`,
      );
    }
    if (process.env['GOOGLE_VERTEX_BASE_URL']) {
      args.push(
        '--env',
        `GOOGLE_VERTEX_BASE_URL=${process.env['GOOGLE_VERTEX_BASE_URL']}`,
      );
    }

    // copy GOOGLE_GENAI_USE_VERTEXAI
    if (process.env['GOOGLE_GENAI_USE_VERTEXAI']) {
      args.push(
        '--env',
        `GOOGLE_GENAI_USE_VERTEXAI=${process.env['GOOGLE_GENAI_USE_VERTEXAI']}`,
      );
    }

    // copy GOOGLE_GENAI_USE_GCA
    if (process.env['GOOGLE_GENAI_USE_GCA']) {
      args.push(
        '--env',
        `GOOGLE_GENAI_USE_GCA=${process.env['GOOGLE_GENAI_USE_GCA']}`,
      );
    }

    // copy GOOGLE_CLOUD_PROJECT
    if (process.env['GOOGLE_CLOUD_PROJECT']) {
      args.push(
        '--env',
        `GOOGLE_CLOUD_PROJECT=${process.env['GOOGLE_CLOUD_PROJECT']}`,
      );
    }

    // copy GOOGLE_CLOUD_LOCATION
    if (process.env['GOOGLE_CLOUD_LOCATION']) {
      args.push(
        '--env',
        `GOOGLE_CLOUD_LOCATION=${process.env['GOOGLE_CLOUD_LOCATION']}`,
      );
    }

    // copy GEMINI_MODEL
    if (process.env['GEMINI_MODEL']) {
      args.push('--env', `GEMINI_MODEL=${process.env['GEMINI_MODEL']}`);
    }

    // copy TERM and COLORTERM to try to maintain terminal setup
    if (process.env['TERM']) {
      args.push('--env', `TERM=${process.env['TERM']}`);
    }
    if (process.env['COLORTERM']) {
      args.push('--env', `COLORTERM=${process.env['COLORTERM']}`);
    }

    // Pass through IDE mode environment variables
    for (const envVar of [
      'GEMINI_CLI_IDE_SERVER_PORT',
      'GEMINI_CLI_IDE_WORKSPACE_PATH',
      'TERM_PROGRAM',
    ]) {
      if (process.env[envVar]) {
        args.push('--env', `${envVar}=${process.env[envVar]}`);
      }
    }

    // copy VIRTUAL_ENV if under working directory
    // also mount-replace VIRTUAL_ENV directory with <project_settings>/sandbox.venv
    // sandbox can then set up this new VIRTUAL_ENV directory using sandbox.bashrc (see below)
    // directory will be empty if not set up, which is still preferable to having host binaries
    if (
      process.env['VIRTUAL_ENV']
        ?.toLowerCase()
        .startsWith(workdir.toLowerCase())
    ) {
      const sandboxVenvPath = path.resolve(GEMINI_DIR, 'sandbox.venv');
      if (!fs.existsSync(sandboxVenvPath)) {
        fs.mkdirSync(sandboxVenvPath, { recursive: true });
      }
      args.push(
        '--volume',
        `${sandboxVenvPath}:${getContainerPath(process.env['VIRTUAL_ENV'])}`,
      );
      args.push(
        '--env',
        `VIRTUAL_ENV=${getContainerPath(process.env['VIRTUAL_ENV'])}`,
      );
    }

    // copy additional environment variables from SANDBOX_ENV
    if (process.env['SANDBOX_ENV']) {
      for (let env of process.env['SANDBOX_ENV'].split(',')) {
        if ((env = env.trim())) {
          if (env.includes('=')) {
            debugLogger.log(`SANDBOX_ENV: ${env}`);
            args.push('--env', env);
          } else {
            throw new FatalSandboxError(
              'SANDBOX_ENV must be a comma-separated list of key=value pairs',
            );
          }
        }
      }
    }

    // copy NODE_OPTIONS
    const existingNodeOptions = process.env['NODE_OPTIONS'] || '';
    const allNodeOptions = [
      ...(existingNodeOptions ? [existingNodeOptions] : []),
      ...nodeArgs,
    ].join(' ');

    if (allNodeOptions.length > 0) {
      args.push('--env', `NODE_OPTIONS="${allNodeOptions}"`);
    }

    // set SANDBOX as container name
    args.push('--env', `SANDBOX=${containerName}`);

    // for podman only, use empty --authfile to skip unnecessary auth refresh overhead
    if (command === 'podman') {
      const emptyAuthFilePath = path.join(os.tmpdir(), 'empty_auth.json');
      fs.writeFileSync(emptyAuthFilePath, '{}', 'utf-8');
      args.push('--authfile', emptyAuthFilePath);
    }

    // Determine if the current user's UID/GID should be passed to the sandbox.
    // See shouldUseCurrentUserInSandbox for more details.
    let userFlag = '';
    const finalEntrypoint = entrypoint(workdir, cliArgs);

    if (process.env['GEMINI_CLI_INTEGRATION_TEST'] === 'true') {
      args.push('--user', 'root');
      userFlag = '--user root';
    } else if (await shouldUseCurrentUserInSandbox()) {
      // For the user-creation logic to work, the container must start as root.
      // The entrypoint script then handles dropping privileges to the correct user.
      args.push('--user', 'root');

      const uid = (await execAsync('id -u')).stdout.trim();
      const gid = (await execAsync('id -g')).stdout.trim();

      // Instead of passing --user to the main sandbox container, we let it
      // start as root, then create a user with the host's UID/GID, and
      // finally switch to that user to run the gemini process. This is
      // necessary on Linux to ensure the user exists within the
      // container's /etc/passwd file, which is required by os.userInfo().
      const username = 'gemini';
      const homeDir = getContainerPath(homedir());

      const setupUserCommands = [
        // Use -f with groupadd to avoid errors if the group already exists.
        `groupadd -f -g ${gid} ${username}`,
        // Create user only if it doesn't exist. Use -o for non-unique UID.
        `id -u ${username} &>/dev/null || useradd -o -u ${uid} -g ${gid} -d ${homeDir} -s /bin/bash ${username}`,
      ].join(' && ');

      const originalCommand = finalEntrypoint[2];
      const escapedOriginalCommand = originalCommand.replace(/'/g, "'\\''");

      // Use `su -p` to preserve the environment.
      const suCommand = `su -p ${username} -c '${escapedOriginalCommand}'`;

      // The entrypoint is always `['bash', '-c', '<command>']`, so we modify the command part.
      finalEntrypoint[2] = `${setupUserCommands} && ${suCommand}`;

      // We still need userFlag for the simpler proxy container, which does not have this issue.
      userFlag = `--user ${uid}:${gid}`;
      // When forcing a UID in the sandbox, $HOME can be reset to '/', so we copy $HOME as well.
      args.push('--env', `HOME=${homedir()}`);
    }

    // push container image name
    args.push(image);

    // push container entrypoint (including args)
    args.push(...finalEntrypoint);

    // start and set up proxy if GEMINI_SANDBOX_PROXY_COMMAND is set
    let proxyProcess: ChildProcess | undefined = undefined;
    let sandboxProcess: ChildProcess | undefined = undefined;

    if (proxyCommand) {
      // run proxyCommand in its own container
      // build args array to prevent command injection
      const proxyContainerArgs = [
        'run',
        '--rm',
        '--init',
        ...(userFlag ? userFlag.split(' ') : []),
        '--name',
        SANDBOX_PROXY_NAME,
        '--network',
        SANDBOX_PROXY_NAME,
        '-p',
        '8877:8877',
        '-v',
        `${process.cwd()}:${workdir}`,
        '--workdir',
        workdir,
        image,
        // proxyCommand may be a shell string, so parse it into tokens safely
        ...parse(proxyCommand, process.env).filter(
          (f): f is string => typeof f === 'string',
        ),
      ];

      proxyProcess = spawn(command, proxyContainerArgs, {
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false, // <-- no shell; args are passed directly
        detached: true,
      });
      // install handlers to stop proxy on exit/signal
      const stopProxy = () => {
        debugLogger.log('stopping proxy container ...');
        execSync(`${command} rm -f ${SANDBOX_PROXY_NAME}`);
      };
      process.off('exit', stopProxy);
      process.on('exit', stopProxy);
      process.off('SIGINT', stopProxy);
      process.on('SIGINT', stopProxy);
      process.off('SIGTERM', stopProxy);
      process.on('SIGTERM', stopProxy);

      // commented out as it disrupts ink rendering
      // proxyProcess.stdout?.on('data', (data) => {
      //   console.info(data.toString());
      // });
      proxyProcess.stderr?.on('data', (data) => {
        debugLogger.debug(`[PROXY STDERR]: ${data.toString().trim()}`);
      });
      proxyProcess.on('close', (code, signal) => {
        if (sandboxProcess?.pid) {
          process.kill(-sandboxProcess.pid, 'SIGTERM');
        }
        throw new FatalSandboxError(
          `Proxy container command '${command} ${proxyContainerArgs.join(' ')}' exited with code ${code}, signal ${signal}`,
        );
      });
      debugLogger.log('waiting for proxy to start ...');
      await execAsync(
        `until timeout 0.25 curl -s http://localhost:8877; do sleep 0.25; done`,
      );
      // connect proxy container to sandbox network
      // (workaround for older versions of docker that don't support multiple --network args)
      await execAsync(
        `${command} network connect ${SANDBOX_NETWORK_NAME} ${SANDBOX_PROXY_NAME}`,
      );
    }

    // spawn child and let it inherit stdio
    process.stdin.pause();
    sandboxProcess = spawn(command, args, {
      stdio: 'inherit',
    });

    return await new Promise<number>((resolve, reject) => {
      sandboxProcess.on('error', (err) => {
        coreEvents.emitFeedback('error', 'Sandbox process error', err);
        reject(err);
      });

      sandboxProcess?.on('close', (code, signal) => {
        process.stdin.resume();
        if (code !== 0 && code !== null) {
          debugLogger.log(
            `Sandbox process exited with code: ${code}, signal: ${signal}`,
          );
        }
        resolve(code ?? 1);
      });
    });
  } finally {
    patcher.cleanup();
  }
}

// Helper function to start a sandbox using LXC/LXD.
// Unlike Docker/Podman, LXC does not launch a transient container from an
// image. The user creates and manages their own LXC container; Gemini runs
// inside it via `lxc exec`. The container name is stored in config.image
// (default: "gemini-sandbox"). The workspace is bind-mounted into the
// container at the same absolute path.
async function start_lxc_sandbox(
  config: SandboxConfig,
  nodeArgs: string[] = [],
  cliArgs: string[] = [],
): Promise<number> {
  const containerName = config.image || 'gemini-sandbox';
  const workdir = path.resolve(process.cwd());

  debugLogger.log(
    `starting lxc sandbox (container: ${containerName}, workdir: ${workdir}) ...`,
  );

  // Verify the container exists and is running.
  let listOutput: string;
  try {
    const { stdout } = await execFileAsync('lxc', [
      'list',
      containerName,
      '--format=json',
    ]);
    listOutput = stdout.trim();
  } catch (err) {
    throw new FatalSandboxError(
      `Failed to query LXC container '${containerName}': ${err instanceof Error ? err.message : String(err)}. ` +
        `Make sure LXC/LXD is installed and '${containerName}' container exists. ` +
        `Create one with: lxc launch ubuntu:24.04 ${containerName}`,
    );
  }

  let containers: Array<{ name: string; status: string }> = [];
  try {
    const parsed: unknown = JSON.parse(listOutput);
    if (Array.isArray(parsed)) {
      containers = parsed
        .filter(
          (item): item is Record<string, unknown> =>
            item !== null &&
            typeof item === 'object' &&
            'name' in item &&
            'status' in item,
        )
        .map((item) => ({
          name: String(item['name']),
          status: String(item['status']),
        }));
    }
  } catch {
    containers = [];
  }

  const container = containers.find((c) => c.name === containerName);
  if (!container) {
    throw new FatalSandboxError(
      `LXC container '${containerName}' not found. ` +
        `Create one with: lxc launch ubuntu:24.04 ${containerName}`,
    );
  }
  if (container.status.toLowerCase() !== 'running') {
    throw new FatalSandboxError(
      `LXC container '${containerName}' is not running (current status: ${container.status}). ` +
        `Start it with: lxc start ${containerName}`,
    );
  }

  const devicesToRemove: string[] = [];
  const removeDevices = () => {
    for (const deviceName of devicesToRemove) {
      try {
        spawnSync(
          'lxc',
          ['config', 'device', 'remove', containerName, deviceName],
          { timeout: 1000, killSignal: 'SIGKILL', stdio: 'ignore' },
        );
      } catch {
        // Best-effort cleanup; ignore errors on exit.
      }
    }
  };

  try {
    // Bind-mount the working directory into the container at the same path.
    // Using "lxc config device add" is idempotent when the device name matches.
    const workspaceDeviceName = `gemini-workspace-${randomBytes(4).toString(
      'hex',
    )}`;
    devicesToRemove.push(workspaceDeviceName);

    try {
      await execFileAsync('lxc', [
        'config',
        'device',
        'add',
        containerName,
        workspaceDeviceName,
        'disk',
        `source=${workdir}`,
        `path=${workdir}`,
      ]);
      debugLogger.log(
        `mounted workspace '${workdir}' into container as device '${workspaceDeviceName}'`,
      );
    } catch (err) {
      throw new FatalSandboxError(
        `Failed to mount workspace into LXC container '${containerName}': ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    // Add custom allowed paths from config
    if (config.allowedPaths) {
      for (const hostPath of config.allowedPaths) {
        if (hostPath && path.isAbsolute(hostPath) && fs.existsSync(hostPath)) {
          const allowedDeviceName = `gemini-allowed-${randomBytes(4).toString(
            'hex',
          )}`;
          devicesToRemove.push(allowedDeviceName);
          try {
            await execFileAsync('lxc', [
              'config',
              'device',
              'add',
              containerName,
              allowedDeviceName,
              'disk',
              `source=${hostPath}`,
              `path=${hostPath}`,
              'readonly=true',
            ]);
            debugLogger.log(
              `mounted allowed path '${hostPath}' into container as device '${allowedDeviceName}' (ro)`,
            );
          } catch (err) {
            debugLogger.warn(
              `Failed to mount allowed path '${hostPath}' into LXC container: ${err instanceof Error ? err.message : String(err)}`,
            );
          }
        }
      }
    }

    // Remove the devices from the container when the process exits.
    // Only the 'exit' event is needed — the CLI's cleanup.ts already handles
    // SIGINT and SIGTERM by calling process.exit(), which fires 'exit'.
    process.on('exit', removeDevices);

    // Build the environment variable arguments for `lxc exec`.
    const envArgs: string[] = [];
    const envVarsToForward: Record<string, string | undefined> = {
      GEMINI_API_KEY: process.env['GEMINI_API_KEY'],
      GOOGLE_API_KEY: process.env['GOOGLE_API_KEY'],
      GOOGLE_GEMINI_BASE_URL: process.env['GOOGLE_GEMINI_BASE_URL'],
      GOOGLE_VERTEX_BASE_URL: process.env['GOOGLE_VERTEX_BASE_URL'],
      GOOGLE_GENAI_USE_VERTEXAI: process.env['GOOGLE_GENAI_USE_VERTEXAI'],
      GOOGLE_GENAI_USE_GCA: process.env['GOOGLE_GENAI_USE_GCA'],
      GOOGLE_CLOUD_PROJECT: process.env['GOOGLE_CLOUD_PROJECT'],
      GOOGLE_CLOUD_LOCATION: process.env['GOOGLE_CLOUD_LOCATION'],
      GEMINI_MODEL: process.env['GEMINI_MODEL'],
      TERM: process.env['TERM'],
      COLORTERM: process.env['COLORTERM'],
      GEMINI_CLI_IDE_SERVER_PORT: process.env['GEMINI_CLI_IDE_SERVER_PORT'],
      GEMINI_CLI_IDE_WORKSPACE_PATH:
        process.env['GEMINI_CLI_IDE_WORKSPACE_PATH'],
      TERM_PROGRAM: process.env['TERM_PROGRAM'],
    };
    for (const [key, value] of Object.entries(envVarsToForward)) {
      if (value) {
        envArgs.push('--env', `${key}=${value}`);
      }
    }

    // Forward SANDBOX_ENV key=value pairs
    if (process.env['SANDBOX_ENV']) {
      for (let env of process.env['SANDBOX_ENV'].split(',')) {
        if ((env = env.trim())) {
          if (env.includes('=')) {
            envArgs.push('--env', env);
          } else {
            throw new FatalSandboxError(
              'SANDBOX_ENV must be a comma-separated list of key=value pairs',
            );
          }
        }
      }
    }

    // Forward NODE_OPTIONS (e.g. from --inspect flags)
    const existingNodeOptions = process.env['NODE_OPTIONS'] || '';
    const allNodeOptions = [
      ...(existingNodeOptions ? [existingNodeOptions] : []),
      ...nodeArgs,
    ].join(' ');
    if (allNodeOptions.length > 0) {
      envArgs.push('--env', `NODE_OPTIONS=${allNodeOptions}`);
    }

    // Mark that we're running inside an LXC sandbox.
    envArgs.push('--env', `SANDBOX=${containerName}`);

    // Build the command entrypoint (same logic as Docker path).
    const finalEntrypoint = entrypoint(workdir, cliArgs);

    // Build the full lxc exec command args.
    const args = [
      'exec',
      containerName,
      '--cwd',
      workdir,
      ...envArgs,
      '--',
      ...finalEntrypoint,
    ];

    debugLogger.log(`lxc exec args: ${args.join(' ')}`);

    process.stdin.pause();
    const sandboxProcess = spawn('lxc', args, {
      stdio: 'inherit',
    });

    return await new Promise<number>((resolve, reject) => {
      sandboxProcess.on('error', (err) => {
        coreEvents.emitFeedback('error', 'LXC sandbox process error', err);
        reject(err);
      });

      sandboxProcess.on('close', (code, signal) => {
        process.stdin.resume();
        if (code !== 0 && code !== null) {
          debugLogger.log(
            `LXC sandbox process exited with code: ${code}, signal: ${signal}`,
          );
        }
        resolve(code ?? 1);
      });
    });
  } finally {
    process.off('exit', removeDevices);
    removeDevices();
  }
}

// Helper functions to ensure sandbox image is present
async function imageExists(sandbox: string, image: string): Promise<boolean> {
  return new Promise((resolve) => {
    const args = ['images', '-q', image];
    const checkProcess = spawn(sandbox, args);

    let stdoutData = '';
    if (checkProcess.stdout) {
      checkProcess.stdout.on('data', (data) => {
        stdoutData += data.toString();
      });
    }

    checkProcess.on('error', (err) => {
      debugLogger.warn(
        `Failed to start '${sandbox}' command for image check: ${err.message}`,
      );
      resolve(false);
    });

    checkProcess.on('close', (code) => {
      // Non-zero code might indicate docker daemon not running, etc.
      // The primary success indicator is non-empty stdoutData.
      if (code !== 0) {
        // console.warn(`'${sandbox} images -q ${image}' exited with code ${code}.`);
      }
      resolve(stdoutData.trim() !== '');
    });
  });
}

async function pullImage(
  sandbox: string,
  image: string,
  cliConfig?: Config,
): Promise<boolean> {
  debugLogger.debug(`Attempting to pull image ${image} using ${sandbox}...`);
  return new Promise((resolve) => {
    const args = ['pull', image];
    const pullProcess = spawn(sandbox, args, { stdio: 'pipe' });

    let stderrData = '';

    const onStdoutData = (data: Buffer) => {
      if (cliConfig?.getDebugMode() || process.env['DEBUG']) {
        debugLogger.log(data.toString().trim()); // Show pull progress
      }
    };

    const onStderrData = (data: Buffer) => {
      stderrData += data.toString();
      // eslint-disable-next-line no-console
      console.error(data.toString().trim()); // Show pull errors/info from the command itself
    };

    const onError = (err: Error) => {
      debugLogger.warn(
        `Failed to start '${sandbox} pull ${image}' command: ${err.message}`,
      );
      cleanup();
      resolve(false);
    };

    const onClose = (code: number | null) => {
      if (code === 0) {
        debugLogger.log(`Successfully pulled image ${image}.`);
        cleanup();
        resolve(true);
      } else {
        debugLogger.warn(
          `Failed to pull image ${image}. '${sandbox} pull ${image}' exited with code ${code}.`,
        );
        if (stderrData.trim()) {
          // Details already printed by the stderr listener above
        }
        cleanup();
        resolve(false);
      }
    };

    const cleanup = () => {
      if (pullProcess.stdout) {
        pullProcess.stdout.removeListener('data', onStdoutData);
      }
      if (pullProcess.stderr) {
        pullProcess.stderr.removeListener('data', onStderrData);
      }
      pullProcess.removeListener('error', onError);
      pullProcess.removeListener('close', onClose);
      if (pullProcess.connected) {
        pullProcess.disconnect();
      }
    };

    if (pullProcess.stdout) {
      pullProcess.stdout.on('data', onStdoutData);
    }
    if (pullProcess.stderr) {
      pullProcess.stderr.on('data', onStderrData);
    }
    pullProcess.on('error', onError);
    pullProcess.on('close', onClose);
  });
}

async function ensureSandboxImageIsPresent(
  sandbox: string,
  image: string,
  cliConfig?: Config,
): Promise<boolean> {
  debugLogger.log(`Checking for sandbox image: ${image}`);
  if (await imageExists(sandbox, image)) {
    debugLogger.log(`Sandbox image ${image} found locally.`);
    return true;
  }

  debugLogger.log(`Sandbox image ${image} not found locally.`);
  if (image === LOCAL_DEV_SANDBOX_IMAGE_NAME) {
    // user needs to build the image themselves
    return false;
  }

  if (await pullImage(sandbox, image, cliConfig)) {
    // After attempting to pull, check again to be certain
    if (await imageExists(sandbox, image)) {
      debugLogger.log(`Sandbox image ${image} is now available after pulling.`);
      return true;
    } else {
      debugLogger.warn(
        `Sandbox image ${image} still not found after a pull attempt. This might indicate an issue with the image name or registry, or the pull command reported success but failed to make the image available.`,
      );
      return false;
    }
  }

  coreEvents.emitFeedback(
    'error',
    `Failed to obtain sandbox image ${image} after check and pull attempt.`,
  );
  return false; // Pull command failed or image still not present
}

// --- macOS Container Framework support ---

async function ensureMacOSContainerSystemReady(): Promise<void> {
  try {
    await execAsync('container system status', { timeout: 10000 });
  } catch {
    throw new FatalSandboxError(
      'macOS Container system is not running.\n' +
        'Ensure the container CLI is installed: https://github.com/apple/container\n' +
        'Start it with: container system start',
    );
  }
}

async function macOSContainerImageExists(image: string): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('container', ['image', 'list', '-q']);
    let stdout = '';
    proc.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
    });
    proc.on('error', () => resolve(false));
    proc.on('close', (code) => {
      if (code !== 0) {
        resolve(false);
        return;
      }
      // Check if any line in the output matches the image reference
      const lines = stdout.trim().split('\n');
      resolve(lines.some((line) => line.trim() === image));
    });
  });
}

async function macOSContainerPullImage(
  image: string,
  cliConfig?: Config,
): Promise<boolean> {
  debugLogger.log(`Pulling macOS Container image: ${image}...`);
  return new Promise((resolve) => {
    const pullProcess = spawn('container', ['image', 'pull', image], {
      stdio: 'pipe',
    });

    pullProcess.stdout?.on('data', (data: Buffer) => {
      if (cliConfig?.getDebugMode() || process.env['DEBUG']) {
        debugLogger.log(data.toString().trim());
      }
    });
    pullProcess.stderr?.on('data', (data: Buffer) => {
      // eslint-disable-next-line no-console
      console.error(data.toString().trim());
    });
    pullProcess.on('error', (err) => {
      debugLogger.warn(`Failed to pull image: ${err.message}`);
      resolve(false);
    });
    pullProcess.on('close', (code) => {
      if (code === 0) {
        debugLogger.log(`Successfully pulled image ${image}.`);
        resolve(true);
      } else {
        debugLogger.warn(`Failed to pull image ${image} (exit code ${code}).`);
        resolve(false);
      }
    });
  });
}

async function ensureMacOSContainerImage(
  image: string,
  cliConfig?: Config,
): Promise<boolean> {
  debugLogger.log(`Checking for macOS Container image: ${image}`);
  if (await macOSContainerImageExists(image)) {
    debugLogger.log(`macOS Container image ${image} found locally.`);
    return true;
  }

  debugLogger.log(`macOS Container image ${image} not found locally.`);
  if (image === LOCAL_DEV_SANDBOX_IMAGE_NAME) {
    return false;
  }

  if (await macOSContainerPullImage(image, cliConfig)) {
    return true;
  }

  coreEvents.emitFeedback(
    'error',
    `Failed to obtain macOS Container image ${image}.`,
  );
  return false;
}

/**
 * Returns the set of architectures available for the given image
 * by running `container image inspect` and parsing the JSON output.
 * Returns null on any failure so callers can fall back gracefully.
 */
export async function macOSContainerImageArch(
  image: string,
): Promise<Set<string> | null> {
  try {
    const { stdout } = await execAsync(
      `container image inspect ${image} --format json`,
    );
    const data: unknown = JSON.parse(stdout);

    // The inspect output may be an object or an array of objects.
    // Each object may have a top-level "Architecture" field, or
    // a "Manifests" array with per-platform entries.
    const items: unknown[] = Array.isArray(data) ? data : [data];
    const archs = new Set<string>();

    for (const item of items) {
      if (typeof item !== 'object' || item === null) continue;

      // Single-arch image: top-level Architecture field
      if ('Architecture' in item && typeof item.Architecture === 'string') {
        archs.add(item.Architecture);
      }
      // Multi-arch manifest list
      if ('Manifests' in item && Array.isArray(item.Manifests)) {
        const manifests: unknown[] = item.Manifests;
        for (const m of manifests) {
          if (typeof m !== 'object' || m === null) continue;
          const platform =
            ('Platform' in m ? m.Platform : undefined) ??
            ('platform' in m ? m.platform : undefined);
          if (typeof platform !== 'object' || platform === null) continue;
          const arch =
            ('Architecture' in platform ? platform.Architecture : undefined) ??
            ('architecture' in platform ? platform.architecture : undefined);
          if (typeof arch === 'string') {
            archs.add(arch);
          }
        }
      }
    }

    if (archs.size === 0) {
      return null;
    }
    return archs;
  } catch {
    debugLogger.warn(`Failed to inspect image arch for ${image}`);
    return null;
  }
}

async function startMacOSContainerSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig?: Config,
  cliArgs: string[] = [],
): Promise<number> {
  debugLogger.log('hopping into macOS Container sandbox...');

  if (process.env['BUILD_SANDBOX']) {
    throw new FatalSandboxError(
      'Cannot BUILD_SANDBOX when using macOS Container. ' +
        'Build the image using Docker, then push it to a registry.',
    );
  }

  await ensureMacOSContainerSystemReady();

  const image = config.image;
  if (!image)
    throw new FatalSandboxError('macOS Container sandbox requires an image');
  const workdir = path.resolve(process.cwd());

  if (!(await ensureMacOSContainerImage(image, cliConfig))) {
    const remedy =
      image === LOCAL_DEV_SANDBOX_IMAGE_NAME
        ? 'Try building the image with Docker first, then push it to a registry accessible by the container CLI.'
        : 'Please check the image name and your network connection.';
    throw new FatalSandboxError(
      `macOS Container image '${image}' could not be obtained. ${remedy}`,
    );
  }

  const args: string[] = ['run', '-i', '--rm', '--workdir', workdir];

  // Custom flags from SANDBOX_FLAGS
  if (process.env['SANDBOX_FLAGS']) {
    const flags = parse(process.env['SANDBOX_FLAGS'], process.env).filter(
      (f): f is string => typeof f === 'string',
    );
    args.push(...flags);
  }

  // TTY if stdin is TTY
  if (process.stdin.isTTY) {
    args.push('-t');
  }

  // Determine Rosetta / arch flags based on image architectures.
  // arm64-native images need no extra flags; amd64-only images need
  // --rosetta --arch amd64; on detection failure fall back to --rosetta.
  const imageArchs = await macOSContainerImageArch(image);
  if (imageArchs === null) {
    // Detection failed — let the container CLI decide
    debugLogger.log('Image arch detection failed, falling back to --rosetta');
    args.push('--rosetta');
  } else if (imageArchs.has('arm64') || imageArchs.has('aarch64')) {
    debugLogger.log('Image has arm64 variant, running natively');
  } else {
    debugLogger.log('Image is amd64-only, using --rosetta --arch amd64');
    args.push('--rosetta', '--arch', 'amd64');
  }

  // Mount working directory
  args.push('--volume', `${workdir}:${workdir}`);

  // Mount settings directory
  const userHomeDirOnHost = homedir();
  const userSettingsDirOnHost = path.join(userHomeDirOnHost, GEMINI_DIR);
  if (!fs.existsSync(userSettingsDirOnHost)) {
    fs.mkdirSync(userSettingsDirOnHost, { recursive: true });
  }
  args.push('--volume', `${userSettingsDirOnHost}:${userSettingsDirOnHost}`);

  // Mount tmp directory
  args.push('--volume', `${os.tmpdir()}:${os.tmpdir()}`);

  // Mount home directory
  args.push('--volume', `${userHomeDirOnHost}:${userHomeDirOnHost}`);

  // Mount gcloud config if exists
  const gcloudConfigDir = path.join(homedir(), '.config', 'gcloud');
  if (fs.existsSync(gcloudConfigDir)) {
    args.push('--volume', `${gcloudConfigDir}:${gcloudConfigDir}`);
  }

  // Mount ADC file if set
  if (process.env['GOOGLE_APPLICATION_CREDENTIALS']) {
    const adcFile = process.env['GOOGLE_APPLICATION_CREDENTIALS'];
    if (fs.existsSync(adcFile)) {
      args.push('--volume', `${adcFile}:${adcFile}`);
      args.push('-e', `GOOGLE_APPLICATION_CREDENTIALS=${adcFile}`);
    }
  }

  // Custom mounts from SANDBOX_MOUNTS
  if (process.env['SANDBOX_MOUNTS']) {
    for (let mount of process.env['SANDBOX_MOUNTS'].split(',')) {
      if (mount.trim()) {
        let [from, to, opts] = mount.trim().split(':');
        to = to || from;
        opts = opts || 'ro';
        mount = `${from}:${to}:${opts}`;
        if (!path.isAbsolute(from)) {
          throw new FatalSandboxError(
            `Path '${from}' listed in SANDBOX_MOUNTS must be absolute`,
          );
        }
        if (!fs.existsSync(from)) {
          throw new FatalSandboxError(
            `Missing mount path '${from}' listed in SANDBOX_MOUNTS`,
          );
        }
        debugLogger.log(`SANDBOX_MOUNTS: ${from} -> ${to} (${opts})`);
        args.push('--volume', mount);
      }
    }
  }

  // Port forwarding
  ports().forEach((p) => args.push('--publish', `${p}:${p}`));

  // Debug port
  if (process.env['DEBUG']) {
    const debugPort = process.env['DEBUG_PORT'] || '9229';
    args.push('--publish', `${debugPort}:${debugPort}`);
  }

  // Container name
  const containerName = `gemini-sandbox-${randomBytes(4).toString('hex')}`;
  args.push('--name', containerName);

  // Forward integration test env vars
  for (const testVar of [
    'GEMINI_CLI_TEST_VAR',
    'GEMINI_CLI_INTEGRATION_TEST',
  ]) {
    if (process.env[testVar]) {
      args.push('-e', `${testVar}=${process.env[testVar]}`);
    }
  }
  if (process.env['GEMINI_API_KEY']) {
    args.push('-e', `GEMINI_API_KEY=${process.env['GEMINI_API_KEY']}`);
  }
  if (process.env['GOOGLE_API_KEY']) {
    args.push('-e', `GOOGLE_API_KEY=${process.env['GOOGLE_API_KEY']}`);
  }
  if (process.env['GOOGLE_GEMINI_BASE_URL']) {
    args.push(
      '-e',
      `GOOGLE_GEMINI_BASE_URL=${process.env['GOOGLE_GEMINI_BASE_URL']}`,
    );
  }
  if (process.env['GOOGLE_VERTEX_BASE_URL']) {
    args.push(
      '-e',
      `GOOGLE_VERTEX_BASE_URL=${process.env['GOOGLE_VERTEX_BASE_URL']}`,
    );
  }
  if (process.env['GOOGLE_GENAI_USE_VERTEXAI']) {
    args.push(
      '-e',
      `GOOGLE_GENAI_USE_VERTEXAI=${process.env['GOOGLE_GENAI_USE_VERTEXAI']}`,
    );
  }
  if (process.env['GOOGLE_GENAI_USE_GCA']) {
    args.push(
      '-e',
      `GOOGLE_GENAI_USE_GCA=${process.env['GOOGLE_GENAI_USE_GCA']}`,
    );
  }
  if (process.env['GOOGLE_CLOUD_PROJECT']) {
    args.push(
      '-e',
      `GOOGLE_CLOUD_PROJECT=${process.env['GOOGLE_CLOUD_PROJECT']}`,
    );
  }
  if (process.env['GOOGLE_CLOUD_LOCATION']) {
    args.push(
      '-e',
      `GOOGLE_CLOUD_LOCATION=${process.env['GOOGLE_CLOUD_LOCATION']}`,
    );
  }
  if (process.env['GEMINI_MODEL']) {
    args.push('-e', `GEMINI_MODEL=${process.env['GEMINI_MODEL']}`);
  }
  if (process.env['TERM']) {
    args.push('-e', `TERM=${process.env['TERM']}`);
  }
  if (process.env['COLORTERM']) {
    args.push('-e', `COLORTERM=${process.env['COLORTERM']}`);
  }

  // IDE mode variables
  for (const envVar of [
    'GEMINI_CLI_IDE_SERVER_PORT',
    'GEMINI_CLI_IDE_WORKSPACE_PATH',
    'TERM_PROGRAM',
  ]) {
    if (process.env[envVar]) {
      args.push('-e', `${envVar}=${process.env[envVar]}`);
    }
  }

  // VIRTUAL_ENV if under working directory
  if (
    process.env['VIRTUAL_ENV']?.toLowerCase().startsWith(workdir.toLowerCase())
  ) {
    const sandboxVenvPath = path.resolve(GEMINI_DIR, 'sandbox.venv');
    if (!fs.existsSync(sandboxVenvPath)) {
      fs.mkdirSync(sandboxVenvPath, { recursive: true });
    }
    args.push('--volume', `${sandboxVenvPath}:${process.env['VIRTUAL_ENV']}`);
    args.push('-e', `VIRTUAL_ENV=${process.env['VIRTUAL_ENV']}`);
  }

  // Custom env from SANDBOX_ENV
  if (process.env['SANDBOX_ENV']) {
    for (let env of process.env['SANDBOX_ENV'].split(',')) {
      if ((env = env.trim())) {
        if (env.includes('=')) {
          debugLogger.log(`SANDBOX_ENV: ${env}`);
          args.push('-e', env);
        } else {
          throw new FatalSandboxError(
            'SANDBOX_ENV must be a comma-separated list of key=value pairs',
          );
        }
      }
    }
  }

  // NODE_OPTIONS
  const existingNodeOptions = process.env['NODE_OPTIONS'] || '';
  const allNodeOptions = [
    ...(existingNodeOptions ? [existingNodeOptions] : []),
    ...nodeArgs,
  ].join(' ');
  if (allNodeOptions.length > 0) {
    args.push('-e', `NODE_OPTIONS="${allNodeOptions}"`);
  }

  // SANDBOX env var
  args.push('-e', 'SANDBOX=macos-container');

  // Proxy support (host-side proxy, like Seatbelt)
  const proxyCommand = process.env['GEMINI_SANDBOX_PROXY_COMMAND'];
  let proxyProcess: ChildProcess | undefined;

  if (proxyCommand) {
    const proxy =
      process.env['HTTPS_PROXY'] ||
      process.env['https_proxy'] ||
      process.env['HTTP_PROXY'] ||
      process.env['http_proxy'] ||
      'http://localhost:8877';
    args.push('-e', `HTTPS_PROXY=${proxy}`);
    args.push('-e', `https_proxy=${proxy}`);
    args.push('-e', `HTTP_PROXY=${proxy}`);
    args.push('-e', `http_proxy=${proxy}`);
    const noProxy = process.env['NO_PROXY'] || process.env['no_proxy'];
    if (noProxy) {
      args.push('-e', `NO_PROXY=${noProxy}`);
      args.push('-e', `no_proxy=${noProxy}`);
    }
    proxyProcess = spawn(proxyCommand, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: true,
      detached: true,
    });
    const stopProxy = () => {
      debugLogger.log('stopping proxy...');
      if (proxyProcess?.pid) {
        process.kill(-proxyProcess.pid, 'SIGTERM');
      }
    };
    process.off('exit', stopProxy);
    process.on('exit', stopProxy);
    process.off('SIGINT', stopProxy);
    process.on('SIGINT', stopProxy);
    process.off('SIGTERM', stopProxy);
    process.on('SIGTERM', stopProxy);
    proxyProcess.stderr?.on('data', (data) => {
      debugLogger.debug(`[PROXY STDERR]: ${data.toString().trim()}`);
    });
    debugLogger.log('waiting for proxy to start...');
    await execAsync(
      'until timeout 0.25 curl -s http://localhost:8877; do sleep 0.25; done',
    );
  }

  // Image
  args.push(image);

  // Entrypoint
  const finalEntrypoint = entrypoint(workdir, cliArgs);
  args.push(...finalEntrypoint);

  // Spawn
  process.stdin.pause();
  const sandboxProcess = spawn('container', args, {
    stdio: 'inherit',
  });

  // Register proxy close handler after sandbox is spawned
  if (proxyProcess) {
    proxyProcess.on('close', (code, signal) => {
      if (sandboxProcess.pid) {
        process.kill(-sandboxProcess.pid, 'SIGTERM');
      }
      throw new FatalSandboxError(
        `Proxy command '${proxyCommand}' exited with code ${code}, signal ${signal}`,
      );
    });
  }

  return new Promise((resolve, reject) => {
    sandboxProcess.on('error', (err) => {
      coreEvents.emitFeedback(
        'error',
        'macOS Container sandbox process error',
        err,
      );
      reject(err);
    });
    sandboxProcess.on('close', (code, signal) => {
      process.stdin.resume();
      if (code !== 0 && code !== null) {
        debugLogger.log(
          `macOS Container sandbox exited with code: ${code}, signal: ${signal}`,
        );
      }
      resolve(code ?? 1);
    });
  });
}

async function startBwrapSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig?: Config,
  cliArgs: string[] = [],
): Promise<number> {
  debugLogger.log('hopping into bubblewrap sandbox...');

  if (process.env['BUILD_SANDBOX']) {
    throw new FatalSandboxError('Cannot BUILD_SANDBOX when using Bubblewrap');
  }

  const profileName = process.env['BWRAP_PROFILE'] ?? DEFAULT_BWRAP_PROFILE;
  const workdir = path.resolve(process.cwd());
  const home = homedir();
  const tmp = os.tmpdir();

  // Warn on WSL when workspace is under /mnt/ (Windows-mounted filesystem)
  if (isWSL() && workdir.startsWith('/mnt/')) {
    debugLogger.warn(
      `Workspace is under /mnt/ (Windows filesystem). ` +
        `Bwrap bind mounts may have permission issues with NTFS paths. ` +
        `For best results, use a Linux filesystem path (e.g. /home/${os.userInfo().username}/...).`,
    );
  }

  // Allow custom profiles from project settings
  let profile;
  if (BUILTIN_BWRAP_PROFILES.includes(profileName)) {
    profile = buildBwrapProfile(profileName, workdir, home, tmp);
  } else {
    // Look for a custom profile file under .gemini/bwrap-profiles/
    throw new FatalSandboxError(
      `Unknown bwrap profile '${profileName}'. ` +
        `Available profiles: ${BUILTIN_BWRAP_PROFILES.join(', ')}`,
    );
  }

  debugLogger.log(`using bubblewrap (profile: ${profileName}) ...`);

  // Prepare seccomp filter (disabled with BWRAP_SECCOMP=off)
  const seccomp = prepareSeccompFd();
  if (seccomp) {
    debugLogger.log('seccomp filter enabled');
  }

  const args: string[] = [
    // Namespace isolation
    '--unshare-user',
    '--uid',
    String(process.getuid?.() ?? 1000),
    '--gid',
    String(process.getgid?.() ?? 1000),
    '--unshare-pid',
    '--new-session',
    '--die-with-parent',

    // Basic system mounts
    '--dev',
    '/dev',
    '--proc',
    '/proc',
    '--tmpfs',
    '/run',
  ];

  // Seccomp filter via fd 3
  if (seccomp) {
    args.push('--seccomp', '3');
  }

  // Network isolation
  if (!profile.shareNetwork) {
    args.push('--unshare-net');
  }

  // Read-only system binds
  for (const bind of profile.roBinds) {
    if (fs.existsSync(bind)) {
      args.push('--ro-bind', bind, bind);
    }
  }

  // Read-write binds
  for (const bind of profile.rwBinds) {
    if (!fs.existsSync(bind)) {
      fs.mkdirSync(bind, { recursive: true });
    }
    args.push('--bind', bind, bind);
  }

  // Ensure the CLI entry script directory is accessible inside the sandbox.
  // When run from a project checkout (e.g. /home/runner/work/gemini-cli/bundle/)
  // this path isn't covered by system dirs or the workdir.
  if (cliArgs.length >= 2 && fs.existsSync(cliArgs[1])) {
    const scriptDir = path.dirname(fs.realpathSync(cliArgs[1]));
    const allBinds = [...profile.roBinds, ...profile.rwBinds];
    if (
      !allBinds.some((b) => scriptDir === b || scriptDir.startsWith(b + '/'))
    ) {
      args.push('--ro-bind', scriptDir, scriptDir);
    }
  }

  // Working directory
  args.push('--chdir', workdir);

  // Core environment variables
  args.push('--setenv', 'SANDBOX', 'bwrap');
  args.push('--setenv', 'HOME', home);

  if (process.env['PATH']) {
    args.push('--setenv', 'PATH', process.env['PATH']);
  }

  // Forward relevant environment variables
  const envVarsToForward = [
    'GEMINI_API_KEY',
    'GOOGLE_API_KEY',
    'GOOGLE_GEMINI_BASE_URL',
    'GOOGLE_VERTEX_BASE_URL',
    'GOOGLE_GENAI_USE_VERTEXAI',
    'GOOGLE_GENAI_USE_GCA',
    'GOOGLE_CLOUD_PROJECT',
    'GOOGLE_CLOUD_LOCATION',
    'GEMINI_MODEL',
    'TERM',
    'COLORTERM',
    'GEMINI_CLI_IDE_SERVER_PORT',
    'GEMINI_CLI_IDE_WORKSPACE_PATH',
    'TERM_PROGRAM',
    'GEMINI_CLI_TEST_VAR',
    'GEMINI_CLI_INTEGRATION_TEST',
    'GOOGLE_APPLICATION_CREDENTIALS',
  ];

  for (const envVar of envVarsToForward) {
    if (process.env[envVar]) {
      args.push('--setenv', envVar, process.env[envVar]);
    }
  }

  // Custom env from SANDBOX_ENV
  if (process.env['SANDBOX_ENV']) {
    for (let env of process.env['SANDBOX_ENV'].split(',')) {
      if ((env = env.trim())) {
        if (env.includes('=')) {
          const [key, ...valueParts] = env.split('=');
          args.push('--setenv', key, valueParts.join('='));
        } else {
          throw new FatalSandboxError(
            'SANDBOX_ENV must be a comma-separated list of key=value pairs',
          );
        }
      }
    }
  }

  // NODE_OPTIONS
  const existingNodeOptions = process.env['NODE_OPTIONS'] || '';
  const allNodeOptions = [
    ...(process.env['DEBUG'] ? ['--inspect-brk'] : []),
    ...(existingNodeOptions ? [existingNodeOptions] : []),
    ...nodeArgs,
  ].join(' ');
  if (allNodeOptions.length > 0) {
    args.push('--setenv', 'NODE_OPTIONS', allNodeOptions);
  }

  // Proxy support (host-side, like Seatbelt)
  const proxyCommand = process.env['GEMINI_SANDBOX_PROXY_COMMAND'];
  let proxyProcess: ChildProcess | undefined;

  if (proxyCommand) {
    const proxy =
      process.env['HTTPS_PROXY'] ||
      process.env['https_proxy'] ||
      process.env['HTTP_PROXY'] ||
      process.env['http_proxy'] ||
      'http://localhost:8877';
    args.push('--setenv', 'HTTPS_PROXY', proxy);
    args.push('--setenv', 'https_proxy', proxy);
    args.push('--setenv', 'HTTP_PROXY', proxy);
    args.push('--setenv', 'http_proxy', proxy);
    const noProxy = process.env['NO_PROXY'] || process.env['no_proxy'];
    if (noProxy) {
      args.push('--setenv', 'NO_PROXY', noProxy);
      args.push('--setenv', 'no_proxy', noProxy);
    }

    proxyProcess = spawn(proxyCommand, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: true,
      detached: true,
    });
    const stopProxy = () => {
      debugLogger.log('stopping proxy...');
      if (proxyProcess?.pid) {
        process.kill(-proxyProcess.pid, 'SIGTERM');
      }
    };
    process.off('exit', stopProxy);
    process.on('exit', stopProxy);
    process.off('SIGINT', stopProxy);
    process.on('SIGINT', stopProxy);
    process.off('SIGTERM', stopProxy);
    process.on('SIGTERM', stopProxy);
    proxyProcess.stderr?.on('data', (data) => {
      debugLogger.debug(`[PROXY STDERR]: ${data.toString().trim()}`);
    });
    debugLogger.log('waiting for proxy to start...');
    await execAsync(
      'until timeout 0.25 curl -s http://localhost:8877; do sleep 0.25; done',
    );
  }

  // The command to run inside bwrap
  args.push('--', ...cliArgs);

  // Spawn bwrap (pass seccomp filter as fd 3 if enabled)
  process.stdin.pause();
  const stdio: Array<'inherit' | number> = ['inherit', 'inherit', 'inherit'];
  if (seccomp) {
    stdio.push(seccomp.fd);
  }
  const sandboxProcess = spawn('bwrap', args, { stdio });

  // Register proxy close handler after sandbox is spawned
  if (proxyProcess) {
    proxyProcess.on('close', (code, signal) => {
      if (sandboxProcess.pid) {
        process.kill(-sandboxProcess.pid, 'SIGTERM');
      }
      throw new FatalSandboxError(
        `Proxy command '${proxyCommand}' exited with code ${code}, signal ${signal}`,
      );
    });
  }

  return new Promise((resolve, reject) => {
    sandboxProcess.on('error', (err) => {
      coreEvents.emitFeedback('error', 'Bubblewrap sandbox process error', err);
      reject(err);
    });
    sandboxProcess.on('close', (code, signal) => {
      process.stdin.resume();
      if (seccomp) {
        cleanupSeccomp(seccomp);
      }
      if (code !== 0 && code !== null) {
        debugLogger.log(
          `Bubblewrap sandbox exited with code: ${code}, signal: ${signal}`,
        );
      }
      resolve(code ?? 1);
    });
  });
}

async function startLandlockSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig?: Config,
  cliArgs: string[] = [],
): Promise<number> {
  debugLogger.log('hopping into landlock sandbox...');

  if (process.env['BUILD_SANDBOX']) {
    throw new FatalSandboxError('Cannot BUILD_SANDBOX when using Landlock');
  }

  const profileName = process.env['LANDLOCK_PROFILE'] ?? 'permissive';
  const workdir = path.resolve(process.cwd());
  const home = homedir();
  const tmp = os.tmpdir();

  // Warn on WSL when workspace is under /mnt/ (Windows-mounted filesystem)
  if (isWSL() && workdir.startsWith('/mnt/')) {
    debugLogger.warn(
      `Workspace is under /mnt/ (Windows filesystem). ` +
        `Landlock rules may have permission issues with NTFS paths. ` +
        `For best results, use a Linux filesystem path (e.g. /home/${os.userInfo().username}/...).`,
    );
  }

  let profile;
  if (BUILTIN_LANDLOCK_PROFILES.includes(profileName)) {
    profile = buildLandlockProfile(profileName, workdir, home, tmp);
  } else {
    throw new FatalSandboxError(
      `Unknown landlock profile '${profileName}'. ` +
        `Available profiles: ${BUILTIN_LANDLOCK_PROFILES.join(', ')}`,
    );
  }

  debugLogger.log(`using landlock (profile: ${profileName}) ...`);

  // Prepare seccomp filter if enabled
  const seccomp = profile.useSeccomp ? prepareSeccompFile() : null;
  if (seccomp) {
    debugLogger.log('seccomp filter enabled');
  }

  // Ensure read-write paths exist
  for (const p of profile.rwPaths) {
    if (!fs.existsSync(p)) {
      fs.mkdirSync(p, { recursive: true });
    }
  }

  // Ensure the CLI entry script directory is accessible inside the sandbox
  const allAccessPaths = [
    ...profile.rxPaths,
    ...profile.rwPaths,
    ...profile.roPaths,
  ];
  if (cliArgs.length >= 2 && fs.existsSync(cliArgs[1])) {
    const scriptDir = path.dirname(fs.realpathSync(cliArgs[1]));
    if (
      !allAccessPaths.some(
        (p) => scriptDir === p || scriptDir.startsWith(p + '/'),
      )
    ) {
      profile.rxPaths.push(scriptDir);
    }
  }

  // Proxy support (host-side, like bwrap/seatbelt)
  const proxyCommand = process.env['GEMINI_SANDBOX_PROXY_COMMAND'];
  let proxyProcess: ChildProcess | undefined;

  if (proxyCommand) {
    proxyProcess = spawn(proxyCommand, {
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: true,
      detached: true,
    });
    const stopProxy = () => {
      debugLogger.log('stopping proxy...');
      if (proxyProcess?.pid) {
        process.kill(-proxyProcess.pid, 'SIGTERM');
      }
    };
    process.off('exit', stopProxy);
    process.on('exit', stopProxy);
    process.off('SIGINT', stopProxy);
    process.on('SIGINT', stopProxy);
    process.off('SIGTERM', stopProxy);
    process.on('SIGTERM', stopProxy);
    proxyProcess.stderr?.on('data', (data) => {
      debugLogger.debug(`[PROXY STDERR]: ${data.toString().trim()}`);
    });
    debugLogger.log('waiting for proxy to start...');
    await execAsync(
      'until timeout 0.25 curl -s http://localhost:8877; do sleep 0.25; done',
    );
  }

  // Environment: Landlock doesn't use namespaces, so env is inherited naturally.
  // Set SANDBOX=landlock and forward proxy env vars.
  const sandboxEnv: Record<string, string | undefined> = {
    ...process.env,
    SANDBOX: 'landlock',
  };

  if (proxyCommand) {
    const proxy =
      process.env['HTTPS_PROXY'] ||
      process.env['https_proxy'] ||
      process.env['HTTP_PROXY'] ||
      process.env['http_proxy'] ||
      'http://localhost:8877';
    sandboxEnv['HTTPS_PROXY'] = proxy;
    sandboxEnv['https_proxy'] = proxy;
    sandboxEnv['HTTP_PROXY'] = proxy;
    sandboxEnv['http_proxy'] = proxy;
    const noProxy = process.env['NO_PROXY'] || process.env['no_proxy'];
    if (noProxy) {
      sandboxEnv['NO_PROXY'] = noProxy;
      sandboxEnv['no_proxy'] = noProxy;
    }
  }

  // Custom env from SANDBOX_ENV
  if (process.env['SANDBOX_ENV']) {
    for (let env of process.env['SANDBOX_ENV'].split(',')) {
      if ((env = env.trim())) {
        if (env.includes('=')) {
          const [key, ...valueParts] = env.split('=');
          sandboxEnv[key] = valueParts.join('=');
          debugLogger.log(`SANDBOX_ENV: ${key}=${sandboxEnv[key]}`);
        } else {
          throw new FatalSandboxError(
            'SANDBOX_ENV must be a comma-separated list of key=value pairs',
          );
        }
      }
    }
  }

  // Filter PATH to only include directories accessible inside the sandbox.
  // Landlock returns EACCES for non-allowed paths (unlike bwrap which returns
  // ENOENT for non-mounted paths). Some execvp implementations record EACCES
  // from early PATH entries and return it even if a later entry succeeds,
  // causing "spawn bash EACCES" failures.
  const allowedBasePaths = [
    ...profile.rxPaths,
    ...profile.rwPaths,
    ...profile.roPaths,
  ];
  if (sandboxEnv['PATH']) {
    sandboxEnv['PATH'] = sandboxEnv['PATH']
      .split(':')
      .filter((dir) =>
        allowedBasePaths.some((p) => dir === p || dir.startsWith(p + '/')),
      )
      .join(':');
  }

  // NODE_OPTIONS
  const existingNodeOptions = process.env['NODE_OPTIONS'] || '';
  const allNodeOptions = [
    ...(process.env['DEBUG'] ? ['--inspect-brk'] : []),
    ...(existingNodeOptions ? [existingNodeOptions] : []),
    ...nodeArgs,
  ].join(' ');
  if (allNodeOptions.length > 0) {
    sandboxEnv['NODE_OPTIONS'] = allNodeOptions;
  }

  // Apply Landlock sandbox to the current process using native module
  try {
    const landlock = await import('@google/gemini-cli-landlock');
    const { applyLandlock } = landlock.default || landlock;
    applyLandlock({
      roPaths: profile.roPaths,
      rwPaths: profile.rwPaths,
      rxPaths: profile.rxPaths,
      seccompFilterPath: seccomp?.path,
    });
    debugLogger.log('landlock sandbox applied to current process');
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new FatalSandboxError(`Failed to apply landlock: ${message}`);
  }

  // Now spawn the command (it inherits the sandbox from this process)
  process.stdin.pause();
  const sandboxProcess = spawn(cliArgs[0], cliArgs.slice(1), {
    stdio: 'inherit',
    env: sandboxEnv,
  });

  // Register proxy close handler after sandbox is spawned
  if (proxyProcess) {
    proxyProcess.on('close', (code, signal) => {
      if (sandboxProcess.pid) {
        process.kill(sandboxProcess.pid, 'SIGTERM');
      }
      throw new FatalSandboxError(
        `Proxy command '${proxyCommand}' exited with code ${code}, signal ${signal}`,
      );
    });
  }

  return new Promise((resolve, reject) => {
    sandboxProcess.on('error', (err) => {
      coreEvents.emitFeedback('error', 'Landlock sandbox process error', err);
      reject(err);
    });
    sandboxProcess.on('close', (code, signal) => {
      process.stdin.resume();
      if (seccomp) {
        cleanupSeccompFile(seccomp);
      }
      if (code !== 0 && code !== null) {
        debugLogger.log(
          `Landlock sandbox exited with code: ${code}, signal: ${signal}`,
        );
      }
      resolve(code ?? 1);
    });
  });
}
