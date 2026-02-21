# Sandbox Implementation Learnings

## Apple macOS Container Framework

- The CLI tool is `container` from https://github.com/apple/container (not the
  `containerization` Swift framework)
- CLI syntax is intentionally Docker-like: `-v`, `-e`, `-i`, `-t`, `--rm`,
  `--name`, `--workdir`, `--publish` all work the same
- Key differences from Docker:
  - No `--init` flag (VM handles signal forwarding natively)
  - No `--add-host` (uses `container system dns` instead)
  - Image commands: `container image list`, `container image pull` (not
    `container images -q`)
  - Container listing: `container list -a` (not `docker ps -a`)
  - No `--authfile` (uses macOS Keychain)
  - Networking: each container gets its own VM with dedicated IP; no
    `--internal` network flag
- Requires `container system start` before use (idempotent)
- Apple Silicon only; `--rosetta` flag enables x86_64 emulation
- macOS 15 has limited networking (no container-to-container); full features
  require macOS 26
- One VM per container = true kernel isolation (strongest security model)

## Multi-arch Image Builds

- CI uses `docker buildx build --platform linux/amd64,linux/arm64 --push` to
  produce a multi-arch manifest in one step (can't `docker push` a local
  multi-arch image)
- Requires `docker/setup-qemu-action@v3` for cross-platform emulation in CI
- `build_sandbox.js --pack-only` packs npm tarballs without running docker
  build, so CI can delegate the build to `docker buildx`
- `macOSContainerImageArch()` inspects the image via
  `container image inspect --format json` to determine available architectures
- When the image has an arm64 variant, the container runs natively (no
  `--rosetta`); amd64-only images get `--rosetta --arch amd64`
- On detection failure, falls back to `--rosetta` to let the container CLI
  decide

## Nested Container Detection

- `detectContainerEnvironment()` in `sandboxUtils.ts` checks multiple signals:
  `SANDBOX` env, `/.dockerenv`, `/run/.containerenv`, `KUBERNETES_SERVICE_HOST`,
  `container=systemd-nspawn`, and cgroup contents
- WSL1 is treated as a container (can't sandbox); WSL2 is NOT (real Linux
  kernel)
- When `sandbox: true` and inside an external container, sandboxing is
  automatically skipped (outer container provides isolation)
- Explicit sandbox commands (`GEMINI_SANDBOX=docker`) are still honored inside
  containers
- `GEMINI_SANDBOX=force` overrides the detection and forces auto-detection
  inside the container
- The check runs early in `getSandboxCommand()` before any command validation

## WSL (Windows Subsystem for Linux) Support

- `isWSL()` detects WSL via `WSL_DISTRO_NAME` env or
  `/proc/sys/fs/binfmt_misc/WSLInterop`
- `isWSL2()` distinguishes WSL2 from WSL1 using kernel version: WSL2 uses real
  Linux kernel 5.x+, WSL1 uses NT translation at 4.4.x; the kernel string also
  typically contains "WSL2"
- WSL2 supports bwrap, landlock, and seccomp — all sandbox mechanisms work
- WSL1 cannot support user namespaces, so sandboxing is skipped with a message
- ContainerEnvironmentType uses `'wsl1'` (not `'wsl'`) to be explicit
- Workspaces under `/mnt/` (Windows filesystem) may have NTFS permission issues
  with bwrap bind mounts; a warning is logged recommending Linux filesystem
  paths

## Bubblewrap (bwrap) Sandbox

- Uses Linux namespaces for isolation (user, mount, PID)
- Works on host filesystem with selective bind mounts (no image needed)
- `--ro-bind src dst` for read-only, `--bind src dst` for read-write
- `--dev /dev`, `--proc /proc`, `--tmpfs /run` for basic system mounts
- `--setenv NAME VALUE` for environment variables (not inherited from parent)
- `--die-with-parent` ensures sandbox dies if parent exits
- `--new-session` prevents tty hijacking
- `--chdir dir` sets working directory inside sandbox
- `--` separates bwrap args from command to run
- Uses host-side proxy (like Seatbelt), not container-based (like Docker)
- Profile system: permissive/restrictive/strict × open/proxied (6 profiles)
- cliArgs (process.argv) passed directly after `--` separator

## Codebase Architecture

- `sandbox.ts` `start_sandbox()` routes by `config.command`:
  - `sandbox-exec` → Seatbelt (returns from if block)
  - `macos-container` → macOS Container (returns from if block)
  - `bwrap` → Bubblewrap (returns from if block)
  - Everything else → Docker/Podman (fallthrough)
- `sandboxConfig.ts` handles auto-detection priority and validation
- `sandboxUtils.ts` has availability detection functions
- `bwrapProfiles.ts` has profile definitions and builder
- Seatbelt uses host-side proxy; Docker uses container-based proxy; macOS
  Container and Bubblewrap use host-side proxy (like Seatbelt)
- Test pattern: mock `spawn` with `EventEmitter`, emit `close` with timeout
- `bwrap-seccomp.ts` has BPF seccomp filter generation and fd management

## Seccomp BPF Filters

- BPF seccomp filters are arrays of `sock_filter` structs (8 bytes each,
  little-endian: u16 code, u8 jt, u8 jf, u32 k)
- bwrap's `--seccomp FD` reads raw sock_filter array from the fd
- To pass the filter: write to temp file, `fs.openSync()` for reading, pass fd
  as extra entry in spawn's `stdio` array (position = fd number in child)
- Key BPF opcodes: `0x20` (load word), `0x15` (jump if equal), `0x06` (return)
- Architecture audit values: x86_64 = `0xC000003E`, aarch64 = `0xC00000B7`
- Seccomp returns: ALLOW = `0x7FFF0000`, ERRNO|EPERM = `0x00050001`
- Syscall numbers differ between x86_64 and aarch64; must use correct table
- BWRAP_SECCOMP=off disables the filter for debugging/compatibility

## Native Binary Build & Cleanup

- `landlock-helper` (C binary) is required for Landlock sandbox on Linux
- Build integration:
  - `scripts/build_package.js` detects `packages/cli/native/Makefile` on Linux
  - Runs `make` to compile the binary
  - Copies the artifact to `packages/cli/dist/landlock-helper` so it's included
    in the package
- Cleanup integration:
  - `scripts/clean.js` explicitly removes `packages/cli/native/landlock-helper`
  - Also cleans `packages/cli/dist` via standard cleanup
- `.gitignore` includes `packages/cli/native/landlock-helper` to prevent
  checking in binaries

## Test Environment Sanitization

- The integration test rig (`packages/test-utils/src/test-rig.ts`) actively
  sanitizes environment variables, stripping most `GEMINI_*` variables to ensure
  test isolation.
- This previously caused `GEMINI_SANDBOX` and `GEMINI_TELEMETRY_*` variables to
  be removed, meaning tests were running unsandboxed (default behavior) even
  when configured otherwise in CI.
- **Fix**: The environment variable allowlist in `TestRig` must include
  `GEMINI_SANDBOX`, `GEMINI_TELEMETRY_ENABLED`, and `GEMINI_TELEMETRY_OUTFILE`.
- **Validation**: Added `integration-tests/sandbox-verification.test.ts` to
  explicitly verify that the `SANDBOX` environment variable is present inside
  the executing shell, confirming that the sandbox is active.

## CI / GitHub Actions Testing

### Workflow Structure

- `.github/workflows/test-sandbox.yml` runs a matrix of sandbox legs: bwrap,
  landlock, sandbox-exec, docker (4 legs)
- Each leg runs unit tests + a sandbox verification integration test
- The verification test uses fake API responses (no real `GEMINI_API_KEY`
  needed), but the CLI still validates the key at startup — set
  `GEMINI_API_KEY=fake-key-for-sandbox-test`
- Use `npm run test:integration:sandbox:<mode> -- sandbox-verification.test.ts`
  to run only the verification test per sandbox mode

### macOS Container Cannot Run on GHA

- Apple's `container` CLI requires Virtualization.framework (VZ) for both
  `container build` and `container run`
- GHA macOS ARM64 runners are VMs that don't support nested VZ
  (https://github.com/actions/runner-images/issues/8465)
- `container system start` succeeds (daemon only), but any operation requiring a
  VM fails with `VZErrorDomain Code=2 "Virtualization is not available"`
- Confirmed in CI runs 22261349562 and 22261620762: both `container build` and
  `container run` fail
- macos-container works on bare-metal Apple Silicon — test locally only
- The `sandbox_command.js` and `build_sandbox.js` changes for macos-container
  support are retained for local development

### sandbox_command.js Binary Mapping

- `sandbox_command.js` validates the sandbox binary exists via `command -v`
- `GEMINI_SANDBOX=macos-container` checks for a binary called `macos-container`,
  but the actual binary is `container`
- Fixed with a `binaryForMode` mapping: `{ 'macos-container': 'container' }`
- Other modes (docker, podman, bwrap, sandbox-exec) match their binary names

### build_sandbox.js and container build

- `build_sandbox.js` uses `${sandboxCommand} build ...` for Docker/Podman
- Apple's container CLI uses `container build` (not `container image build`)
  with the same flags (`-t`, `-f`, `--build-arg`)
- Added a `sandboxCommand === 'macos-container'` branch to use `container build`
- Also skip `image prune` for macos-container (not a valid container CLI
  command)
- The npm script `test:integration:sandbox:macos-container` now includes
  `build:sandbox` (matching the docker script)

### bwrap/landlock CLI Entry Script Path

- When running from a project checkout (e.g. CI), the CLI entry script
  (`bundle/gemini.js`) lives outside the standard system dirs and workdir
- bwrap: added `--ro-bind` for the entry script's directory
- landlock: added `--rx` for the entry script's directory
- Without this, the sandbox blocks access to its own entry point

### Landlock CI Setup

- Ubuntu runners have Landlock LSM loaded but `/sys/kernel/security` may not be
  mounted — add `sudo mount -t securityfs securityfs /sys/kernel/security`
- Verify LSM availability by reading `/sys/kernel/security/lsm` and grepping for
  `landlock`
- Build and install `landlock-helper` from `packages/cli/native/` before tests

### bwrap CI Setup

- Ubuntu 24.04 restricts unprivileged user namespaces via AppArmor
- Enable with `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`
- Install bubblewrap: `sudo apt-get install -y bubblewrap`

### Integration Test Verification Approach

- Fake responses don't echo tool output to stdout, so checking for env vars in
  stdout doesn't work
- Use `rig.waitForToolCall('run_shell_command')` to verify the tool was called
  inside the sandbox — this checks telemetry logs, not stdout
