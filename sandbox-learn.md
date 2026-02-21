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
  `WSL_DISTRO_NAME`, `container=systemd-nspawn`, and cgroup contents
- When `sandbox: true` and inside an external container, sandboxing is
  automatically skipped (outer container provides isolation)
- Explicit sandbox commands (`GEMINI_SANDBOX=docker`) are still honored inside
  containers
- `GEMINI_SANDBOX=force` overrides the detection and forces auto-detection
  inside the container
- The check runs early in `getSandboxCommand()` before any command validation

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
