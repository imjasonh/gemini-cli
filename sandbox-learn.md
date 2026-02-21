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

## Codebase Architecture

- `sandbox.ts` `start_sandbox()` routes by `config.command`:
  - `sandbox-exec` → Seatbelt (returns from if block)
  - `macos-container` → macOS Container (returns from if block)
  - Everything else → Docker/Podman (fallthrough)
- `sandboxConfig.ts` handles auto-detection priority and validation
- `sandboxUtils.ts` has availability detection functions
- Seatbelt uses host-side proxy; Docker uses container-based proxy; macOS
  Container uses host-side proxy (like Seatbelt)
- Test pattern: mock `spawn` with `EventEmitter`, emit `close` with timeout
