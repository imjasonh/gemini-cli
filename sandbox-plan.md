# Sandbox Enhancement Plan: Bubblewrap & macOS Container Framework

This document outlines the implementation plan for adding two new sandboxing
options to Gemini CLI:

1. **Bubblewrap (`bwrap`)** - Linux namespace-based sandboxing
2. **macOS Container Framework** - Lightweight Linux VM sandboxing on macOS 15+

## Executive Summary

The current sandboxing options are:

- **macOS**: `sandbox-exec` (Seatbelt) - lightweight but limited to
  process-level restrictions
- **Linux/Cross-platform**: `docker` / `podman` - full container isolation but
  heavier weight

The new options will provide:

- **Linux**: `bwrap` - stronger namespace-based isolation with stricter defaults
- **macOS 15+**: `macos-container` - strict VM-level isolation using Apple's
  Container framework

Both will be opt-in initially, with a phased transition to becoming the
recommended defaults.

## Important: Paradigm Differences

The new sandbox modes represent different security paradigms:

| Mode              | Type                | Environment               | Security Level | Notes                                                                 |
| ----------------- | ------------------- | ------------------------- | -------------- | --------------------------------------------------------------------- |
| `sandbox-exec`    | Process restriction | Native macOS              | Medium         | Seatbelt profiles limit access, but no namespace isolation            |
| `docker`/`podman` | Container isolation | Linux container           | Medium         | Namespaces + seccomp, but **volume mounts expose workspace/settings** |
| `bwrap`           | Namespace isolation | Host Linux + restrictions | Medium-High    | Namespace isolation + seccomp, shares kernel                          |
| `landlock`        | Landlock + seccomp  | Host Linux + restrictions | Medium-High    | Filesystem ACLs + syscall filtering, shares kernel                    |
| `macos-container` | VM isolation        | Linux VM                  | **High**       | Separate kernel; only true strong isolation                           |

**Why Docker/Podman is only "Medium" security:**

- We mount the workspace, `~/.gemini`, temp directories, and gcloud config into
  the container
- These volume mounts give the container access to all the data it could misuse
  anyway
- The real value of Docker is **consistent environment** (reproducible tools),
  not security isolation
- Kernel exploits can still escape to the host (shared kernel)

**Why only VM isolation is "High":**

- macOS Container runs a separate Linux kernel
- Kernel exploits in the VM don't affect the host
- This is the only mode where a compromised sandbox cannot directly attack the
  host kernel

**Key trade-offs users should understand:**

- **`macos-container` runs Linux, not macOS**: macOS-specific tools (`open`,
  `pbcopy`, etc.) won't be available. This provides stronger isolation at the
  cost of native macOS integration.
- **`bwrap` uses host tools**: Unlike Docker's consistent sandbox image, bwrap
  uses whatever is installed on the host system. This is lighter weight but less
  predictable across systems.

These are intentional trade-offs for stronger security. Users who need the old
behavior can explicitly opt back in.

---

## Milestone 1: Core Infrastructure Updates

**Goal**: Update the type system, configuration, and schema to support new
sandbox commands.

### 1.1 Update `SandboxConfig` Type

**File**: `packages/core/src/config/config.ts`

```typescript
export interface SandboxConfig {
  command:
    | 'docker'
    | 'podman'
    | 'sandbox-exec'
    | 'bwrap'
    | 'macos-container'
    | 'landlock';
  image: string;
}
```

### 1.2 Update Settings Schema

**File**: `packages/cli/src/config/settingsSchema.ts`

Update the `sandbox` setting description to document new options:

```typescript
sandbox: {
  type: 'string',
  label: 'Sandbox',
  category: 'Tools',
  requiresRestart: true,
  default: undefined as boolean | string | undefined,
  ref: 'BooleanOrString',
  description: oneLine`
    Sandbox execution environment. Set to true to auto-detect, false to disable,
    or specify: "docker", "podman", "sandbox-exec", "bwrap" (Linux),
    "landlock" (Linux, recommended), or "macos-container" (macOS 15+).
  `,
  showInDialog: false,
},
```

### 1.3 Update Sandbox Config Loader

**File**: `packages/cli/src/config/sandboxConfig.ts`

```typescript
const VALID_SANDBOX_COMMANDS: ReadonlyArray<SandboxConfig['command']> = [
  'docker',
  'podman',
  'sandbox-exec',
  'bwrap',
  'macos-container',
  'landlock',
];
```

Update `getSandboxCommand()` to handle new options:

- Add detection for `bwrap` binary on Linux
- Add detection for Landlock support (kernel 5.13+) on Linux
- Add detection for `container` CLI and macOS version 15+ for `macos-container`
- On Linux with `sandbox: true`, prefer `landlock` if available, fall back to
  `bwrap`, then `docker`
- Maintain backward compatibility with existing auto-detection logic

### 1.4 Update Sandbox Utils

**File**: `packages/cli/src/utils/sandboxUtils.ts`

Add new constants and helper functions:

```typescript
export const BWRAP_PROFILE_DIR = '.gemini/bwrap-profiles';
export const DEFAULT_BWRAP_PROFILE = 'permissive';

export async function isMacOSContainerAvailable(): Promise<boolean> {
  // Check macOS version >= 15 and container CLI exists
}

export async function isBwrapAvailable(): Promise<boolean> {
  // Check bwrap binary exists and user namespaces are enabled
}

export async function isLandlockAvailable(): Promise<boolean> {
  // Check kernel version >= 5.13 and Landlock ABI available
  // Check /sys/kernel/security/landlock exists
}
```

### Deliverables

- [x] Updated TypeScript types in core package
- [x] Updated settings schema with new options
- [x] Updated sandbox config loader with new command validation
- [x] New utility functions for availability detection
- [x] Unit tests for all changes

### Estimated Effort

2-3 days

---

## Milestone 2: macOS Container Framework Integration

**Goal**: Implement `macos-container` sandbox option using Apple's Container
framework.

### 2.1 Understand the `container` CLI

The macOS Container framework provides a `container` CLI tool that can:

- Pull and run OCI-compatible images
- Mount host directories into the Linux VM
- Forward environment variables
- Handle TTY allocation

### 2.2 Implement macOS Container Sandbox

**File**: `packages/cli/src/utils/sandbox.ts`

Add new function `startMacOSContainerSandbox()`:

```typescript
async function startMacOSContainerSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig?: Config,
  cliArgs: string[],
): Promise<number> {
  // 1. Verify macOS 15+ and container CLI availability
  // 2. Build container run arguments:
  //    - Mount working directory
  //    - Mount ~/.gemini settings
  //    - Mount gcloud config (if exists)
  //    - Forward required environment variables
  //    - Set up TTY if available
  // 3. Use the existing Docker sandbox image
  // 4. Spawn container process and return exit code
}
```

Key implementation details:

- Reuse `config.image` (the Docker sandbox image)
- Mirror the volume mounting logic from Docker/Podman implementation
- Handle environment variable forwarding (API keys, proxy settings, etc.)
- Support debug mode with appropriate port forwarding

### 2.3 Update `start_sandbox()` Router

**File**: `packages/cli/src/utils/sandbox.ts`

```typescript
export async function start_sandbox(
  config: SandboxConfig,
  nodeArgs: string[] = [],
  cliConfig?: Config,
  cliArgs: string[] = [],
): Promise<number> {
  if (config.command === 'sandbox-exec') {
    return startSeatbeltSandbox(config, nodeArgs, cliConfig, cliArgs);
  } else if (config.command === 'macos-container') {
    return startMacOSContainerSandbox(config, nodeArgs, cliConfig, cliArgs);
  } else {
    // docker/podman path
    return startContainerSandbox(config, nodeArgs, cliConfig, cliArgs);
  }
}
```

### 2.4 Handle macOS Container Specifics

Research and implement handling for:

- **Rosetta**: If running on Apple Silicon, ensure Rosetta is available for x86
  images
- **Networking**: Container framework networking model (may differ from Docker)
- **File permissions**: UID/GID mapping between host and VM
- **Resource limits**: Memory and CPU constraints if needed

### 2.5 Documentation

**File**: `docs/cli/sandbox.md`

Add section for macOS Container:

```markdown
### 3. macOS Container (macOS 15+ only)

Strict VM-level isolation using Apple's Container framework.

**Requirements**: macOS 15 (Sequoia) or later

**Enable**:

- `gemini --sandbox=macos-container`
- `GEMINI_SANDBOX=macos-container`
- `{"tools": {"sandbox": "macos-container"}}`

**Benefits**:

- Complete VM isolation (stronger than Seatbelt)
- Uses the same sandbox image as Docker/Podman
- Native Apple Silicon support with Rosetta for x86 images
```

### Deliverables

- [x] `startMacOSContainerSandbox()` implementation
- [x] Integration with existing sandbox routing
- [x] macOS version detection utility
- [x] Updated documentation
- [ ] Manual testing on macOS 15+ machine
- [x] Unit tests with mocked `container` CLI

### Estimated Effort

4-5 days

---

## Milestone 3: Bubblewrap Integration (Linux)

**Goal**: Implement `bwrap` sandbox option for Linux systems.

### 3.1 Bubblewrap Overview

Bubblewrap uses Linux namespaces to create isolated environments:

- **User namespace**: Run as unprivileged user
- **Mount namespace**: Restricted filesystem view
- **Network namespace**: Optional network isolation
- **PID namespace**: Isolated process tree

Unlike Docker, bwrap uses the **host filesystem** with selective bind mounts,
similar to Seatbelt on macOS.

### 3.2 Design Bwrap Profiles

Create profile system similar to Seatbelt profiles:

**File**: `packages/cli/src/utils/bwrap-profiles/permissive.ts`

```typescript
export interface BwrapProfile {
  name: string;
  // Directories to bind read-write
  rwBinds: string[];
  // Directories to bind read-only
  roBinds: string[];
  // Whether to allow network access
  shareNetwork: boolean;
  // Additional bwrap flags
  extraFlags: string[];
}

export const permissiveProfile: BwrapProfile = {
  name: 'permissive',
  rwBinds: [
    '${TARGET_DIR}',
    '${TMP_DIR}',
    '${HOME}/.gemini',
    '${HOME}/.npm',
    '${HOME}/.cache',
  ],
  roBinds: [
    '/usr',
    '/lib',
    '/lib64',
    '/bin',
    '/sbin',
    '/etc',
    '${HOME}/.gitconfig',
    '${HOME}/.config/gcloud',
  ],
  shareNetwork: true,
  extraFlags: [],
};
```

Profile variants:

- `permissive` - Write to project dir, network allowed (default)
- `permissive-proxied` - Write to project dir, network via proxy
- `restrictive` - Limited writes, network allowed
- `restrictive-proxied` - Limited writes, network via proxy
- `strict` - Minimal access, network allowed
- `strict-proxied` - Minimal access, network via proxy

### 3.3 Implement Bubblewrap Sandbox

**File**: `packages/cli/src/utils/sandbox.ts`

Add new function `startBwrapSandbox()`:

```typescript
async function startBwrapSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig?: Config,
  cliArgs: string[],
): Promise<number> {
  const profile = process.env['BWRAP_PROFILE'] ?? 'permissive';
  const profileConfig = loadBwrapProfile(profile);

  const args: string[] = [
    // User namespace (unprivileged)
    '--unshare-user',
    '--uid',
    String(process.getuid()),
    '--gid',
    String(process.getgid()),

    // Mount namespace
    '--unshare-mount',

    // PID namespace
    '--unshare-pid',

    // New session
    '--new-session',

    // Die with parent
    '--die-with-parent',
  ];

  // Add read-only system binds
  for (const bind of profileConfig.roBinds) {
    const resolved = resolvePath(bind);
    if (fs.existsSync(resolved)) {
      args.push('--ro-bind', resolved, resolved);
    }
  }

  // Add read-write binds
  for (const bind of profileConfig.rwBinds) {
    const resolved = resolvePath(bind);
    args.push('--bind', resolved, resolved);
  }

  // Network namespace (optional)
  if (!profileConfig.shareNetwork) {
    args.push('--unshare-net');
  }

  // Set working directory
  args.push('--chdir', process.cwd());

  // Set SANDBOX environment variable
  args.push('--setenv', 'SANDBOX', 'bwrap');

  // Add the command to run
  args.push('--', ...cliArgs);

  // Spawn bwrap process
  const child = spawn('bwrap', args, { stdio: 'inherit' });

  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve(code ?? 1));
  });
}
```

### 3.4 Handle Linux-Specific Requirements

- **User namespaces**: Check `/proc/sys/kernel/unprivileged_userns_clone` on
  Debian/Ubuntu
- **Fallback**: If bwrap fails due to namespace restrictions, provide helpful
  error message
- **Dev access**: Bind `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/tty`
- **Proc/sys**: Mount minimal `/proc` and `/sys` as needed

### 3.5 Proxy Support for Bwrap

For `*-proxied` profiles:

```typescript
if (profile.endsWith('-proxied')) {
  // Start proxy process similar to Seatbelt implementation
  const proxyCommand = process.env['GEMINI_SANDBOX_PROXY_COMMAND'];
  // ... proxy setup logic
}
```

### 3.6 Documentation

**File**: `docs/cli/sandbox.md`

Add section for Bubblewrap:

```markdown
### 4. Bubblewrap (Linux only)

Lightweight namespace-based sandboxing using bwrap.

**Requirements**: Linux with user namespace support, `bwrap` binary installed

**Install**:

- Debian/Ubuntu: `sudo apt install bubblewrap`
- Fedora: `sudo dnf install bubblewrap`
- Arch: `sudo pacman -S bubblewrap`

**Enable**:

- `gemini --sandbox=bwrap`
- `GEMINI_SANDBOX=bwrap`
- `{"tools": {"sandbox": "bwrap"}}`

**Profiles** (set via `BWRAP_PROFILE` env var):

- `permissive` (default): Write to project dir, network allowed
- `restrictive`: Limited writes, network allowed
- `strict`: Minimal access

**Benefits**:

- No container runtime required
- Fast startup (no image pull needed)
- Low resource overhead
- Works on systems where Docker isn't available
```

### Deliverables

- [ ] Bwrap profile system implementation
- [ ] `startBwrapSandbox()` implementation
- [ ] Profile definitions (permissive, restrictive, strict variants)
- [ ] Proxy support for bwrap
- [ ] Linux capability detection utilities
- [ ] Updated documentation
- [ ] Unit tests with mocked bwrap binary
- [ ] Integration tests on Linux CI

### Estimated Effort

5-6 days

---

## Milestone 4: Testing Infrastructure

**Goal**: Enable automated testing for all sandbox modes on GitHub Actions.

### 4.1 GitHub Actions Matrix

**File**: `.github/workflows/test-sandbox.yml` (new)

```yaml
name: Sandbox Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test-sandbox-macos:
    runs-on: macos-15 # When available, or macos-latest if 15+
    strategy:
      matrix:
        sandbox: [sandbox-exec, macos-container]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run build
      - name: Test ${{ matrix.sandbox }} sandbox
        run: |
          GEMINI_SANDBOX=${{ matrix.sandbox }} npm run test:sandbox
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}

  test-sandbox-linux:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        sandbox: [docker, bwrap]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install bubblewrap
        if: matrix.sandbox == 'bwrap'
        run: sudo apt-get install -y bubblewrap
      - run: npm ci
      - run: npm run build
      - name: Test ${{ matrix.sandbox }} sandbox
        run: |
          GEMINI_SANDBOX=${{ matrix.sandbox }} npm run test:sandbox
        env:
          GEMINI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
```

### 4.2 Sandbox Integration Tests

**File**: `integration-tests/sandbox.test.ts` (new or extend existing)

```typescript
describe('Sandbox Integration Tests', () => {
  const sandboxCommand = process.env['GEMINI_SANDBOX'];

  it('should run shell commands in sandbox', async () => {
    // Test that commands execute within sandbox
  });

  it('should restrict writes outside project directory', async () => {
    // Test that writes to /tmp or other dirs fail appropriately
  });

  it('should allow reads from system directories', async () => {
    // Test that reading /etc/hosts etc. works
  });

  it('should forward environment variables correctly', async () => {
    // Test GEMINI_API_KEY and other vars are available
  });

  it('should handle network access based on profile', async () => {
    // Test network connectivity
  });
});
```

### 4.3 Unit Tests

Extend existing test files:

**File**: `packages/cli/src/config/sandboxConfig.test.ts`

- Add tests for `bwrap` and `macos-container` command detection
- Add tests for availability checking functions

**File**: `packages/cli/src/utils/sandbox.test.ts`

- Add tests for new sandbox startup functions
- Mock external binaries (`bwrap`, `container`)

### 4.4 CI Runner Requirements

| Sandbox Mode      | CI Runner       | Notes                       |
| ----------------- | --------------- | --------------------------- |
| `sandbox-exec`    | `macos-latest`  | Works on all macOS versions |
| `macos-container` | `macos-15`      | Requires macOS 15+ runner   |
| `docker`          | `ubuntu-latest` | Docker pre-installed        |
| `podman`          | `ubuntu-latest` | Need to install podman      |
| `bwrap`           | `ubuntu-latest` | Need to install bubblewrap  |

**Note**: As of 2024, GitHub Actions `macos-15` runners may not be generally
available. The workflow should gracefully skip `macos-container` tests if the
runner doesn't support it.

### Deliverables

- [ ] New GitHub Actions workflow for sandbox testing
- [ ] Integration test suite for sandbox modes
- [ ] Extended unit tests for new functionality
- [ ] CI matrix covering all sandbox × platform combinations
- [ ] Skip logic for unavailable sandbox modes

### Estimated Effort

3-4 days

---

## Milestone 5: Documentation & Polish

**Goal**: Comprehensive documentation and user experience improvements.

### 5.1 Update Main Sandbox Documentation

**File**: `docs/cli/sandbox.md`

Restructure to cover all five sandbox modes:

1. Overview and comparison table
2. macOS Seatbelt (`sandbox-exec`)
3. macOS Container (`macos-container`) - NEW
4. Docker (`docker`)
5. Podman (`podman`)
6. Bubblewrap (`bwrap`) - NEW
7. Choosing the right sandbox
8. Troubleshooting

### 5.2 Comparison Table

| Feature           | sandbox-exec  | macos-container | docker    | podman    | bwrap         |
| ----------------- | ------------- | --------------- | --------- | --------- | ------------- |
| Platform          | macOS         | macOS 15+       | All       | All       | Linux         |
| Isolation         | Process       | VM              | Container | Container | Namespace     |
| Startup time      | Fast          | Medium          | Medium    | Medium    | Fast          |
| Image required    | No            | Yes             | Yes       | Yes       | No            |
| Network isolation | Profile-based | Yes             | Yes       | Yes       | Profile-based |
| Resource overhead | Low           | Medium          | Medium    | Medium    | Low           |
| Security level    | Medium        | High            | High      | High      | Medium-High   |

### 5.3 Error Messages and Help Text

Improve error messages for common issues:

```typescript
// When bwrap fails due to namespace restrictions
throw new FatalSandboxError(
  'Bubblewrap requires user namespace support. On Ubuntu/Debian, run:\n' +
    '  sudo sysctl kernel.unprivileged_userns_clone=1\n' +
    'Or use Docker/Podman instead: GEMINI_SANDBOX=docker',
);

// When macos-container is unavailable
throw new FatalSandboxError(
  'macOS Container requires macOS 15 (Sequoia) or later.\n' +
    'Your version: ' +
    macOSVersion +
    '\n' +
    'Use Seatbelt instead: GEMINI_SANDBOX=sandbox-exec',
);
```

### 5.4 CLI Help Updates

Update `--sandbox` flag help text to mention new options.

### Deliverables

- [ ] Comprehensive sandbox documentation
- [ ] Comparison table and decision guide
- [ ] Improved error messages
- [ ] Updated CLI help text
- [ ] CHANGELOG entry

### Estimated Effort

2 days

---

## Milestone 6: Phased Transition to Secure Defaults

**Goal**: Gradually transition users to more secure sandbox defaults with clear
communication and opt-out paths.

### 6.1 Positioning Strategy

Frame the new modes as **security upgrades**, not replacements:

- **`macos-container`**: "Strict sandbox mode - maximum isolation via Linux VM"
- **`bwrap`**: "Strict sandbox mode - strong namespace isolation without Docker"

Documentation and messaging should emphasize:

1. These modes provide **stronger security** than current defaults
2. Trade-offs exist (Linux environment on macOS, host tools on Linux)
3. Users can opt out if they need the old behavior
4. The old modes remain available but are **not recommended** for
   security-conscious users

### 6.2 Phased Rollout Timeline

#### Phase 1: Introduction (v1.x - Current)

- New modes available as explicit opt-in
- Documentation highlights security benefits
- No warnings, no behavior changes for existing users

#### Phase 2: Recommendation (v1.x+1)

- First-run prompts ask users if they want to enable strict sandbox mode
- `gemini doctor` recommends upgrading to strict mode
- Settings UI shows "Upgrade to strict sandbox" option
- Documentation positions old modes as "legacy"

#### Phase 3: Soft Warning (v2.0)

- Users on old defaults see periodic warnings:
  ```
  ⚠️  You're using sandbox-exec which provides limited isolation.
      Consider upgrading to macos-container for stronger security.
      Run `gemini config set tools.sandbox macos-container` to upgrade.
      To suppress this warning: `gemini config set tools.sandbox sandbox-exec`
  ```
- Warning appears once per session, max once per day
- Explicit configuration suppresses the warning

#### Phase 4: Default Change (v2.x)

- `sandbox: true` auto-detection prefers new secure modes:
  - macOS 15+: `macos-container` (falls back to `sandbox-exec` if unavailable)
  - macOS <15: `sandbox-exec` (unchanged)
  - Linux: `bwrap` (falls back to `docker` if bwrap unavailable)
- Users who previously had `sandbox: true` see one-time migration notice
- Explicit settings (`sandbox: "sandbox-exec"`) continue to work indefinitely

#### Phase 5: Legacy Mode (v3.0+)

- Old modes remain functional but:
  - Marked as "legacy" in documentation
  - Show occasional security recommendations
  - May not receive new features
- No plans to remove them entirely

### 6.3 User Communication

#### First-Run Experience (Phase 2+)

```
┌─────────────────────────────────────────────────────────────┐
│  🔒 Sandbox Security Upgrade Available                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Gemini CLI can now use stricter sandboxing for better     │
│  security. This runs commands in an isolated Linux VM.      │
│                                                             │
│  Trade-offs:                                                │
│  • macOS-specific tools (open, pbcopy) won't be available  │
│  • Slightly slower startup time                            │
│  • Stronger protection against malicious commands          │
│                                                             │
│  [Enable Strict Mode]  [Keep Current]  [Learn More]        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Migration Notice (Phase 4)

```
ℹ️  Sandbox default changed to macos-container for stronger security.
    Your commands now run in an isolated Linux VM.

    If you need macOS-native tools, you can switch back:
      gemini config set tools.sandbox sandbox-exec

    Learn more: https://github.com/google-gemini/gemini-cli/docs/sandbox
```

### 6.4 Configuration Handling

```typescript
// In sandboxConfig.ts - Phase 4 logic
function getSandboxCommand(
  sandbox?: boolean | string | null,
): SandboxConfig['command'] | '' {
  // Explicit string settings always honored
  if (typeof sandbox === 'string' && isSandboxCommand(sandbox)) {
    return validateAndReturnCommand(sandbox);
  }

  // sandbox: true - use new secure defaults
  if (sandbox === true) {
    if (os.platform() === 'darwin') {
      if (isMacOS15OrLater() && commandExists.sync('container')) {
        showMigrationNoticeIfNeeded('macos-container');
        return 'macos-container';
      }
      return 'sandbox-exec'; // Fallback for older macOS
    } else if (os.platform() === 'linux') {
      if (commandExists.sync('bwrap') && userNamespacesEnabled()) {
        showMigrationNoticeIfNeeded('bwrap');
        return 'bwrap';
      }
      // Fallback to docker/podman
      if (commandExists.sync('docker')) return 'docker';
      if (commandExists.sync('podman')) return 'podman';
    }
  }

  return '';
}

function showMigrationNoticeIfNeeded(newDefault: string): void {
  const noticeShown = readSetting('sandbox.migrationNoticeShown');
  if (!noticeShown) {
    displayMigrationNotice(newDefault);
    writeSetting('sandbox.migrationNoticeShown', true);
  }
}
```

### 6.5 Opt-Out Documentation

Create clear documentation for users who need to opt out:

**File**: `docs/cli/sandbox-migration.md`

```markdown
# Sandbox Migration Guide

## Why are defaults changing?

Gemini CLI is transitioning to more secure sandbox defaults to better protect
your system from potentially harmful commands.

## What's changing?

| Platform  | Old Default  | New Default     | When      |
| --------- | ------------ | --------------- | --------- |
| macOS 15+ | sandbox-exec | macos-container | v2.0      |
| macOS <15 | sandbox-exec | sandbox-exec    | No change |
| Linux     | docker       | bwrap           | v2.0      |

## How to keep the old behavior

If you need macOS-native tools or Docker's consistent environment:

# macOS - keep using Seatbelt

gemini config set tools.sandbox sandbox-exec

# Linux - keep using Docker

gemini config set tools.sandbox docker

## Understanding the trade-offs

### macos-container (new macOS default)

✅ Stronger isolation (full VM) ✅ Protection against kernel exploits ✅
Consistent Linux environment ❌ No macOS-specific tools (open, pbcopy, etc.) ❌
Slightly slower startup ❌ Higher memory usage

### sandbox-exec (old macOS default)

✅ Native macOS environment ✅ Fast startup ✅ Lower resource usage ❌ Weaker
isolation (process-level only) ❌ Potential kernel-level escapes

We recommend macos-container for most users unless you specifically need
macOS-native tool integration.
```

### 6.6 Telemetry & Monitoring (Optional)

Track adoption to inform rollout decisions:

- Percentage of users on each sandbox mode
- Error rates by sandbox mode
- Opt-out rates after migration

### Deliverables

- [ ] Migration notice UI components
- [ ] `showMigrationNoticeIfNeeded()` implementation
- [ ] Warning system for Phase 3
- [ ] First-run prompt for Phase 2
- [ ] `docs/cli/sandbox-migration.md` guide
- [ ] Settings to suppress warnings/track migration
- [ ] CHANGELOG entries for each phase
- [ ] Blog post / announcement for v2.0

### Estimated Effort

- Phase 1: Included in Milestones 1-5
- Phase 2: 2-3 days (prompts, doctor command)
- Phase 3: 1-2 days (warning system)
- Phase 4: 1-2 days (default change, migration notice)
- Phase 5: Documentation only

---

## Implementation Order

```
Week 1:
├── Milestone 1: Core Infrastructure (2-3 days)
└── Milestone 2: macOS Container (start)

Week 2:
├── Milestone 2: macOS Container (complete, 4-5 days total)
└── Milestone 4: Testing for macOS (partial)

Week 3:
├── Milestone 3: Bubblewrap (5-6 days)
└── Milestone 4: Testing for Linux (partial)

Week 4:
├── Milestone 4: Testing Infrastructure (complete, 3-4 days total)
├── Milestone 5: Documentation (2 days)
└── Milestone 6 Phase 1: Release as opt-in

Future Releases:
├── v1.x+1: Milestone 6 Phase 2 (recommendation prompts)
├── v2.0-beta: Milestone 6 Phase 3 (soft warnings)
├── v2.0: Milestone 6 Phase 4 (default change)
└── v3.0+: Milestone 6 Phase 5 (legacy mode)
```

**Total Estimated Effort for Initial Release**: 3-4 weeks **Full Transition
Timeline**: 6-12 months across multiple releases

---

## Risk Assessment

| Risk                                       | Likelihood | Impact | Mitigation                                                                |
| ------------------------------------------ | ---------- | ------ | ------------------------------------------------------------------------- |
| macOS Container API changes                | Low        | High   | Pin to stable API, add version checks                                     |
| GitHub Actions lacks macOS 15 runners      | Medium     | Medium | Skip tests gracefully, test manually                                      |
| Bwrap namespace restrictions on some Linux | Medium     | Low    | Clear error messages, fallback to Docker                                  |
| Performance regressions                    | Low        | Medium | Benchmark before/after, profile startup                                   |
| User confusion about paradigm change       | Medium     | Medium | Clear documentation, migration notices, easy opt-out                      |
| Users frustrated by lost macOS tools       | Medium     | Medium | Prominent warnings during transition, one-command opt-out                 |
| High opt-out rates                         | Low        | Low    | Monitor telemetry, adjust messaging, consider keeping both as "supported" |
| Inconsistent bwrap behavior across distros | Medium     | Medium | Document known issues, test on multiple distros in CI                     |

---

## Success Criteria

### Initial Release (Milestones 1-5)

1. **Functionality**: Both new sandbox modes work correctly on their respective
   platforms
2. **Performance**: Startup time acceptable (document any differences)
3. **Security**: New modes provide measurably stronger isolation
4. **Testing**: Full CI coverage for all sandbox modes
5. **Documentation**: Clear guidance on security trade-offs and when to use each
   mode
6. **Compatibility**: Existing configurations continue to work unchanged

### Transition Success (Milestone 6)

1. **Adoption**: >50% of eligible users on new secure defaults within 6 months
   of v2.0
2. **Opt-out rate**: <20% of users explicitly opt back to legacy modes
3. **Support burden**: No significant increase in sandbox-related issues
4. **User satisfaction**: Positive feedback on security improvements outweighs
   complaints about lost features

---

## Resolved Decisions

1. **Image caching for macOS Container**: The Container framework handles image
   caching natively. No additional implementation needed.

2. **Bwrap on WSL**: Yes, support bwrap on Windows Subsystem for Linux. Add WSL
   detection and testing.

3. **ARM vs x86 images**: The sandbox image must be multi-arch (ARM64 + x86_64).
   Update build pipeline if needed.

4. **Nested sandboxing**: Detect external containers and gracefully skip
   sandboxing (see Milestone 7 below).

5. **Transition timing**: Minimum 2 release cycles for Phase 3 (soft warnings)
   before Phase 4 (default change).

6. **Opt-out friction**: Simple config change is sufficient. No confirmation
   step required.

7. **Feature parity**: Gate new sandbox features to "secure" modes only to
   incentivize adoption. Legacy modes receive maintenance only.

8. **IDE integration**: VS Code companion extension updates required for
   macos-container (see Milestone 8 below).

---

## Milestone 7: Nested Sandboxing Detection

**Goal**: Gracefully handle Gemini CLI running inside existing containers.

### 7.1 Problem Statement

Users may run Gemini CLI inside:

- Docker/Podman containers (CI/CD, dev containers, Codespaces)
- WSL environments
- Other sandboxed environments

Attempting to launch another sandbox from within can fail or behave
unexpectedly.

### 7.2 Detection Strategy

**File**: `packages/cli/src/utils/sandboxUtils.ts`

```typescript
export interface ContainerEnvironment {
  detected: boolean;
  type:
    | 'docker'
    | 'podman'
    | 'kubernetes'
    | 'wsl'
    | 'systemd-nspawn'
    | 'unknown'
    | 'none';
  isGeminiSandbox: boolean; // Our own sandbox
}

export function detectContainerEnvironment(): ContainerEnvironment {
  // Already in Gemini's sandbox
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

  // WSL detection
  if (
    process.env['WSL_DISTRO_NAME'] ||
    fs.existsSync('/proc/sys/fs/binfmt_misc/WSLInterop')
  ) {
    return { detected: true, type: 'wsl', isGeminiSandbox: false };
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
  } catch {}

  return { detected: false, type: 'none', isGeminiSandbox: false };
}
```

### 7.3 Behavior When Nested

**File**: `packages/cli/src/config/sandboxConfig.ts`

```typescript
function getSandboxCommand(
  sandbox?: boolean | string | null,
): SandboxConfig['command'] | '' {
  const containerEnv = detectContainerEnvironment();

  // Already in Gemini's own sandbox - never re-sandbox
  if (containerEnv.isGeminiSandbox) {
    return '';
  }

  // In external container - skip sandboxing unless forced
  if (containerEnv.detected && !containerEnv.isGeminiSandbox) {
    if (process.env['GEMINI_SANDBOX'] === 'force') {
      debugLogger.warn(
        `Forcing sandbox inside ${containerEnv.type} container. This may not work correctly.`,
      );
      // Continue with normal sandbox detection
    } else {
      debugLogger.log(
        `Running inside ${containerEnv.type} container. ` +
          `Sandboxing disabled (outer container provides isolation). ` +
          `Set GEMINI_SANDBOX=force to override.`,
      );
      return '';
    }
  }

  // ... rest of existing logic
}
```

### 7.4 User Feedback

When sandboxing is skipped due to nested environment:

```
ℹ️  Detected Docker container environment. Using container's isolation instead of additional sandboxing.
    To force nested sandboxing: GEMINI_SANDBOX=force gemini
```

### Deliverables

- [ ] `detectContainerEnvironment()` utility function
- [ ] Integration with sandbox config loader
- [ ] Support for `GEMINI_SANDBOX=force` override
- [ ] Unit tests for detection logic
- [ ] Documentation for nested environment behavior

### Estimated Effort

1-2 days

---

## Milestone 8: VS Code Companion Extension Updates

**Goal**: Ensure IDE integration works with macos-container sandbox mode.

### 8.1 Problem Statement

The VS Code companion extension (`packages/vscode-ide-companion`) communicates
with the CLI. When the CLI runs in a Linux VM (macos-container), the
communication path changes:

- Port forwarding between VM and host
- File path translation (macOS paths ↔ Linux paths)
- Potential latency increases

### 8.2 Required Changes

#### 8.2.1 Port Forwarding

**File**: `packages/cli/src/utils/sandbox.ts` (in `startMacOSContainerSandbox`)

```typescript
// Forward IDE server port into the container
if (process.env['GEMINI_CLI_IDE_SERVER_PORT']) {
  const idePort = process.env['GEMINI_CLI_IDE_SERVER_PORT'];
  args.push('--publish', `${idePort}:${idePort}`);
}
```

#### 8.2.2 Path Translation Service

**File**: `packages/cli/src/utils/sandboxPathTranslation.ts` (new)

```typescript
export interface PathTranslator {
  hostToContainer(hostPath: string): string;
  containerToHost(containerPath: string): string;
}

export function createMacOSContainerPathTranslator(
  workdir: string,
  mounts: Map<string, string>,
): PathTranslator {
  return {
    hostToContainer(hostPath: string): string {
      // Translate /Users/... to /workspace/... etc.
      for (const [hostMount, containerMount] of mounts) {
        if (hostPath.startsWith(hostMount)) {
          return hostPath.replace(hostMount, containerMount);
        }
      }
      return hostPath;
    },
    containerToHost(containerPath: string): string {
      // Reverse translation
      for (const [hostMount, containerMount] of mounts) {
        if (containerPath.startsWith(containerMount)) {
          return containerPath.replace(containerMount, hostMount);
        }
      }
      return containerPath;
    },
  };
}
```

#### 8.2.3 Extension Awareness

**File**: `packages/vscode-ide-companion/src/extension.ts`

The extension needs to:

1. Detect when CLI is running in macos-container mode
2. Apply path translations when sending file paths to CLI
3. Apply reverse translations when receiving paths from CLI

### 8.3 Testing

- [ ] Test file editing operations through VS Code with macos-container
- [ ] Test debugging/breakpoints if applicable
- [ ] Test file watching/live reload features
- [ ] Verify no regressions with other sandbox modes

### Deliverables

- [ ] Port forwarding for IDE server in macos-container
- [ ] Path translation utility
- [ ] VS Code extension updates for path handling
- [ ] Integration tests for IDE + macos-container
- [ ] Documentation for IDE users on sandbox mode considerations

### Estimated Effort

3-4 days

---

## Milestone 9: WSL Support for Bubblewrap

**Goal**: Enable bwrap sandboxing on Windows Subsystem for Linux.

### 9.1 WSL-Specific Considerations

- WSL2 supports user namespaces (WSL1 does not)
- File system performance differs (especially for Windows-mounted paths)
- Some syscalls may behave differently

### 9.2 Detection and Compatibility

**File**: `packages/cli/src/utils/sandboxUtils.ts`

```typescript
export async function isBwrapAvailableOnWSL(): Promise<{
  available: boolean;
  reason?: string;
}> {
  // Check if we're in WSL
  if (
    !process.env['WSL_DISTRO_NAME'] &&
    !fs.existsSync('/proc/sys/fs/binfmt_misc/WSLInterop')
  ) {
    return { available: false, reason: 'Not running in WSL' };
  }

  // Check for WSL2 (required for user namespaces)
  try {
    const version = fs.readFileSync('/proc/version', 'utf8');
    if (!version.includes('microsoft') || version.includes('WSL1')) {
      return {
        available: false,
        reason: 'WSL1 does not support user namespaces. Upgrade to WSL2.',
      };
    }
  } catch {}

  // Check bwrap binary
  if (!commandExists.sync('bwrap')) {
    return {
      available: false,
      reason: 'bwrap not installed. Run: sudo apt install bubblewrap',
    };
  }

  return { available: true };
}
```

### 9.3 WSL-Specific Bwrap Configuration

Some adjustments for WSL:

- Avoid binding Windows-mounted paths (`/mnt/c/...`) which have permission
  issues
- Handle the `/init` process differences
- Test with common WSL distros (Ubuntu, Debian)

### 9.4 CI Testing

**File**: `.github/workflows/test-sandbox.yml`

```yaml
test-sandbox-wsl:
  runs-on: windows-latest
  steps:
    - name: Setup WSL
      uses: Vampire/setup-wsl@v2
      with:
        distribution: Ubuntu-22.04
    - name: Install bubblewrap
      shell: wsl-bash {0}
      run: sudo apt-get update && sudo apt-get install -y bubblewrap
    - name: Test bwrap sandbox
      shell: wsl-bash {0}
      run: |
        cd /mnt/d/a/gemini-cli/gemini-cli  # GitHub workspace in WSL
        npm ci && npm run build
        GEMINI_SANDBOX=bwrap npm run test:sandbox
```

### Deliverables

- [ ] WSL detection utilities
- [ ] WSL2 version check
- [ ] WSL-specific bwrap configuration adjustments
- [ ] GitHub Actions WSL testing workflow
- [ ] Documentation for WSL users

### Estimated Effort

2-3 days

---

## Milestone 10: Multi-Architecture Sandbox Image

**Goal**: Ensure the sandbox image works on both ARM64 and x86_64 architectures.

### 10.1 Current State

Check existing sandbox image build process in `scripts/build_sandbox.js` and
`.github/workflows/release-sandbox.yml`.

### 10.2 Required Changes

#### 10.2.1 Multi-arch Build

**File**: `scripts/build_sandbox.js` (update)

```javascript
// Build for multiple architectures
const platforms = ['linux/amd64', 'linux/arm64'];
const buildArgs = [
  'buildx',
  'build',
  '--platform',
  platforms.join(','),
  '--push', // or --load for local testing
  '-t',
  imageName,
  '.',
];
```

#### 10.2.2 GitHub Actions Workflow

**File**: `.github/workflows/release-sandbox.yml` (update)

```yaml
- name: Set up QEMU
  uses: docker/setup-qemu-action@v3

- name: Set up Docker Buildx
  uses: docker/setup-buildx-action@v3

- name: Build and push multi-arch image
  uses: docker/build-push-action@v5
  with:
    platforms: linux/amd64,linux/arm64
    push: true
    tags: ${{ env.IMAGE_NAME }}:${{ env.VERSION }}
```

### 10.3 Testing

- [ ] Test sandbox image on x86_64 Linux
- [ ] Test sandbox image on ARM64 Linux (e.g., Graviton, Apple Silicon via
      Docker)
- [ ] Test macos-container with ARM64 image on Apple Silicon (native)
- [ ] Test macos-container with x86_64 image on Apple Silicon (Rosetta)

### Deliverables

- [ ] Multi-arch build configuration
- [ ] Updated GitHub Actions workflow
- [ ] CI testing on both architectures
- [ ] Documentation noting architecture support

### Estimated Effort

1-2 days

---

## Updated Implementation Order

```
Week 1:
├── Milestone 1: Core Infrastructure (2-3 days)
└── Milestone 2: macOS Container (start)

Week 2:
├── Milestone 2: macOS Container (complete, 4-5 days total)
├── Milestone 7: Nested Sandboxing Detection (1-2 days)
└── Milestone 10: Multi-arch Image (1-2 days)

Week 3:
├── Milestone 3: Bubblewrap (5-6 days)
└── Milestone 9: WSL Support (2-3 days)

Week 4:
├── Milestone 4: Testing Infrastructure (3-4 days)
├── Milestone 5: Documentation (2 days)
└── Milestone 8: VS Code Extension (start)

Week 5:
├── Milestone 8: VS Code Extension (complete, 3-4 days total)
└── Milestone 6 Phase 1: Release as opt-in

Future Releases:
├── v1.x+1: Milestone 6 Phase 2 (recommendation prompts)
├── v2.0-beta: Milestone 6 Phase 3 (soft warnings, min 2 release cycles)
├── v2.0: Milestone 6 Phase 4 (default change)
└── v3.0+: Milestone 6 Phase 5 (legacy mode)
```

**Total Estimated Effort for Initial Release**: 4-5 weeks **Full Transition
Timeline**: 6-12 months across multiple releases

---

## Additional Resolved Decisions

1. **macOS Container networking model**: The macOS Container framework uses
   virtio-net for networking. The VM can access host services via the host's IP
   address (similar to Docker's `host.docker.internal`). Proxy support should
   work by passing `HTTPS_PROXY` environment variables into the container. Will
   verify during implementation.

2. **Bwrap seccomp filters**: Yes, implement seccomp filtering for
   defense-in-depth. Best practices:
   - Use a restrictive default policy that blocks dangerous syscalls
   - Block: `ptrace`, `process_vm_*`, `personality`, `keyctl`, `add_key`,
     `request_key`
   - Block kernel module operations: `init_module`, `finit_module`,
     `delete_module`
   - Allow syscalls needed for Node.js runtime operation
   - Consider using Flatpak's seccomp profile as a reference (well-tested,
     production-ready)

3. **Startup time budget**: <3 seconds added latency is acceptable. Document
   actual performance in release notes.

4. **GitHub Actions macos-15 availability**: **Confirmed available.** GitHub
   Actions provides `macos-15` runners running macOS 15.7.3. We can use
   `runs-on: macos-15` directly. Additionally, `macos-latest` may also resolve
   to macOS 15 in some cases.

5. **Sandbox escape reporting**: Covered by existing vulnerability reporting
   programs. No implementation needed in this work.

---

## Milestone 11: Seccomp Filtering for Bwrap

**Goal**: Add seccomp syscall filtering to bwrap for defense-in-depth security.

### 11.1 Background

Seccomp (Secure Computing Mode) restricts the system calls a process can make.
Combined with namespace isolation, this provides defense-in-depth:

- Namespaces: Restrict what resources a process can see
- Seccomp: Restrict what operations a process can perform

### 11.2 Seccomp Profile Design

**File**: `packages/cli/src/utils/bwrap-seccomp.ts`

```typescript
// Syscalls to block for security
const BLOCKED_SYSCALLS = [
  // Debugging/tracing (container escape vector)
  'ptrace',
  'process_vm_readv',
  'process_vm_writev',

  // Kernel module operations
  'init_module',
  'finit_module',
  'delete_module',

  // Key management (potential privilege escalation)
  'keyctl',
  'add_key',
  'request_key',

  // Personality (can disable ASLR)
  'personality',

  // Namespace manipulation from within sandbox
  'setns',
  'unshare',

  // Mount operations (already blocked by mount namespace, belt-and-suspenders)
  'mount',
  'umount',
  'umount2',

  // Reboot/power operations
  'reboot',
  'kexec_load',
  'kexec_file_load',

  // Clock manipulation
  'clock_settime',
  'settimeofday',
  'adjtimex',
];

export function generateSeccompProfile(): string {
  // Generate bpf filter or use bwrap's --seccomp flag
}
```

### 11.3 Integration with Bwrap

Bwrap supports seccomp via `--seccomp <fd>` flag, passing a BPF filter file
descriptor:

```typescript
// In startBwrapSandbox()
const seccompFd = createSeccompFilter(BLOCKED_SYSCALLS);
args.push('--seccomp', String(seccompFd));
```

Alternatively, use a pre-compiled seccomp filter file:

```typescript
args.push('--seccomp', '3'); // fd 3
// Pass filter via process.spawn's stdio option
```

### 11.4 Profile Variants

| Profile      | Blocked Syscalls                    | Use Case                        |
| ------------ | ----------------------------------- | ------------------------------- |
| `standard`   | Core dangerous syscalls             | Default for most users          |
| `strict`     | Standard + network-related syscalls | Proxied network mode            |
| `permissive` | Minimal blocking                    | Debugging, compatibility issues |

### 11.5 Testing

- [ ] Verify Node.js runtime works with seccomp filter
- [ ] Verify common shell commands work (git, npm, etc.)
- [ ] Test that blocked syscalls actually fail
- [ ] Test on multiple Linux distributions
- [ ] Performance impact assessment

### 11.6 Reference Implementations

- **Flatpak**: Well-tested seccomp profile for desktop apps
- **Docker**: Default seccomp profile blocks ~44 syscalls
- **Firejail**: Security-focused sandbox with seccomp support

### Deliverables

- [ ] Seccomp profile definitions
- [ ] BPF filter generation or pre-compiled filters
- [ ] Integration with bwrap startup
- [ ] Profile selection via environment variable
- [ ] Documentation of blocked syscalls
- [ ] Unit and integration tests

### Estimated Effort

2-3 days

---

## Milestone 12: Landlock + Seccomp Sandbox (Linux)

**Goal**: Implement modern Linux sandboxing using Landlock (filesystem) +
seccomp (syscalls), matching Codex's default approach.

### 12.1 Why Landlock?

Landlock is a Linux security module (kernel 5.13+) that provides unprivileged
filesystem sandboxing:

- **No root required**: Unlike traditional LSMs, Landlock works for unprivileged
  processes
- **Modern approach**: Codex uses Landlock + seccomp as their default Linux
  sandbox
- **Complementary to seccomp**: Landlock handles filesystem access; seccomp
  handles syscall filtering
- **No external dependencies**: Built into the kernel, unlike Bubblewrap

### 12.2 Landlock Overview

Landlock restricts filesystem access through rules:

- **Read**: Allow reading files/directories
- **Write**: Allow writing/creating files
- **Execute**: Allow executing files
- **Directory operations**: Create, remove, rename

Combined with seccomp (already in Milestone 11), this provides defense-in-depth.

### 12.3 Implementation

**File**: `packages/cli/src/utils/landlock.ts` (new)

```typescript
import { execSync } from 'node:child_process';
import fs from 'node:fs';

export interface LandlockRule {
  path: string;
  access: ('read' | 'write' | 'execute')[];
}

export interface LandlockConfig {
  rules: LandlockRule[];
  seccompProfile: string; // Path to seccomp BPF filter
}

export function isLandlockSupported(): boolean {
  // Check kernel version >= 5.13
  try {
    const release = execSync('uname -r', { encoding: 'utf8' }).trim();
    const [major, minor] = release.split('.').map(Number);
    if (major < 5 || (major === 5 && minor < 13)) {
      return false;
    }
  } catch {
    return false;
  }

  // Check Landlock ABI availability
  return fs.existsSync('/sys/kernel/security/landlock');
}

export function getLandlockABIVersion(): number {
  // Returns 0 if not supported, otherwise ABI version (1, 2, 3, 4, 5)
  try {
    // ABI version detection via syscall or /proc
    return 4; // Placeholder - implement actual detection
  } catch {
    return 0;
  }
}
```

**File**: `packages/cli/src/utils/sandbox.ts` (add function)

```typescript
async function startLandlockSandbox(
  config: SandboxConfig,
  nodeArgs: string[],
  cliConfig?: Config,
  cliArgs: string[],
): Promise<number> {
  if (!isLandlockSupported()) {
    throw new FatalSandboxError(
      'Landlock requires Linux kernel 5.13 or later.\n' +
        'Your kernel: ' +
        execSync('uname -r', { encoding: 'utf8' }).trim() +
        '\n' +
        'Use bwrap instead: GEMINI_SANDBOX=bwrap',
    );
  }

  const profile = process.env['LANDLOCK_PROFILE'] ?? 'workspace-write';
  const workdir = process.cwd();

  // Build Landlock rules based on profile
  const rules: LandlockRule[] = [
    // Always allow read access to system directories
    { path: '/usr', access: ['read', 'execute'] },
    { path: '/lib', access: ['read', 'execute'] },
    { path: '/lib64', access: ['read', 'execute'] },
    { path: '/bin', access: ['read', 'execute'] },
    { path: '/sbin', access: ['read', 'execute'] },
    { path: '/etc', access: ['read'] },

    // Workspace access based on profile
    { path: workdir, access: ['read', 'write', 'execute'] },
    { path: os.tmpdir(), access: ['read', 'write'] },

    // Gemini settings
    { path: path.join(homedir(), '.gemini'), access: ['read', 'write'] },
  ];

  // Protected paths (read-only even in workspace)
  const protectedPaths = [
    path.join(workdir, '.git'),
    path.join(workdir, '.gemini'),
  ];

  // Use native Node.js addon or spawn helper process
  // Option 1: Native addon using landlock_create_ruleset syscall
  // Option 2: Spawn via helper binary that sets up Landlock then execs

  const sandboxHelper = path.join(__dirname, 'landlock-helper');
  const args = [
    '--rules',
    JSON.stringify(rules),
    '--protected',
    JSON.stringify(protectedPaths),
    '--seccomp',
    getSeccompFilterPath(),
    '--',
    ...cliArgs,
  ];

  const child = spawn(sandboxHelper, args, {
    stdio: 'inherit',
    env: { ...process.env, SANDBOX: 'landlock' },
  });

  return new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => resolve(code ?? 1));
  });
}
```

### 12.4 Landlock Helper Binary

Since Landlock requires syscalls that Node.js doesn't expose natively, we need
either:

**Option A: Native Node.js addon (preferred)**

- Write C/Rust addon exposing `landlock_create_ruleset`, `landlock_add_rule`,
  `landlock_restrict_self`
- Compile for Linux x64 and ARM64

**Option B: Helper binary**

- Small C/Rust binary that sets up Landlock restrictions then execs the target
  command
- Ship pre-compiled or build during npm install

```c
// landlock-helper.c (simplified)
#include <linux/landlock.h>
#include <sys/syscall.h>

int main(int argc, char *argv[]) {
    // Parse rules from argv
    // Create Landlock ruleset
    int ruleset_fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);

    // Add rules for allowed paths
    syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);

    // Apply seccomp filter
    // ...

    // Restrict self
    syscall(SYS_landlock_restrict_self, ruleset_fd, 0);

    // Exec the actual command
    execvp(command, command_args);
}
```

### 12.5 Profile System

Similar to Bwrap profiles but using Landlock access flags:

| Profile                   | Filesystem Access          | Network | Use Case             |
| ------------------------- | -------------------------- | ------- | -------------------- |
| `read-only`               | Read system + workspace    | Blocked | Safe exploration     |
| `workspace-write`         | Read system, R/W workspace | Blocked | Default editing      |
| `workspace-write-network` | Read system, R/W workspace | Allowed | Package installation |
| `permissive`              | Broad read/write           | Allowed | Debugging            |

### 12.6 Protected Paths

Like Codex, automatically protect sensitive paths even in writable mode:

```typescript
const ALWAYS_PROTECTED_PATHS = [
  '.git', // Prevent Git history manipulation
  '.gemini', // Prevent settings tampering
  '.env', // Prevent credential theft
  '.ssh', // Prevent key theft (if somehow in workspace)
];

function isProtectedPath(filepath: string, workdir: string): boolean {
  const relative = path.relative(workdir, filepath);
  return ALWAYS_PROTECTED_PATHS.some(
    (p) => relative === p || relative.startsWith(p + path.sep),
  );
}
```

### 12.7 Fallback Chain

When `sandbox: true` on Linux:

1. Try Landlock + seccomp (kernel 5.13+)
2. Fall back to Bubblewrap + seccomp
3. Fall back to Docker/Podman
4. Error if nothing available

```typescript
async function getLinuxSandboxCommand(): Promise<SandboxConfig['command']> {
  if (await isLandlockSupported()) {
    return 'landlock';
  }
  if (commandExists.sync('bwrap') && (await userNamespacesEnabled())) {
    return 'bwrap';
  }
  if (commandExists.sync('docker')) {
    return 'docker';
  }
  if (commandExists.sync('podman')) {
    return 'podman';
  }
  throw new FatalSandboxError(
    'No sandbox mechanism available on this Linux system.',
  );
}
```

### 12.8 Testing

- [ ] Test on kernel 5.13, 5.15, 6.1, 6.5+ for ABI compatibility
- [ ] Verify filesystem restrictions work correctly
- [ ] Test protected paths cannot be written
- [ ] Verify seccomp integration
- [ ] Test fallback to Bubblewrap on older kernels
- [ ] Performance benchmarks vs Bubblewrap

### 12.9 Documentation

**File**: `docs/cli/sandbox.md`

```markdown
### 5. Landlock (Linux, Recommended)

Modern kernel-based sandboxing using Landlock + seccomp.

**Requirements**: Linux kernel 5.13 or later

**Why Landlock?**

- Built into the kernel (no external dependencies)
- Same approach used by Codex CLI
- Combines filesystem isolation (Landlock) with syscall filtering (seccomp)
- No root or special capabilities required

**Enable**:

- `gemini --sandbox=landlock`
- `GEMINI_SANDBOX=landlock`
- Or simply `sandbox: true` (auto-detected on supported kernels)

**Profiles** (set via `LANDLOCK_PROFILE` env var):

- `workspace-write` (default): Read/write in project, read-only system
- `read-only`: No writes anywhere
- `workspace-write-network`: Includes network access

**Protected paths** (always read-only):

- `.git` - Prevents Git history manipulation
- `.gemini` - Prevents settings tampering
```

### Deliverables

- [ ] `isLandlockSupported()` detection function
- [ ] Landlock helper binary or native addon
- [ ] `startLandlockSandbox()` implementation
- [ ] Profile system (read-only, workspace-write, etc.)
- [ ] Protected paths feature
- [ ] Fallback chain implementation
- [ ] Integration with seccomp (from Milestone 11)
- [ ] Unit and integration tests
- [ ] Documentation

### Estimated Effort

4-5 days

---

## Final Implementation Order

```
Week 1:
├── Milestone 1: Core Infrastructure (2-3 days)
└── Milestone 2: macOS Container (start)

Week 2:
├── Milestone 2: macOS Container (complete, 4-5 days total)
├── Milestone 7: Nested Sandboxing Detection (1-2 days)
└── Milestone 10: Multi-arch Image (1-2 days)

Week 3:
├── Milestone 3: Bubblewrap (5-6 days)
├── Milestone 11: Seccomp Filtering (2-3 days)
└── Milestone 9: WSL Support (2-3 days)

Week 4:
├── Milestone 12: Landlock + Seccomp (4-5 days)
├── Milestone 4: Testing Infrastructure (3-4 days)
└── Milestone 5: Documentation (2 days)

Week 5-6:
├── Milestone 8: VS Code Extension (3-4 days)
├── Integration testing across all sandbox modes
└── Milestone 6 Phase 1: Release as opt-in

Future Releases:
├── v1.x+1: Milestone 6 Phase 2 (recommendation prompts)
├── v2.0-beta: Milestone 6 Phase 3 (soft warnings, min 2 release cycles)
├── v2.0: Milestone 6 Phase 4 (default change)
└── v3.0+: Milestone 6 Phase 5 (legacy mode)
```

**Total Estimated Effort for Initial Release**: 6-7 weeks **Full Transition
Timeline**: 6-12 months across multiple releases

---

## Open Questions

None remaining. All questions have been resolved.

---

## Competitive Analysis: Gemini CLI vs Claude Code vs Codex

This section compares the sandboxing approaches across AI coding assistants to
contextualize this plan's improvements.

**Sources:**

- Claude Code: https://docs.anthropic.com/en/docs/claude-code/sandboxing
- Codex: https://developers.openai.com/codex/security/

### Current State Comparison

| Feature                        | Gemini CLI (Current)    | Gemini CLI (Planned)                                    | Claude Code                              | Codex                                              |
| ------------------------------ | ----------------------- | ------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------- |
| **macOS Sandboxing**           | Seatbelt (sandbox-exec) | Seatbelt + macOS Container                              | Seatbelt                                 | Seatbelt                                           |
| **Linux Sandboxing**           | Docker/Podman           | Landlock + seccomp (default), Bubblewrap, Docker/Podman | Bubblewrap                               | Landlock + seccomp (default), Bubblewrap (opt-in)  |
| **VM-level Isolation**         | ❌ No                   | ✅ macOS Container                                      | ❌ No                                    | ❌ No                                              |
| **WSL Support**                | Docker only             | Landlock + seccomp, Bubblewrap, Docker                  | Bubblewrap                               | Landlock + seccomp (WSL2 only)                     |
| **Windows Native**             | ❌ No                   | ❌ No                                                   | ❌ No                                    | ✅ Yes (experimental)                              |
| **Filesystem Isolation**       | Profile-based           | Landlock ACLs + protected paths                         | Configurable allow/deny                  | Workspace-based with protected paths               |
| **Network Isolation**          | Proxy-based (optional)  | Proxy-based + namespace                                 | Proxy with domain filtering              | Off by default; configurable                       |
| **Seccomp Filtering**          | ❌ No                   | ✅ Yes (Landlock + seccomp)                             | ❌ Not documented                        | ✅ Yes (Linux)                                     |
| **Protected Paths**            | ❌ No                   | ✅ Yes (`.git`, `.gemini`)                              | ✅ Yes                                   | ✅ Yes (`.git`, `.agents`, `.codex`)               |
| **Nested Container Detection** | ❌ No                   | ✅ Yes (planned)                                        | ✅ Yes (weaker mode available)           | ✅ Yes (recommends `danger-full-access` in Docker) |
| **IDE Integration**            | VS Code companion       | VS Code (enhanced)                                      | Native VS Code                           | VS Code extension, dedicated app                   |
| **Open Source Sandbox**        | ✅ Yes                  | ✅ Yes                                                  | ✅ Yes (`@anthropic-ai/sandbox-runtime`) | ✅ Yes (CLI is open source)                        |
| **Approval Policies**          | Permission prompts      | Permission prompts                                      | Auto-allow mode within boundaries        | Configurable (`on-request`, `untrusted`, `never`)  |

**Note on Docker/Podman**: While Docker provides namespace isolation and a
default seccomp profile, its security value in Gemini CLI is limited because we
mount the workspace, `~/.gemini`, temp directories, and cloud credentials into
the container. The primary benefit of Docker is **environment consistency**
(reproducible toolset), not security isolation. All competitors (Claude Code,
Codex) use host-based sandboxing (Seatbelt, Bubblewrap, Landlock) rather than
containers for this reason.

### Claude Code Sandboxing Details

**Source:** https://docs.anthropic.com/en/docs/claude-code/sandboxing

**Architecture:**

- **macOS**: Seatbelt policies via `sandbox-exec`
- **Linux/WSL2**: Bubblewrap for isolation
- **Network**: Proxy-based domain allowlisting with user confirmation for new
  domains
- **Enforcement**: OS-level ensuring child processes inherit restrictions

**Strengths:**

- Auto-allow mode reduces permission fatigue while maintaining security
- Open-source sandbox runtime (`@anthropic-ai/sandbox-runtime`) usable
  independently
- Well-documented security limitations and escape hatches
- `dangerouslyDisableSandbox` parameter with explicit documentation

**Documented Limitations:**

- Network filtering is domain-based only (no traffic inspection)
- Domain fronting can potentially bypass network filtering
- Unix socket access (`allowUnixSockets`) can lead to escapes (e.g., Docker
  socket)
- Linux `enableWeakerNestedSandbox` mode significantly reduces security
- WSL1 not supported (requires kernel features only in WSL2)

### Codex Sandboxing Details

**Source:** https://developers.openai.com/codex/security/#os-level-sandbox

**Architecture:**

- **macOS**: Seatbelt policies via `sandbox-exec` with configurable profiles
- **Linux**: Landlock + seccomp by default; Bubblewrap available via
  `features.use_linux_sandbox_bwrap = true`
- **Windows**: Experimental native sandbox; recommended to use WSL2 with Linux
  sandbox
- **WSL**: Uses Linux sandbox implementation (WSL2 required)

**Sandbox Modes:**

- `read-only`: Can only read files
- `workspace-write`: Read/write within workspace, protected paths (`.git`,
  `.agents`, `.codex`) remain read-only
- `danger-full-access`: No sandbox (not recommended)

**Approval Policies:**

- `on-request`: Ask for actions outside sandbox boundaries
- `untrusted`: Only auto-approve known-safe read operations
- `never`: No prompts (for CI/automation)

**Strengths:**

- Landlock + seccomp provides strong Linux isolation without container overhead
- Protected paths prevent modification of `.git` even in writable roots
- Comprehensive approval policy system with enterprise management
- Network disabled by default; explicit opt-in required
- Web search can use cached results to reduce prompt injection risk
- Enterprise MDM support for managed configuration

**Documented Limitations:**

- Native Windows sandbox is experimental with known limitations
- Containerized environments (Docker) may not support Landlock/seccomp;
  recommends `danger-full-access` inside container
- No documented VM-level isolation option

### How This Plan Compares

#### Advantages of Planned Gemini CLI Sandboxing

1. **VM-level isolation option (macOS Container)**
   - Claude Code: Process-level Seatbelt isolation only
   - Codex: Process-level Seatbelt isolation only
   - Gemini CLI (planned): Optional full VM isolation via macOS Container
     framework
   - **Benefit**: Strongest isolation against kernel-level exploits; unique
     differentiator

2. **Landlock + seccomp parity with Codex**
   - Claude Code: Bubblewrap only
   - Codex: Landlock + seccomp (modern, kernel-native)
   - Gemini CLI (planned): Landlock + seccomp as default on Linux 5.13+
   - **Benefit**: Matches Codex's security level; no external dependencies

3. **Multi-paradigm flexibility**
   - Claude Code: Single approach per platform (Seatbelt OR Bubblewrap)
   - Codex: Landlock+seccomp default with Bubblewrap opt-in on Linux
   - Gemini CLI (planned): Multiple options per platform (Seatbelt OR macOS
     Container on macOS; Landlock OR Bubblewrap OR Docker on Linux)
   - **Benefit**: Users can choose security/convenience trade-off

4. **Consistent container environment option**
   - Claude Code: Uses host filesystem with restrictions
   - Codex: Uses host filesystem with restrictions
   - Gemini CLI: Offers both host-based (bwrap) AND container-based
     (Docker/macOS Container) with consistent sandbox image
   - **Benefit**: Reproducible environments across machines

#### Areas Where Competitors Lead

**Codex strengths now matched:**

1. ✅ **Landlock + seccomp as default on Linux**: Implemented in Milestone 12
2. ✅ **Protected paths**: Implemented in Milestone 12 (`.git`, `.gemini`
   auto-protected)

**Codex strengths to consider adopting:** 3. **Cached web search**: Reduces
prompt injection risk from live web content 4. **Enterprise MDM support**: macOS
managed preferences for configuration

**Claude Code strengths to consider adopting:**

1. **Auto-allow mode**: Sandboxed commands within boundaries run without prompts
2. **Domain-level network filtering**: Proxy filters by domain with user prompts
   for new domains
3. **Standalone sandbox package**: `@anthropic-ai/sandbox-runtime` usable
   independently

### Recommendations Based on Analysis

1. ~~**Landlock + seccomp for Linux**~~: ✅ Added in Milestone 12

2. ~~**Protected paths**~~: ✅ Added in Milestone 12

3. **Adopt auto-allow pattern**: Both competitors offer modes where safe
   operations proceed without prompts.

4. **Add cached web search option**: Codex's approach of using cached results
   reduces prompt injection risk.

5. **Consider standalone packaging**: Extract sandbox implementation into
   reusable package (`@google/gemini-sandbox-runtime`).

6. **Highlight VM isolation as unique**: Neither Claude Code nor Codex offers
   VM-level isolation; macOS Container is a genuine differentiator.

### Security Level Summary

| Isolation Level            | Security    | Gemini CLI Current | Gemini CLI Planned | Claude Code | Codex               |
| -------------------------- | ----------- | ------------------ | ------------------ | ----------- | ------------------- |
| **Process restrictions**   | Medium      | sandbox-exec       | sandbox-exec       | Seatbelt    | Seatbelt            |
| **Landlock + seccomp**     | Medium-High | -                  | Landlock + seccomp | -           | Landlock + seccomp  |
| **Namespace (Bubblewrap)** | Medium-High | -                  | bwrap + seccomp    | Bubblewrap  | Bubblewrap (opt-in) |
| **Container + mounts**     | Medium      | Docker/Podman      | Docker/Podman      | -           | -                   |
| **VM isolation**           | **High**    | -                  | macOS Container    | -           | -                   |

**Note on security levels:**

- **Medium**: Provides meaningful restrictions but shares kernel with host;
  volume mounts or broad access reduce isolation value
- **Medium-High**: Strong filesystem/syscall controls, but kernel exploits could
  still escape
- **High**: Separate kernel means host is protected even if sandbox is fully
  compromised

### Conclusion

After implementing this plan, Gemini CLI will offer:

1. **Broadest range of isolation options**: From lightweight Seatbelt to full VM
   isolation
2. **Strongest maximum security**: macOS Container provides VM-level isolation
   not available in Claude Code or Codex
3. **Full parity with Codex on Linux**: Landlock + seccomp as default
   (Milestone 12)
4. **Exceeds Claude Code on Linux**: Landlock + seccomp vs Bubblewrap alone
5. **Platform flexibility**: Native options for macOS, Linux, and WSL without
   requiring Docker
6. **Container environment consistency**: Unlike competitors, offers
   reproducible sandbox image option
7. **Protected paths**: Auto-protect `.git`, `.gemini` like Codex

The planned enhancements position Gemini CLI to offer **equal or better security
than Codex on Linux** (Landlock + seccomp) and **exceed Claude Code** (which
uses only Bubblewrap). The **unique VM-level option on macOS** provides
isolation neither competitor offers. The multi-paradigm approach (host-based AND
container-based options) provides flexibility neither Claude Code nor Codex
currently matches.

### Future Considerations

Based on competitive analysis, consider these additions for future milestones:

1. ~~**Landlock support**~~: ✅ Added in Milestone 12
2. ~~**Protected paths**~~: ✅ Added in Milestone 12
3. **Approval policy presets**: Match Codex's `on-request`/`untrusted`/`never`
   model
4. **Enterprise MDM**: macOS managed preferences for corporate deployment
5. **Cached web/fetch results**: Reduce prompt injection risk from live content
6. **Auto-allow mode**: Claude Code's pattern of auto-approving within
   boundaries
