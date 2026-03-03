# Landlock Rust N-API Migration Plan

## Executive Summary

Migrate the Landlock sandbox implementation from a C helper binary to a Rust
N-API native module using napi-rs. This improves reliability, simplifies
distribution, and provides better type safety while maintaining all existing
functionality.

## Current State Analysis

### Implementation (C + Native Bundling)

- **Code**: 380-line C helper (`packages/cli/native/landlock-helper.c`)
- **Build**: Makefile with cross-compilation for amd64/arm64
- **Distribution**: Static binaries bundled in `dist/` directory
- **Integration**: TypeScript spawns helper as external process
- **Complexity**: Runtime binary search, PATH filtering, process lifecycle
  management

### Key Features to Preserve

- Landlock ABI version detection (v1/v2/v3)
- Three access levels: `--ro` (read-only), `--rw` (read-write), `--rx`
  (read-execute)
- Seccomp BPF filter integration via file
- Non-fatal RO path handling vs fatal RW paths
- Six builtin profiles (permissive, restrictive, strict + proxied variants)

## Benefits of Rust + N-API

### Reliability

- **Direct function calls** instead of spawning external processes
- No PATH search issues or missing binary errors
- Proper error propagation vs parsing stderr
- No process lifecycle management overhead

### Simplicity

- **napi-rs handles all FFI/binding generation** automatically
- TypeScript types generated from Rust code
- Standard npm dependency model vs custom binary bundling
- Single build system (Cargo + npm) vs dual (Make + npm)

### Distribution

- **Platform-specific optional dependencies** (standard npm pattern)
- Automatic platform selection at install time
- Pre-built binaries via GitHub Actions
- Smaller package size (only relevant binary installed)

### Developer Experience

- Type-safe Rust implementation with compile-time guarantees
- Better error messages and debugging
- Easier testing (direct function calls)
- Modern tooling (cargo, clippy, rustfmt)

## Migration Architecture

### Package Structure

```
packages/
├── cli/                          # Main CLI package
│   ├── package.json              # Add optionalDependencies for platform packages
│   └── src/
│       └── utils/
│           ├── sandbox.ts        # Call native module instead of spawn
│           └── landlockProfiles.ts  # Keep profiles, remove path args generation
│
└── landlock/                     # New Rust N-API package
    ├── Cargo.toml                # Rust package config
    ├── package.json              # npm metadata + optional deps
    ├── build.rs                  # Optional build script
    ├── src/
    │   └── lib.rs                # Main N-API module
    ├── index.js                  # Generated loader by napi-rs
    ├── index.d.ts                # Generated TypeScript types
    └── npm/                      # Platform-specific packages (auto-generated)
        ├── darwin-arm64/
        ├── darwin-x64/
        ├── linux-arm64-gnu/
        └── linux-x64-gnu/
```

### API Design

**Rust N-API Module** (`@google/gemini-cli-landlock`):

```rust
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct LandlockConfig {
  pub ro_paths: Vec<String>,
  pub rw_paths: Vec<String>,
  pub rx_paths: Vec<String>,
  pub seccomp_filter_path: Option<String>,
}

#[napi(object)]
pub struct LandlockInfo {
  pub available: bool,
  pub abi_version: u32,
  pub error: Option<String>,
}

/// Check if Landlock is available and detect ABI version
#[napi]
pub fn check_landlock() -> LandlockInfo { ... }

/// Apply Landlock sandbox to current process
#[napi]
pub fn apply_landlock(config: LandlockConfig) -> Result<()> { ... }

/// Helper: get access rights mask for ABI version
#[napi]
pub fn get_access_mask(abi_version: u32, access_type: String) -> Result<u64> { ... }
```

**TypeScript Integration**:

```typescript
// Auto-generated types from Rust
import {
  checkLandlock,
  applyLandlock,
  LandlockConfig,
} from '@google/gemini-cli-landlock';

export async function startLandlockSandbox(
  config: SandboxConfig,
): Promise<ChildProcess> {
  const profile = getLandlockProfile();

  // Apply sandbox to current process BEFORE spawning child
  applyLandlock({
    roPaths: profile.roPaths,
    rwPaths: profile.rwPaths,
    rxPaths: profile.rxPaths,
    seccompFilterPath: seccompFile,
  });

  // Now spawn the actual command (already sandboxed)
  return spawn(config.command[0], config.command.slice(1), {
    env: { ...process.env, SANDBOX: 'landlock' },
    stdio: 'inherit',
  });
}
```

## Implementation Plan

### Phase 1: Setup and Bootstrap (Week 1)

#### Task 1.1: Initialize napi-rs Package

- [ ] Install `@napi-rs/cli` globally
- [ ] Run `napi new` to create `packages/landlock`
- [ ] Configure for target platforms: linux-x64-gnu, linux-arm64-gnu
- [ ] Set up GitHub Actions for cross-compilation (auto-generated)
- [ ] Add to workspace in root `package.json`

#### Task 1.2: Project Configuration

- [ ] Configure `Cargo.toml` with dependencies:
  - `napi` (N-API bindings)
  - `napi-derive` (procedural macros)
- [ ] Set up `package.json` with correct scoping (`@google/gemini-cli-landlock`)
- [ ] Configure optional dependencies for platform packages
- [ ] Add build scripts

### Phase 2: Core Landlock Implementation (Week 1-2)

#### Task 2.1: Syscall Wrappers

- [ ] Define Landlock constants (syscall numbers, access flags, ABI versions)
- [ ] Implement syscall wrappers:
  - `landlock_create_ruleset()`
  - `landlock_add_rule()`
  - `landlock_restrict_self()`
- [ ] Add ABI version detection logic
- [ ] Handle errors and convert to napi::Error

#### Task 2.2: Public API Functions

- [ ] Implement `check_landlock()` for availability detection
- [ ] Implement `apply_landlock(config)` for sandbox activation
- [ ] Add path validation and normalization
- [ ] Implement access rights mapping (RO, RW, RX per ABI version)

#### Task 2.3: Seccomp Integration

- [ ] Add BPF filter loading from file
- [ ] Implement `prctl(PR_SET_SECCOMP, SECCOMP_SET_MODE_FILTER, ...)` wrapper
- [ ] Handle seccomp errors gracefully

### Phase 3: Integration with CLI (Week 2)

#### Task 3.1: Update TypeScript Code

- [ ] Add `@google/gemini-cli-landlock` to `packages/cli/package.json`
      dependencies
- [ ] Refactor `sandbox.ts:startLandlockSandbox()`:
  - Call `checkLandlock()` instead of searching for binary
  - Call `applyLandlock()` before spawning child
  - Remove binary path detection logic
  - Simplify error handling
- [ ] Update `sandboxUtils.ts:isLandlockAvailable()`:
  - Use native `checkLandlock()` function
  - Simplify kernel version check (now redundant with native check)
- [ ] Remove `getLandlockHelperPath()` function (no longer needed)

#### Task 3.2: Profile Handling

- [ ] Keep `landlockProfiles.ts` as-is (profiles remain in TypeScript)
- [ ] Remove command-line argument generation (no longer spawning external
      binary)
- [ ] Pass profile paths directly to `applyLandlock()`

### Phase 4: Testing (Week 2-3)

#### Task 4.1: Unit Tests (Rust)

- [ ] Test ABI version detection on different kernels
- [ ] Test access rights calculation for each ABI version
- [ ] Test error handling (missing paths, invalid syscalls)
- [ ] Mock syscalls for CI environments without Landlock

#### Task 4.2: Integration Tests (TypeScript)

- [ ] Update existing tests in `landlockProfiles.test.ts`
- [ ] Update sandbox verification tests
- [ ] Test on actual Linux systems (CI: Ubuntu 22.04+)
- [ ] Verify seccomp integration still works

#### Task 4.3: Cross-Platform Validation

- [ ] Test pre-built binaries install correctly
- [ ] Verify graceful degradation on non-Linux systems
- [ ] Test on WSL (known edge case from current implementation)

### Phase 5: Migration and Cleanup (Week 3)

#### Task 5.1: Remove C Implementation

- [ ] Delete `packages/cli/native/landlock-helper.c`
- [ ] Delete `packages/cli/native/Makefile`
- [ ] Remove native build logic from `scripts/build_package.js`
- [ ] Remove binary bundling logic

#### Task 5.2: Documentation

- [ ] Update README with new architecture
- [ ] Document Rust module API
- [ ] Add developer guide for building native modules
- [ ] Update troubleshooting guide (no more binary PATH issues)

#### Task 5.3: CI/CD Updates

- [ ] Configure GitHub Actions to build Rust module
- [ ] Set up automated publishing of platform packages
- [ ] Update release process documentation
- [ ] Verify all platforms build successfully

## Risk Assessment

### High Impact Risks

**Risk**: Landlock syscall behavior differs between kernel versions

- **Mitigation**: Extensive testing on Ubuntu 22.04, 24.04, and latest kernels
- **Fallback**: Keep C implementation for one release cycle

**Risk**: N-API overhead affects performance

- **Mitigation**: Benchmark current vs new implementation
- **Likelihood**: Low (N-API is designed for performance)

**Risk**: Platform package distribution complexity

- **Mitigation**: Use napi-rs standard patterns (well-tested)
- **Validation**: Test installation on fresh systems

### Medium Impact Risks

**Risk**: TypeScript integration breaks existing behavior

- **Mitigation**: Comprehensive integration tests before migration
- **Testing**: Run full sandbox test suite on both implementations

**Risk**: Binary size increases

- **Mitigation**: Strip debug symbols, optimize Rust build
- **Measurement**: Compare current static binary vs .node module size

## Success Criteria

- [ ] All existing Landlock functionality works identically
- [ ] All integration tests pass
- [ ] Binary size comparable or smaller than current C binary
- [ ] Installation time improved (only one platform binary downloaded)
- [ ] Zero runtime binary search overhead
- [ ] TypeScript types auto-generated from Rust code
- [ ] GitHub Actions successfully build all platform binaries
- [ ] Documentation complete and accurate

## Implementation Status

### Completed

- [x] Phase 1: Setup napi-rs package structure
- [x] Phase 2: Core Landlock implementation in Rust (syscalls, ABI detection,
      seccomp)
- [x] Phase 3: N-API public interface (`checkLandlock`, `applyLandlock`)
- [x] Phase 4: TypeScript integration (removed binary spawning, now uses native
      module)
- [x] Phase 5.1: Removed C implementation (landlock-helper.c, Makefile, native/)
- [x] Phase 5.2: Updated build scripts (build_package.js)

### Remaining

- [ ] Phase 4.3: Testing - Update unit tests and integration tests
- [ ] Phase 5.3: CI/CD Updates - Configure GitHub Actions for Rust builds

## Timeline

- **Week 1**: Setup + Core Implementation (Phases 1-2) ✅ **COMPLETE**
- **Week 2**: Integration + Initial Testing (Phases 3-4) ✅ **COMPLETE**
- **Week 3**: Final Testing + Migration (Phase 4-5) 🚧 **IN PROGRESS**

**Status**: Core migration complete. Testing and CI updates remaining.

## Resources

### Documentation

- [napi-rs Official Docs](https://napi.rs/)
- [napi-rs GitHub](https://github.com/napi-rs/napi-rs)
- [Getting Started Guide](https://napi.rs/docs/introduction/getting-started)
- [Package Template](https://github.com/napi-rs/package-template)
- [Building Node.js modules in Rust (LogRocket)](https://blog.logrocket.com/building-nodejs-modules-rust-napi-rs/)

### Examples

- [napi-rs Canvas](https://www.npmjs.com/package/@napi-rs/canvas) - Production
  example
- [Exposing Rust to Node](https://johns.codes/blog/exposing-a-rust-library-to-node-with-napirs)

### Landlock References

- Current implementation: `packages/cli/native/landlock-helper.c`
- Profiles: `packages/cli/src/utils/landlockProfiles.ts`
- Integration: `packages/cli/src/utils/sandbox.ts:1647-1883`
