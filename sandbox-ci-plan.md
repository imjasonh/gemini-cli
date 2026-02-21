# Sandbox CI Fix Plan

This document outlines the plan to address the CI failures in the sandbox test
legs and add the missing pre-existing options to the CI matrix.

## 1. Fix `bwrap` Sandbox Failures

**Issue:** The `bwrap` integration tests fail with
`bwrap: unknown option --unshare-mount`. The version of `bubblewrap` available
on the Ubuntu runner does not support this flag. **Action Taken:**

- Removed the `--unshare-mount` argument from the `bwrap` invocation in
  `packages/cli/src/utils/sandbox.ts`.
- Updated the corresponding unit tests in
  `packages/cli/src/utils/sandbox.test.ts` to reflect this removal.

## 2. Fix `sandbox-exec` (macOS Seatbelt) Failures

**Issue:** Integration tests (like `telemetry.test.ts` and
`utf-bom-encoding.test.ts`) fail with
`EPERM: operation not permitted, open '.../telemetry.log'`. The macOS seatbelt
permissive profile (`sandbox-macos-permissive-open.sb`) restricts write access
in the home directory to specific folders like `.gemini`, `.npm`, and `.cache`.
Writing `telemetry.log` directly to the home directory root is blocked. **Action
Taken:**

- Changed the telemetry log path from `~/telemetry.log` to
  `~/.gemini/telemetry.log` in:
  - `packages/test-utils/src/test-rig.ts`
  - `integration-tests/globalSetup.ts`
  - `integration-tests/acp-telemetry.test.ts`

## 3. Add Missing Sandbox Options to CI Matrix

**Issue:** The CI workflow `.github/workflows/test-sandbox.yml` was missing test
legs for `docker` (and `seatbelt` is already covered under `sandbox-exec`).
**Action Taken:**

- Added a `docker` matrix leg running on `ubuntu-latest` to
  `.github/workflows/test-sandbox.yml`.

## 4. Address `landlock` Sandbox Failures

**Issue:** The `landlock` integration tests fail with exit code 44. The logs
indicate:
`isLandlockAvailable: /sys/kernel/security/landlock not accessible, Landlock LSM may not be loaded`.
The standard GitHub Actions Ubuntu runners do not have the Landlock LSM enabled
by default in their kernels. **Next Steps:**

- **Option A:** Modify the integration tests to gracefully skip if Landlock is
  not available on the host system (checking `isLandlockAvailable`).
- **Option B:** If Landlock testing is strictly required in CI, we may need to
  configure a custom runner or use a specific action to enable the Landlock LSM
  in the runner's boot parameters (though this is difficult in standard hosted
  runners).
- _Recommendation:_ For now, ensure the CLI gracefully falls back or errors
  informatively, and update the test rig to skip Landlock integration tests if
  the kernel doesn't support it, preventing spurious CI failures.

## 5. Monitor `macos-container`

**Issue:** The `macos-container` leg was still running and potentially subject
to the same `telemetry.log` write permission issues if it uses strict volume
mounts. **Next Steps:**

- The fix applied for `sandbox-exec` (moving `telemetry.log` to `.gemini/`)
  should proactively resolve similar volume mount permission issues for
  `macos-container`.
- Monitor the next CI run to verify `macos-container` passes successfully.
