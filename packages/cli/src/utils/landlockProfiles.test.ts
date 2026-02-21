/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import {
  buildLandlockProfile,
  BUILTIN_LANDLOCK_PROFILES,
} from './landlockProfiles.js';
import { FatalSandboxError } from '@google/gemini-cli-core';

describe('landlockProfiles', () => {
  const workdir = '/home/user/project';
  const homeDir = '/home/user';
  const tmpDir = '/tmp';

  describe('BUILTIN_LANDLOCK_PROFILES', () => {
    it('should contain 6 profiles', () => {
      expect(BUILTIN_LANDLOCK_PROFILES).toHaveLength(6);
    });

    it('should contain all expected profile names', () => {
      expect(BUILTIN_LANDLOCK_PROFILES).toContain('permissive');
      expect(BUILTIN_LANDLOCK_PROFILES).toContain('permissive-proxied');
      expect(BUILTIN_LANDLOCK_PROFILES).toContain('restrictive');
      expect(BUILTIN_LANDLOCK_PROFILES).toContain('restrictive-proxied');
      expect(BUILTIN_LANDLOCK_PROFILES).toContain('strict');
      expect(BUILTIN_LANDLOCK_PROFILES).toContain('strict-proxied');
    });
  });

  describe('buildLandlockProfile', () => {
    it('should throw for unknown profile names', () => {
      expect(() =>
        buildLandlockProfile('unknown', workdir, homeDir, tmpDir),
      ).toThrow(FatalSandboxError);
    });

    describe('permissive profile', () => {
      it('should allow rw to workspace, tmp, and user dirs', () => {
        const profile = buildLandlockProfile(
          'permissive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('permissive');
        expect(profile.rwPaths).toContain(workdir);
        expect(profile.rwPaths).toContain(tmpDir);
        expect(profile.rwPaths).toContain('/home/user/.gemini');
        expect(profile.rwPaths).toContain('/home/user/.npm');
        expect(profile.rwPaths).toContain('/home/user/.cache');
        expect(profile.useSeccomp).toBe(true);
      });

      it('should include user config files as read-only', () => {
        const profile = buildLandlockProfile(
          'permissive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.roPaths).toContain('/home/user/.gitconfig');
        expect(profile.roPaths).toContain('/home/user/.config/gcloud');
      });

      it('should include system dirs as rx', () => {
        const profile = buildLandlockProfile(
          'permissive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.rxPaths).toContain('/usr');
        expect(profile.rxPaths).toContain('/etc');
        expect(profile.rxPaths).toContain('/bin');
      });
    });

    describe('permissive-proxied profile', () => {
      it('should match permissive but with proxied name', () => {
        const profile = buildLandlockProfile(
          'permissive-proxied',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('permissive-proxied');
        expect(profile.rwPaths).toContain(workdir);
        expect(profile.rwPaths).toContain(tmpDir);
      });
    });

    describe('restrictive profile', () => {
      it('should allow rw only to workspace and tmp', () => {
        const profile = buildLandlockProfile(
          'restrictive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('restrictive');
        expect(profile.rwPaths).toContain(workdir);
        expect(profile.rwPaths).toContain(tmpDir);
        expect(profile.rwPaths).not.toContain('/home/user/.npm');
        expect(profile.rwPaths).not.toContain('/home/user/.cache');
      });

      it('should make .gemini read-only', () => {
        const profile = buildLandlockProfile(
          'restrictive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.roPaths).toContain('/home/user/.gemini');
        expect(profile.rwPaths).not.toContain('/home/user/.gemini');
      });
    });

    describe('strict profile', () => {
      it('should allow rw only to workspace', () => {
        const profile = buildLandlockProfile(
          'strict',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('strict');
        expect(profile.rwPaths).toEqual([workdir]);
      });

      it('should have no ro paths and only system rx paths', () => {
        const profile = buildLandlockProfile(
          'strict',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.roPaths).toEqual([]);
        expect(profile.rxPaths).toContain('/usr');
        expect(profile.rxPaths).toContain('/etc');
        expect(profile.rxPaths).not.toContain('/home/user/.gemini');
      });
    });

    describe('strict-proxied profile', () => {
      it('should match strict but with proxied name', () => {
        const profile = buildLandlockProfile(
          'strict-proxied',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('strict-proxied');
        expect(profile.rwPaths).toEqual([workdir]);
        expect(profile.useSeccomp).toBe(true);
      });
    });

    it('should use correct paths for all profiles', () => {
      const customWorkdir = '/opt/myproject';
      const customHome = '/home/dev';
      const customTmp = '/var/tmp';

      const profile = buildLandlockProfile(
        'permissive',
        customWorkdir,
        customHome,
        customTmp,
      );
      expect(profile.rwPaths).toContain(customWorkdir);
      expect(profile.rwPaths).toContain(customTmp);
      expect(profile.rwPaths).toContain('/home/dev/.gemini');
      expect(profile.roPaths).toContain('/home/dev/.gitconfig');
    });
  });
});
