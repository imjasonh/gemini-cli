/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest';
import { buildBwrapProfile, BUILTIN_BWRAP_PROFILES } from './bwrapProfiles.js';
import { FatalSandboxError } from '@google/gemini-cli-core';

describe('bwrapProfiles', () => {
  const workdir = '/home/user/project';
  const homeDir = '/home/user';
  const tmpDir = '/tmp';

  describe('BUILTIN_BWRAP_PROFILES', () => {
    it('should contain 6 profiles', () => {
      expect(BUILTIN_BWRAP_PROFILES).toHaveLength(6);
    });

    it('should contain all expected profile names', () => {
      expect(BUILTIN_BWRAP_PROFILES).toContain('permissive');
      expect(BUILTIN_BWRAP_PROFILES).toContain('permissive-proxied');
      expect(BUILTIN_BWRAP_PROFILES).toContain('restrictive');
      expect(BUILTIN_BWRAP_PROFILES).toContain('restrictive-proxied');
      expect(BUILTIN_BWRAP_PROFILES).toContain('strict');
      expect(BUILTIN_BWRAP_PROFILES).toContain('strict-proxied');
    });
  });

  describe('buildBwrapProfile', () => {
    it('should throw for unknown profile names', () => {
      expect(() =>
        buildBwrapProfile('unknown', workdir, homeDir, tmpDir),
      ).toThrow(FatalSandboxError);
    });

    describe('permissive profile', () => {
      it('should allow rw to workspace, tmp, and user dirs', () => {
        const profile = buildBwrapProfile(
          'permissive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('permissive');
        expect(profile.rwBinds).toContain(workdir);
        expect(profile.rwBinds).toContain(tmpDir);
        expect(profile.rwBinds).toContain('/home/user/.gemini');
        expect(profile.rwBinds).toContain('/home/user/.npm');
        expect(profile.rwBinds).toContain('/home/user/.cache');
        expect(profile.shareNetwork).toBe(true);
      });

      it('should include system ro binds and user config files', () => {
        const profile = buildBwrapProfile(
          'permissive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.roBinds).toContain('/usr');
        expect(profile.roBinds).toContain('/etc');
        expect(profile.roBinds).toContain('/home/user/.gitconfig');
      });
    });

    describe('permissive-proxied profile', () => {
      it('should match permissive but with proxied name', () => {
        const profile = buildBwrapProfile(
          'permissive-proxied',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('permissive-proxied');
        expect(profile.rwBinds).toContain(workdir);
        expect(profile.rwBinds).toContain(tmpDir);
        expect(profile.shareNetwork).toBe(true);
      });
    });

    describe('restrictive profile', () => {
      it('should allow rw only to workspace and tmp', () => {
        const profile = buildBwrapProfile(
          'restrictive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('restrictive');
        expect(profile.rwBinds).toContain(workdir);
        expect(profile.rwBinds).toContain(tmpDir);
        expect(profile.rwBinds).not.toContain('/home/user/.npm');
        expect(profile.rwBinds).not.toContain('/home/user/.cache');
      });

      it('should make .gemini read-only', () => {
        const profile = buildBwrapProfile(
          'restrictive',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.roBinds).toContain('/home/user/.gemini');
        expect(profile.rwBinds).not.toContain('/home/user/.gemini');
      });
    });

    describe('strict profile', () => {
      it('should allow rw only to workspace', () => {
        const profile = buildBwrapProfile('strict', workdir, homeDir, tmpDir);
        expect(profile.name).toBe('strict');
        expect(profile.rwBinds).toEqual([workdir]);
      });

      it('should have minimal ro binds (system dirs only)', () => {
        const profile = buildBwrapProfile('strict', workdir, homeDir, tmpDir);
        expect(profile.roBinds).toContain('/usr');
        expect(profile.roBinds).toContain('/etc');
        expect(profile.roBinds).not.toContain('/home/user/.gemini');
        expect(profile.roBinds).not.toContain('/home/user/.gitconfig');
      });
    });

    describe('strict-proxied profile', () => {
      it('should match strict but with proxied name', () => {
        const profile = buildBwrapProfile(
          'strict-proxied',
          workdir,
          homeDir,
          tmpDir,
        );
        expect(profile.name).toBe('strict-proxied');
        expect(profile.rwBinds).toEqual([workdir]);
        expect(profile.shareNetwork).toBe(true);
      });
    });

    it('should use correct paths for all profiles', () => {
      const customWorkdir = '/opt/myproject';
      const customHome = '/home/dev';
      const customTmp = '/var/tmp';

      const profile = buildBwrapProfile(
        'permissive',
        customWorkdir,
        customHome,
        customTmp,
      );
      expect(profile.rwBinds).toContain(customWorkdir);
      expect(profile.rwBinds).toContain(customTmp);
      expect(profile.rwBinds).toContain('/home/dev/.gemini');
      expect(profile.roBinds).toContain('/home/dev/.gitconfig');
    });
  });
});
