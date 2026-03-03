/**
 * @license
 * Copyright 2026 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/* eslint-disable @typescript-eslint/no-require-imports, no-undef */

const { existsSync } = require('node:fs');
const { join } = require('node:path');

const { platform, arch } = process;

function loadBinding() {
  // Only support Linux
  if (platform !== 'linux') {
    throw new Error(
      `Landlock is only available on Linux. Current platform: ${platform}`,
    );
  }

  // Determine the target triple
  let nativeBinding = null;
  let loadError = null;

  const localFileExisted = existsSync(
    join(__dirname, 'gemini-cli-landlock.node'),
  );
  if (localFileExisted) {
    try {
      nativeBinding = require('./gemini-cli-landlock.node');
    } catch (e) {
      loadError = e;
    }
  }

  if (!nativeBinding) {
    // Try platform-specific binding
    const triple = getTriple();
    try {
      nativeBinding = require(`./gemini-cli-landlock.${triple}.node`);
    } catch (e) {
      if (!loadError) {
        loadError = e;
      }
    }
  }

  if (!nativeBinding) {
    if (loadError) {
      throw loadError;
    }
    throw new Error(`Failed to load native binding for ${platform}-${arch}`);
  }

  return nativeBinding;
}

function getTriple() {
  const { platform, arch } = process;

  if (platform === 'linux') {
    if (arch === 'x64') {
      return 'linux-x64-gnu';
    } else if (arch === 'arm64') {
      return 'linux-arm64-gnu';
    }
  }

  throw new Error(`Unsupported platform/architecture: ${platform}/${arch}`);
}

module.exports = loadBinding();
