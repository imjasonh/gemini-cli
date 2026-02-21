/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from 'node:fs';

const inputFile = process.argv[2];

if (!inputFile || !fs.existsSync(inputFile)) {
  console.log('No telemetry file found or provided.');
  process.exit(0);
}

const content = fs.readFileSync(inputFile, 'utf-8');

// The file contains concatenated JSON objects, each pretty-printed.
// We need to robustly split them.
// Since they are top-level objects, we can look for "}\n{" which indicates a boundary,
// but we need to be careful about nested objects.
// A simpler robust way: count braces.

const objects = [];
let braceCount = 0;
let currentObject = '';
let inString = false;
let escape = false;

for (let i = 0; i < content.length; i++) {
  const char = content[i];
  currentObject += char;

  if (escape) {
    escape = false;
    continue;
  }

  if (char === '\\') {
    escape = true;
    continue;
  }

  if (char === '"') {
    inString = !inString;
    continue;
  }

  if (!inString) {
    if (char === '{') {
      braceCount++;
    } else if (char === '}') {
      braceCount--;
      if (braceCount === 0) {
        // End of an object
        try {
          objects.push(JSON.parse(currentObject.trim()));
        } catch (_e) {
          // Ignore parse errors (e.g. partial writes)
        }
        currentObject = '';
      }
    }
  }
}

// Group by session.id to get the last export for each process (cumulative)
const lastExportBySession = new Map();

for (const obj of objects) {
  const resourceAttrs = obj.resource?.attributes || [];
  const sessionIdAttr = resourceAttrs.find((a) => a.key === 'session.id');
  const sessionId = sessionIdAttr?.value?.stringValue;

  if (sessionId) {
    lastExportBySession.set(sessionId, obj);
  }
}

// Aggregation variables
let totalToolCalls = 0;
let totalDurationMs = 0;
let bucketCounts = new Map(); // bound -> count

// Extract Histogram data for tool.call.latency
for (const obj of lastExportBySession.values()) {
  const scopeMetrics = obj.scopeMetrics || [];
  for (const scopeMetric of scopeMetrics) {
    const metrics = scopeMetric.metrics || [];
    for (const metric of metrics) {
      if (metric.name === 'tool.call.latency') {
        const dataPoints = metric.histogram?.dataPoints || [];
        for (const dp of dataPoints) {
          totalToolCalls += Number(dp.count || 0);
          totalDurationMs += Number(dp.sum || 0);

          // Aggregate buckets for percentile calculation
          // explicitBounds: [0, 5, 10, 25, 50, 75, 100, 250, 500, 1000, 2500, 5000, 10000]
          // bucketCounts: [c0, c1, ..., cN] where cI is count in (bounds[i-1], bounds[i]]
          if (dp.explicitBounds && dp.bucketCounts) {
            dp.explicitBounds.forEach((bound, i) => {
              // Bucket i corresponds to range ending at explicitBounds[i]
              // dp.bucketCounts has length explicitBounds.length + 1
              const count = Number(dp.bucketCounts[i] || 0);
              bucketCounts.set(bound, (bucketCounts.get(bound) || 0) + count);
            });
            // Last bucket (infinity)
            const lastBound = Infinity;
            const lastCount = Number(
              dp.bucketCounts[dp.explicitBounds.length] || 0,
            );
            bucketCounts.set(
              lastBound,
              (bucketCounts.get(lastBound) || 0) + lastCount,
            );
          }
        }
      }
    }
  }
}

const avgLatency =
  totalToolCalls > 0 ? (totalDurationMs / totalToolCalls).toFixed(2) : 'N/A';

console.log('### Sandbox Performance Metrics');
console.log('');
console.log('| Metric | Value |');
console.log('| :--- | :--- |');
console.log(`| Total Tool Calls | ${totalToolCalls} |`);
console.log(`| Average Latency | ${avgLatency} ms |`);
console.log(`| Total Duration | ${totalDurationMs.toFixed(2)} ms |`);
