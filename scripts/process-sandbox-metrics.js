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

// The file contains concatenated JSON objects. Split by counting braces.
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

// Aggregation variables
let totalToolCalls = 0;
let totalDurationMs = 0;

// Extract Histogram data for gemini_cli.tool.call.latency
// Format: { resource, scopeMetrics: [{ metrics: [{ descriptor: { name }, dataPoints: [{ value: { count, sum, buckets: { boundaries, counts } } }] }] }] }
for (const obj of objects) {
  const scopeMetrics = obj.scopeMetrics || [];
  for (const scopeMetric of scopeMetrics) {
    const metrics = scopeMetric.metrics || [];
    for (const metric of metrics) {
      const name = metric.descriptor?.name || metric.name;
      if (name === 'gemini_cli.tool.call.latency') {
        const dataPoints =
          metric.dataPoints || metric.histogram?.dataPoints || [];
        for (const dp of dataPoints) {
          const count = Number(dp.value?.count ?? dp.count ?? 0);
          const sum = Number(dp.value?.sum ?? dp.sum ?? 0);
          totalToolCalls += count;
          totalDurationMs += sum;
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
