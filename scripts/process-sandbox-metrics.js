/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from 'node:fs';

const inputFiles = process.argv.slice(2).filter((f) => fs.existsSync(f));

if (inputFiles.length === 0) {
  console.log('No telemetry files found or provided.');
  process.exit(0);
}

// Parse concatenated JSON objects from a string. The telemetry file contains
// multiple JSON objects written back-to-back (not newline-delimited).
function parseJsonObjects(content) {
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

  return objects;
}

// Collect all JSON objects from all telemetry files
const objects = [];
for (const inputFile of inputFiles) {
  const content = fs.readFileSync(inputFile, 'utf-8');
  objects.push(...parseJsonObjects(content));
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
