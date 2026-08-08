import { Buffer } from "node:buffer";
import { performance } from "node:perf_hooks";

import { NdjsonDecoder } from "../../src/cli/protocol.js";

const EVENT_COUNT = 10_000;
const LONG_STREAM_EVENT_COUNT = 100_000;
const EVENTS_PER_BATCH = 500;
const CHUNK_BYTES = 64 * 1024;
const SAMPLE_COUNT = 7;
const WARMUP_COUNT = 2;
const MAX_LINE_BYTES = 1024 * 1024;

const eventLine = `${JSON.stringify({
  protocol_version: 1,
  event: "progress",
  operation_id: "benchmark",
  timestamp_ms: 1,
  phase: "compile",
  message: "Compiling deterministic fixture",
  completed: 42,
  total: 100
})}\n`;

const tenThousandEvents = Buffer.from(eventLine.repeat(EVENT_COUNT), "utf8");
const batch = Buffer.from(eventLine.repeat(EVENTS_PER_BATCH), "utf8");
const parseSamples = measureSamples(() => {
  const count = parseBytes(tenThousandEvents);
  if (count !== EVENT_COUNT) {
    throw new Error(`decoded ${count} events instead of ${EVENT_COUNT}`);
  }
});

collectGarbage();
const heapBefore = process.memoryUsage().heapUsed;
let peakHeap = heapBefore;
const streamStarted = performance.now();
let decoded = 0;
const decoder = new NdjsonDecoder(MAX_LINE_BYTES);
for (let offset = 0; offset < LONG_STREAM_EVENT_COUNT; offset += EVENTS_PER_BATCH) {
  decoded += pushChunks(decoder, batch);
  peakHeap = Math.max(peakHeap, process.memoryUsage().heapUsed);
}
decoder.finish();
const longStreamMs = performance.now() - streamStarted;
if (decoded !== LONG_STREAM_EVENT_COUNT) {
  throw new Error(`decoded ${decoded} long-stream events instead of ${LONG_STREAM_EVENT_COUNT}`);
}
collectGarbage();
const heapAfter = process.memoryUsage().heapUsed;

process.stdout.write(`${JSON.stringify({
  schemaVersion: 1,
  environment: {
    node: process.version,
    platform: process.platform,
    architecture: process.arch
  },
  parameters: {
    protocolEvents: EVENT_COUNT,
    longStreamEvents: LONG_STREAM_EVENT_COUNT,
    chunkBytes: CHUNK_BYTES,
    samples: SAMPLE_COUNT,
    warmups: WARMUP_COUNT
  },
  measurements: {
    protocolParse10000Ms: summarize(parseSamples),
    longStream: {
      elapsedMs: rounded(longStreamMs),
      peakHeapDeltaBytes: Math.max(0, peakHeap - heapBefore),
      retainedHeapDeltaBytes: heapAfter - heapBefore
    }
  }
})}\n`);

function parseBytes(bytes: Uint8Array): number {
  const decoder = new NdjsonDecoder(MAX_LINE_BYTES);
  const count = pushChunks(decoder, bytes);
  decoder.finish();
  return count;
}

function pushChunks(decoder: NdjsonDecoder, bytes: Uint8Array): number {
  let count = 0;
  for (let offset = 0; offset < bytes.byteLength; offset += CHUNK_BYTES) {
    count += decoder.push(bytes.subarray(offset, offset + CHUNK_BYTES)).length;
  }
  return count;
}

function measureSamples(operation: () => void): number[] {
  for (let index = 0; index < WARMUP_COUNT; index += 1) {
    operation();
  }
  const samples: number[] = [];
  for (let index = 0; index < SAMPLE_COUNT; index += 1) {
    const started = performance.now();
    operation();
    samples.push(performance.now() - started);
  }
  return samples;
}

function summarize(values: readonly number[]): Readonly<{ median: number; p95: number }> {
  const sorted = [...values].sort((left, right) => left - right);
  return {
    median: rounded(sorted[Math.floor(sorted.length / 2)] ?? 0),
    p95: rounded(sorted[Math.ceil(sorted.length * 0.95) - 1] ?? 0)
  };
}

function rounded(value: number): number {
  return Number(value.toFixed(3));
}

function collectGarbage(): void {
  const gc = (globalThis as { gc?: () => void }).gc;
  gc?.();
}
