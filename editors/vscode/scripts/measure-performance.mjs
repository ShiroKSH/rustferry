import { constants as fsConstants } from "node:fs";
import { access, mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";

import { build } from "esbuild";

const SAMPLE_COUNT = 7;
const WARMUP_COUNT = 2;
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 20_000;
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const extensionRoot = path.resolve(scriptDirectory, "..");
const repositoryRoot = path.resolve(extensionRoot, "../..");
const executableName = process.platform === "win32" ? "cargo-ferry.exe" : "cargo-ferry";
const cliPath = path.resolve(
  process.env.RUSTFERRY_TEST_CLI ?? path.join(repositoryRoot, "target", "debug", executableName)
);
const fixture = path.join(extensionRoot, "test", "fixtures", "ferry-project");
const temporary = await mkdtemp(path.join(os.tmpdir(), "rustferry-vscode-perf-"));

try {
  await access(cliPath, process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
  const handshake = await measureCommand(["ide", "handshake", "--json"], extensionRoot, (value) => {
    if (value.protocol_version !== 1) {
      throw new Error("handshake did not return protocol v1");
    }
  });
  const validation = await measureCommand(
    ["ide", "validate", "--workspace", fixture, "--json"],
    fixture,
    (value) => {
      if (value.protocol_version !== 1 || value.valid !== true) {
        throw new Error("fixture validation did not return valid protocol v1 output");
      }
    }
  );
  const bundle = path.join(temporary, "protocol-performance.cjs");
  await build({
    entryPoints: [path.join(extensionRoot, "test", "performance", "protocol.ts")],
    bundle: true,
    outfile: bundle,
    format: "cjs",
    platform: "node",
    target: "node20",
    logLevel: "silent"
  });
  const protocol = JSON.parse((await execute(process.execPath, ["--expose-gc", bundle], extensionRoot)).stdout);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    environment: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch
    },
    parameters: {
      samples: SAMPLE_COUNT,
      warmups: WARMUP_COUNT,
      cargoFerryProfile: "debug"
    },
    measurements: {
      cliHandshakeMs: summarize(handshake),
      configValidationMs: summarize(validation),
      ...protocol.measurements
    },
    limitations: [
      "Wall-clock values include process startup for CLI commands.",
      "Long-stream heap deltas measure the isolated Node decoder process, not the complete VS Code Extension Host.",
      "No Android SDK, simulator, emulator, or device operation runs in this benchmark."
    ]
  }, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`Extension performance measurement failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
} finally {
  await rm(temporary, { recursive: true, force: true });
}

async function measureCommand(args, cwd, validate) {
  for (let index = 0; index < WARMUP_COUNT; index += 1) {
    validate(JSON.parse((await execute(cliPath, args, cwd)).stdout));
  }
  const samples = [];
  for (let index = 0; index < SAMPLE_COUNT; index += 1) {
    const started = performance.now();
    const output = await execute(cliPath, args, cwd);
    samples.push(performance.now() - started);
    validate(JSON.parse(output.stdout));
  }
  return samples;
}

function execute(executable, args, cwd) {
  return new Promise((resolve, reject) => {
    execFile(
      executable,
      args,
      { cwd, encoding: "utf8", maxBuffer: MAX_OUTPUT_BYTES, timeout: COMMAND_TIMEOUT_MS },
      (error, stdout, stderr) => {
        if (error !== null) {
          reject(new Error(`${path.basename(executable)} failed: ${stderr.trim() || error.message}`));
          return;
        }
        resolve({ stdout, stderr });
      }
    );
  });
}

function summarize(values) {
  const sorted = [...values].sort((left, right) => left - right);
  return {
    median: rounded(sorted[Math.floor(sorted.length / 2)] ?? 0),
    p95: rounded(sorted[Math.ceil(sorted.length * 0.95) - 1] ?? 0)
  };
}

function rounded(value) {
  return Number(value.toFixed(3));
}
