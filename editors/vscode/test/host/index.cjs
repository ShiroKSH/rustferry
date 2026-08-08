const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { setTimeout: delay } = require("node:timers/promises");

const vscode = require("vscode");

const EXTENSION_ID = "shiroksh.rustferry-vscode";
const EXPECTED_COMMANDS = [
  "rustferry.check",
  "rustferry.doctor",
  "rustferry.openConfig",
  "rustferry.refresh"
];

async function run() {
  const scenario = process.env.RUSTFERRY_HOST_SCENARIO;
  const extension = vscode.extensions.getExtension(EXTENSION_ID);
  assert.ok(extension, `Extension ${EXTENSION_ID} was not loaded by the development host`);

  if (scenario === "ordinary") {
    await delay(1_500);
    assert.equal(extension.isActive, false, "ordinary Rust workspace activated RustFerry without ferry.toml");
    process.stdout.write("host-smoke ordinary: extension remained inactive\n");
    return;
  }
  assert.equal(scenario, "ferry", `Unknown host-smoke scenario: ${String(scenario)}`);

  await waitFor(() => extension.isActive, 20_000, "workspaceContains:ferry.toml activation");
  const api = await waitForValue(
    () => performanceApi(extension.exports),
    20_000,
    "RustFerry performance API"
  );
  const commands = await vscode.commands.getCommands(true);
  for (const command of EXPECTED_COMMANDS) {
    assert.ok(commands.includes(command), `Activated extension did not register ${command}`);
  }

  const snapshot = api.performanceSnapshot();
  assert.equal(snapshot.projectCount, 1, "ferry fixture was not discovered as one project");
  assertNonNegative(snapshot.activationMs, "activationMs");
  assertNonNegative(snapshot.projectDiscoveryMs, "projectDiscoveryMs");
  assertNonNegative(snapshot.treeRefreshMs, "treeRefreshMs");

  const refreshSamples = [];
  for (let index = 0; index < 5; index += 1) {
    const started = performance.now();
    await vscode.commands.executeCommand("rustferry.refresh");
    refreshSamples.push(performance.now() - started);
  }

  const openStarted = performance.now();
  await vscode.commands.executeCommand("rustferry.openConfig");
  const openManifestMs = performance.now() - openStarted;
  const expectedManifest = process.env.RUSTFERRY_EXPECTED_MANIFEST;
  assert.ok(expectedManifest, "RUSTFERRY_EXPECTED_MANIFEST was not supplied");
  const activeDocument = vscode.window.activeTextEditor?.document;
  assert.ok(activeDocument, "Open ferry.toml command did not create an active editor");
  assert.equal(path.resolve(activeDocument.uri.fsPath), path.resolve(expectedManifest));
  await waitFor(
    () => api.performanceSnapshot().validProjectCount === 1,
    20_000,
    "successful real CLI configuration validation"
  );
  const rustFerryDiagnostics = vscode.languages
    .getDiagnostics(activeDocument.uri)
    .filter((diagnostic) => diagnostic.source === "RustFerry");
  assert.deepEqual(rustFerryDiagnostics, [], "valid ferry fixture produced RustFerry diagnostics");

  const savedManifest = readFileSync(expectedManifest, "utf8");
  const identifier = 'identifier = "com.example.hostsmokeferry"';
  const identifierOffset = activeDocument.getText().indexOf(identifier);
  assert.ok(identifierOffset >= 0, "ferry fixture identifier was not found");
  const editor = vscode.window.activeTextEditor;
  assert.ok(editor, "ferry.toml editor disappeared before dirty validation");
  const changed = await editor.edit((edit) => {
    edit.replace(
      new vscode.Range(
        activeDocument.positionAt(identifierOffset),
        activeDocument.positionAt(identifierOffset + identifier.length)
      ),
      'identifier = "not-an-identifier"'
    );
  });
  assert.equal(changed, true, "VS Code refused the unsaved ferry.toml edit");
  assert.equal(activeDocument.isDirty, true, "ferry.toml did not become dirty");
  await waitFor(
    () => vscode.languages.getDiagnostics(activeDocument.uri).some(
      (diagnostic) => diagnostic.source === "RustFerry" && diagnosticCode(diagnostic) === "ferry.config.app-identifier"
    ),
    20_000,
    "unsaved manifest validation diagnostic"
  );
  assert.equal(readFileSync(expectedManifest, "utf8"), savedManifest, "dirty validation changed ferry.toml on disk");
  await vscode.commands.executeCommand("workbench.action.files.revert");
  assert.equal(activeDocument.isDirty, false, "ferry.toml remained dirty after host-smoke cleanup");

  const hostStartedAtMs = Number(process.env.RUSTFERRY_HOST_STARTED_AT_MS);
  assert.ok(Number.isFinite(hostStartedAtMs), "RUSTFERRY_HOST_STARTED_AT_MS was not supplied");
  emitMeasurements({
    hostStartupToActivationMs: Date.now() - hostStartedAtMs,
    activationMs: snapshot.activationMs,
    projectDiscoveryMs: snapshot.projectDiscoveryMs,
    initialTreeRefreshMs: snapshot.treeRefreshMs,
    repeatedTreeRefreshMedianMs: median(refreshSamples),
    openDiscoveredManifestMs: openManifestMs
  });
}

function diagnosticCode(diagnostic) {
  return typeof diagnostic.code === "object" ? diagnostic.code.value : diagnostic.code;
}

function performanceApi(value) {
  if (typeof value !== "object" || value === null || typeof value.performanceSnapshot !== "function") {
    return undefined;
  }
  return value;
}

async function waitFor(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) {
      throw new Error(`Timed out waiting for ${label}`);
    }
    await delay(50);
  }
}

async function waitForValue(read, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = read();
    if (value !== undefined) {
      return value;
    }
    if (Date.now() >= deadline) {
      throw new Error(`Timed out waiting for ${label}`);
    }
    await delay(50);
  }
}

function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.floor(sorted.length / 2)];
}

function assertNonNegative(value, field) {
  assert.equal(typeof value, "number", `${field} was not numeric`);
  assert.ok(Number.isFinite(value) && value >= 0, `${field} was not finite and non-negative`);
}

function emitMeasurements(measurements) {
  process.stdout.write(`RUSTFERRY_HOST_PERF ${JSON.stringify({
    schemaVersion: 1,
    unit: "milliseconds",
    measurements
  })}\n`);
}

module.exports = { run };
