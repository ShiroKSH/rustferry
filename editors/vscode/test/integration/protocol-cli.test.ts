import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import type * as vscode from "vscode";
import { describe, expect, it } from "vitest";

import { CliClient } from "../../src/cli/client.js";
import { ProcessRunner } from "../../src/cli/process.js";
import {
  NdjsonDecoder,
  eventDiagnostic,
  parseDeviceSnapshotResponse,
  parseHandshake,
  parseJobsListResponse,
  parseJsonObject,
  parseProjectResponse,
  parseValidationResponse
} from "../../src/cli/protocol.js";

const executable = process.env.RUSTFERRY_TEST_CLI;

describe.runIf(executable !== undefined)("live cargo-ferry IDE protocol", () => {
  const workspace = path.resolve(process.cwd(), "../../examples/counter");

  it("reads workspace-bound jobs through the negotiated IDE commands", async () => {
    const handshake = parseHandshake(run(["ide", "handshake", "--json"]).stdout);
    expect(handshake.supported_commands).toEqual(expect.arrayContaining([
      "jobs-list",
      "jobs-show",
      "jobs-artifacts",
      "jobs-logs"
    ]));
    expect(handshake.supported_commands.includes("remote-build-preview")).toBe(
      handshake.supported_commands.includes("remote-build-submit")
    );
    const jobs = parseJobsListResponse(run([
      "ide",
      "jobs-list",
      "--workspace",
      workspace,
      "--limit",
      "50",
      "--json"
    ]).stdout);
    expect(jobs.returned).toBe(jobs.jobs.length);
    expect(jobs.limit).toBe(50);
    expect(jobs.workspace.toLowerCase()).toContain(workspace.toLowerCase());

    const runner = new ProcessRunner();
    const client = new CliClient(
      { executable: executable!, prefixArgs: [], source: "path" },
      runner,
      { appendLine: () => undefined } as unknown as vscode.OutputChannel,
      1_048_576
    );
    try {
      await expect(client.jobsList(workspace)).resolves.toMatchObject({
        response: { limit: 50, returned: jobs.returned }
      });
      await expect(client.jobShow(workspace, "job-missing")).rejects.toMatchObject({
        code: "job_not_found"
      });
      await expect(client.jobArtifacts(workspace, "job-missing")).rejects.toMatchObject({
        code: "job_not_found"
      });
      if (handshake.supported_commands.includes("jobs-logs-page")) {
        await expect(client.jobLogsPage(
          workspace,
          "job-missing",
          { afterSequence: "0", limit: 256 }
        )).rejects.toMatchObject({ code: "job_not_found" });
      }
    } finally {
      runner.dispose();
    }
  });

  it("aligns handshake, project, validation, schema, and failed stream output", () => {
    const handshake = parseHandshake(run(["ide", "handshake", "--json"]).stdout);
    expect(handshake.protocol_version).toBe(1);
    expect(handshake.tool.name).toBe("cargo-ferry");
    expect(handshake.templates.length).toBeGreaterThan(0);

    const project = parseProjectResponse(run(["ide", "project", "--workspace", workspace, "--json"]).stdout);
    expect(project.project.config_path).toBe(path.join(workspace, "ferry.toml"));
    expect(project.project.target_directory).toContain(path.join("target", "ferry"));

    const validation = parseValidationResponse(run(["ide", "validate", "--workspace", workspace, "--json"]).stdout);
    expect(validation.valid).toBe(true);
    expect(validation.diagnostics).toEqual([]);

    const schema = parseJsonObject(run(["ide", "schema", "--json"]).stdout, "cargo-ferry schema");
    expect(schema.$schema).toBeTypeOf("string");

    const capabilities = parseJsonObject(
      run(["capabilities", "--json"], path.dirname(workspace)).stdout,
      "cargo-ferry capabilities"
    );
    expect(capabilities).toMatchObject({ schema_version: 1, status: "ok" });
    expect(capabilities.data).toBeInstanceOf(Array);

    const devices = parseDeviceSnapshotResponse(run(["ide", "devices", "--platform", "all", "--json-stream"]).stdout);
    expect(devices.devices).toBeInstanceOf(Array);
    expect(devices.warnings).toBeInstanceOf(Array);

    const failed = run([
      "ide",
      "build",
      "--workspace",
      path.join(workspace, "missing", "workspace"),
      "--platform",
      "android",
      "--operation-id",
      "vscode:smoke",
      "--json-stream"
    ], false);
    expect(failed.status).not.toBe(0);
    const decoder = new NdjsonDecoder(1_048_576);
    const events = decoder.push(Buffer.from(failed.stdout));
    decoder.finish();
    expect(events.map((event) => event.event)).toEqual(expect.arrayContaining(["operation_started", "diagnostic", "operation_finished"]));
    expect(events.at(-1)).toMatchObject({ event: "operation_finished", success: false });
  }, 30_000);

  it("validates exact unsaved manifest source without changing the saved file", () => {
    const manifest = path.join(workspace, "ferry.toml");
    const saved = readFileSync(manifest, "utf8");
    const unsaved = saved.replace(
      'identifier = "com.example.counter"',
      'identifier = "not-an-identifier"'
    );
    expect(unsaved).not.toBe(saved);

    const result = spawnSync(executable!, [
      "ide",
      "validate",
      "--workspace",
      workspace,
      "--manifest-stdin",
      "--json"
    ], {
      cwd: path.resolve(process.cwd(), "../.."),
      encoding: "utf8",
      input: unsaved,
      maxBuffer: 2 * 1024 * 1024,
      shell: false
    });
    if (result.error !== undefined) {
      throw result.error;
    }
    expect(result.status).toBe(0);
    const validation = parseValidationResponse(result.stdout);
    expect(validation.valid).toBe(false);
    expect(validation.diagnostics[0]?.file).toBe(manifest);
    expect(readFileSync(manifest, "utf8")).toBe(saved);
  });

  it.runIf(process.platform !== "win32")("streams fake Cargo diagnostics through IDE Check", async () => {
    const tools = await mkdtemp(path.join(os.tmpdir(), "rustferry-vscode-check-tools-"));
    const fakeCargo = path.join(tools, "cargo");
    const compilerMessage = {
      reason: "compiler-message",
      message: {
        message: "mismatched types",
        code: { code: "E0308", explanation: null },
        level: "error",
        spans: [{
          file_name: "src/app.rs",
          line_start: 7,
          line_end: 7,
          column_start: 5,
          column_end: 8,
          is_primary: true,
          text: [{ text: "    bad", highlight_start: 5, highlight_end: 8 }]
        }],
        children: [{ message: "use the expected type", level: "help" }],
        rendered: "error[E0308]: mismatched types\n --> src/app.rs:7:5\n"
      }
    };
    await writeFile(
      fakeCargo,
      `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(`${JSON.stringify(compilerMessage)}\n`)});\nprocess.exit(101);\n`,
      "utf8"
    );
    await chmod(fakeCargo, 0o755);
    try {
      const result = spawnSync(executable!, [
        "ide",
        "check",
        "--workspace",
        workspace,
        "--operation-id",
        "vscode:check-diagnostic",
        "--json-stream"
      ], {
        cwd: path.resolve(process.cwd(), "../.."),
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${tools}${path.delimiter}${process.env.PATH ?? ""}`
        },
        maxBuffer: 2 * 1024 * 1024,
        shell: false
      });
      if (result.error !== undefined) {
        throw result.error;
      }
      expect(result.status).toBe(4);
      expect(result.stderr).toBe("");
      const decoder = new NdjsonDecoder(1_048_576);
      const events = decoder.push(Buffer.from(result.stdout));
      decoder.finish();
      const diagnostics = events
        .map(eventDiagnostic)
        .filter((diagnostic) => diagnostic !== undefined);
      expect(diagnostics).toEqual([expect.objectContaining({
        code: "rustc.E0308",
        file: path.join(workspace, "src/app.rs"),
        range: {
          start: { line: 6, character: 4 },
          end: { line: 6, character: 7 }
        }
      })]);
      expect(events[0]).toMatchObject({ event: "operation_started", command: "check" });
      expect(events.at(-1)).toMatchObject({ event: "operation_finished", success: false });
      expect(events.some((event) => event.event === "artifact")).toBe(false);
    } finally {
      await rm(tools, { recursive: true, force: true });
    }
  });

  it("runs the development wizard contract with an explicit display name and capability", async () => {
    const repository = path.resolve(process.cwd(), "../..");
    const parent = await mkdtemp(path.join(os.tmpdir(), "rustferry-vscode-live-wizard-"));
    const runner = new ProcessRunner();
    const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
    const invocation = {
      executable: executable!,
      prefixArgs: [],
      source: "development" as const,
      developmentRoot: repository
    };
    const client = new CliClient(invocation, runner, output, 1_048_576);
    try {
      const generated = await client.newProject({
        parent,
        name: "harbor-demo",
        displayName: "Harbor Demo 🚢",
        identifier: "com.rustferry.harbordemo",
        template: "minimal",
        platform: "both",
        initializeGit: false,
        skipCheck: true,
        runtimePath: path.join(invocation.developmentRoot, "crates", "rustferry")
      });
      const projectPath = typeof generated.project === "string"
        ? generated.project
        : path.join(parent, "harbor-demo");
      const project = await client.project(projectPath);
      expect(project.project.display_name).toBe("Harbor Demo 🚢");
      expect(project.project.identifier).toBe("com.rustferry.harbordemo");

      await client.mutateCapability(projectPath, "network", true);
      const updated = await client.project(projectPath);
      expect(updated.project.capabilities).toContain("network");
    } finally {
      runner.dispose();
      await rm(parent, { recursive: true, force: true });
    }
  }, 120_000);
});

function run(
  args: readonly string[],
  cwdOrRequireSuccess: string | boolean = true,
  requireSuccess = true
): Readonly<{ status: number | null; stdout: string; stderr: string }> {
  const cwd = typeof cwdOrRequireSuccess === "string" ? cwdOrRequireSuccess : path.resolve(process.cwd(), "../..");
  const shouldSucceed = typeof cwdOrRequireSuccess === "boolean" ? cwdOrRequireSuccess : requireSuccess;
  const result = spawnSync(executable!, [...args], {
    cwd,
    encoding: "utf8",
    maxBuffer: 2 * 1024 * 1024,
    shell: false
  });
  if (result.error !== undefined) {
    throw result.error;
  }
  if (shouldSucceed && result.status !== 0) {
    throw new Error(`cargo-ferry ${args.join(" ")} failed: ${result.stderr}`);
  }
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
