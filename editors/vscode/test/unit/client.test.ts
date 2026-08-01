import type * as vscode from "vscode";
import { describe, expect, it } from "vitest";

import { CliClient, CliCommandError, deploymentStreamRequest } from "../../src/cli/client.js";
import type { ProcessRequest, ProcessRunner, ProcessResult } from "../../src/cli/process.js";
import { ProtocolError, type ProtocolEvent } from "../../src/cli/protocol.js";

const invocation = { executable: "cargo-ferry", prefixArgs: [], source: "path" } as const;
const success: ProcessResult = { code: 0, signal: null, stdout: "", stderr: "" };

describe("CLI manifest validation input", () => {
  it("sends unsaved source only through bounded stdin with an explicit protocol flag", async () => {
    const source = "[app]\nname = \"Unsaved Ferry\"\n";
    const controller = new AbortController();
    let captured: ProcessRequest | undefined;
    const runner = {
      runBuffered: (request: ProcessRequest): Promise<ProcessResult> => {
        captured = request;
        return Promise.resolve({
          ...success,
          stdout: JSON.stringify({
            protocol_version: 1,
            workspace: "/tmp/rustferry-client-test",
            valid: true,
            diagnostics: []
          })
        });
      }
    } as unknown as ProcessRunner;
    const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
    const client = new CliClient(invocation, runner, output, 1_048_576);

    await client.validate("/tmp/rustferry-client-test", {
      manifestSource: source,
      signal: controller.signal
    });

    expect(captured).toBeDefined();
    expect(captured?.args).toContain("--manifest-stdin");
    expect(captured?.args.every((argument) => !argument.includes(source))).toBe(true);
    expect(captured?.stdin).toBe(source);
    expect(captured?.signal).toBe(controller.signal);
  });
});

describe("CLI stream contract", () => {
  it("runs Check through the IDE stream and forwards compiler diagnostics", async () => {
    const compilerDiagnostic = {
      severity: "error",
      code: "rustc.E0308",
      message: "mismatched types",
      file: "/tmp/rustferry-client-test/src/app.rs",
      range: {
        start: { line: 6, character: 4 },
        end: { line: 6, character: 7 }
      },
      help: "use the expected type",
      documentation: "https://doc.rust-lang.org/error_codes/E0308.html",
      fixes: []
    };
    let captured: ProcessRequest | undefined;
    const runner = {
      runNdjson: async (
        request: ProcessRequest,
        _maxLineBytes: number,
        onEvent: (event: ProtocolEvent) => void | Promise<void>
      ): Promise<ProcessResult> => {
        captured = request;
        const operationIndex = request.args.indexOf("--operation-id");
        const operationId = request.args[operationIndex + 1];
        expect(operationId).toBeTypeOf("string");
        await onEvent(event("operation_started", { command: "check" }, operationId));
        await onEvent(event("diagnostic", { diagnostic: compilerDiagnostic }, operationId));
        await onEvent(event("phase_finished", { phase: "rust_check", success: false, duration_ms: 1 }, operationId));
        await onEvent(event("operation_finished", {
          success: false,
          duration_ms: 1,
          error: { code: "external_command_failed", message: "Rust project validation failed." }
        }, operationId));
        return { ...success, code: 4 };
      }
    } as unknown as ProcessRunner;
    const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
    const client = new CliClient(invocation, runner, output, 1_048_576);
    const diagnostics: unknown[] = [];

    await expect(client.check(
      "/tmp/rustferry-client-test",
      (protocolEvent) => {
        if (protocolEvent.event === "diagnostic") {
          diagnostics.push(protocolEvent.diagnostic);
        }
      }
    )).rejects.toMatchObject({ name: "CliCommandError", code: "external_command_failed" });

    expect(captured?.args.slice(0, 2)).toEqual(["ide", "check"]);
    expect(captured?.args).toContain("--json-stream");
    expect(captured?.args).not.toContain("--platform");
    expect(diagnostics).toEqual([compilerDiagnostic]);
  });

  it("rebuilds deployment artifacts instead of sending an untrusted path", () => {
    const value = deploymentStreamRequest(
      "install",
      "/tmp/rustferry client",
      "ios-simulator",
      "SIM-1",
      "deploy-1"
    );
    expect(value).not.toHaveProperty("artifact");
    expect(value).toMatchObject({
      operation: "install",
      platform: "ios-simulator",
      device: "SIM-1"
    });
  });

  it("passes a non-secret Development Team through argv for physical deployment", () => {
    expect(deploymentStreamRequest(
      "run",
      "/tmp/rustferry client",
      "ios-device",
      "PHONE-1",
      "deploy-physical-1",
      "ABCDE12345"
    )).toMatchObject({
      operation: "run",
      platform: "ios-device",
      device: "PHONE-1",
      team: "ABCDE12345"
    });
  });

  it("surfaces a typed terminal operation failure", async () => {
    const client = createClient([
      event("operation_started", { command: "build" }),
      event("operation_finished", {
        success: false,
        duration_ms: 1,
        error: {
          code: "project-not-found",
          message: "Project not found.",
          help: "Open a folder containing ferry.toml.",
          details: ["missing ferry.toml"]
        }
      })
    ], { ...success, code: 2 });

    const failure = client.stream(request(), () => undefined);
    await expect(failure).rejects.toBeInstanceOf(CliCommandError);
    await expect(failure).rejects.toMatchObject({
      name: "CliCommandError",
      code: "project-not-found",
      message: "Project not found.",
      help: "Open a folder containing ferry.toml.",
      details: ["missing ferry.toml"]
    });
  });

  it("rejects events for a different operation", async () => {
    const client = createClient([
      {
        ...event("operation_started", { command: "build" }),
        operation_id: "other-operation"
      }
    ]);

    const failure = client.stream(request(), () => undefined);
    await expect(failure).rejects.toBeInstanceOf(ProtocolError);
    await expect(failure).rejects.toMatchObject({
      code: "protocol.operation_mismatch"
    });
  });

  it("rejects a zero-exit stream without a terminal event", async () => {
    const client = createClient([
      event("operation_started", { command: "build" }),
      event("progress", { phase: "build", message: "still working" })
    ]);

    await expect(client.stream(request(), () => undefined)).rejects.toMatchObject({
      code: "protocol.missing_terminal"
    });
  });

  it("rejects any event after the terminal event", async () => {
    const client = createClient([
      event("operation_started", { command: "build" }),
      event("operation_finished", { success: true, duration_ms: 1 }),
      event("warning", { message: "late event" })
    ]);

    await expect(client.stream(request(), () => undefined)).rejects.toMatchObject({
      code: "protocol.event_after_terminal"
    });
  });
});

function createClient(events: readonly ProtocolEvent[], result: ProcessResult = success): CliClient {
  const runner = {
    runNdjson: async (
      _request: unknown,
      _maxLineBytes: number,
      onEvent: (event: ProtocolEvent) => void | Promise<void>
    ): Promise<ProcessResult> => {
      for (const protocolEvent of events) {
        await onEvent(protocolEvent);
      }
      return result;
    }
  } as unknown as ProcessRunner;
  const output = { appendLine: () => undefined } as unknown as vscode.OutputChannel;
  return new CliClient(invocation, runner, output, 1_048_576);
}

function request() {
  return {
    operation: "build" as const,
    workspace: "/tmp/rustferry-client-test",
    platform: "android",
    profile: "debug" as const,
    operationId: "expected-operation"
  };
}

function event(
  name: string,
  fields: Readonly<Record<string, unknown>>,
  operationId = "expected-operation"
): ProtocolEvent {
  return {
    protocol_version: 1,
    operation_id: operationId,
    timestamp_ms: 1,
    event: name,
    ...fields
  };
}
