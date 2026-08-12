import type * as vscode from "vscode";
import { describe, expect, it } from "vitest";

import {
  CliClient,
  CliCommandError,
  approveRemoteBuildPreview,
  deploymentStreamRequest
} from "../../src/cli/client.js";
import type { ProcessRequest, ProcessRunner, ProcessResult } from "../../src/cli/process.js";
import { ProtocolError, type ProtocolEvent } from "../../src/cli/protocol.js";
import { jobIdeCommands, remoteIdeCommands } from "../../src/constants.js";

const invocation = { executable: "cargo-ferry", prefixArgs: [], source: "path" } as const;
const success: ProcessResult = { code: 0, signal: null, stdout: "", stderr: "" };
const digest = "a".repeat(64);

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

describe("workspace-bound job requests", () => {
  it("freshly handshakes, requires the exact command, and passes workspace on the endpoint call", async () => {
    const requests: ProcessRequest[] = [];
    const runner = {
      runBuffered: (request: ProcessRequest): Promise<ProcessResult> => {
        requests.push(request);
        const command = request.args[1];
        return Promise.resolve({
          ...success,
          stdout: command === "handshake"
            ? JSON.stringify(handshake([jobIdeCommands.list]))
            : JSON.stringify({
                protocol_version: 1,
                workspace: "C:\\work\\ferry",
                limit: 50,
                returned: 0,
                jobs: []
              })
        });
      }
    } as unknown as ProcessRunner;
    const client = new CliClient(
      invocation,
      runner,
      { appendLine: () => undefined } as unknown as vscode.OutputChannel,
      1_048_576
    );

    await expect(client.jobsList("C:\\work\\ferry")).resolves.toMatchObject({
      response: { workspace: "C:\\work\\ferry", jobs: [] }
    });
    await client.jobsList("C:\\work\\ferry");
    expect(requests).toHaveLength(4);
    expect(requests[0]?.args).toEqual(["ide", "handshake", "--json"]);
    expect(requests[1]?.args).toEqual([
      "ide",
      jobIdeCommands.list,
      "--workspace",
      "C:\\work\\ferry",
      "--limit",
      "50",
      "--json"
    ]);
    expect(requests[1]?.cwd).toBe("C:\\work\\ferry");
    expect(requests[2]?.args).toEqual(["ide", "handshake", "--json"]);
    expect(requests[3]?.args).toEqual(requests[1]?.args);
  });

  it("rejects a parsed response bound to a different workspace", async () => {
    const requests: ProcessRequest[] = [];
    const runner = bufferedRunner(requests, (command) => command === "handshake"
      ? handshake([jobIdeCommands.list])
      : {
          protocol_version: 1,
          workspace: "C:\\other",
          limit: 50,
          returned: 0,
          jobs: []
        });
    const client = testClient(runner);

    await expect(client.jobsList("C:\\work\\ferry")).rejects.toMatchObject({
      code: "protocol.workspace_mismatch"
    });
  });

  it("does not execute a prefix-matched or cached-looking job action", async () => {
    const requests: ProcessRequest[] = [];
    const runner = {
      runBuffered: (request: ProcessRequest): Promise<ProcessResult> => {
        requests.push(request);
        return Promise.resolve({
          ...success,
          stdout: JSON.stringify(handshake([`${jobIdeCommands.cancel}-future`]))
        });
      }
    } as unknown as ProcessRunner;
    const client = new CliClient(
      invocation,
      runner,
      { appendLine: () => undefined } as unknown as vscode.OutputChannel,
      1_048_576
    );

    await expect(client.cancelJob(
      "C:\\work\\ferry",
      "job-1",
      new AbortController().signal
    )).rejects.toMatchObject({
      code: "protocol.command_unsupported"
    });
    expect(requests).toHaveLength(1);
  });

  it("never sends page flags to a CLI that advertises only the isolated legacy log snapshot", async () => {
    const requests: ProcessRequest[] = [];
    const runner = bufferedRunner(requests, (command) => command === "handshake"
      ? handshake([jobIdeCommands.logs])
      : legacyLogSnapshot());
    const client = testClient(runner);

    await expect(client.jobLogsPage(
      "C:\\work\\ferry",
      "job-1",
      { afterSequence: "0", limit: 2, refresh: true }
    )).rejects.toMatchObject({ code: "protocol.command_unsupported" });
    expect(requests).toHaveLength(1);

    await expect(client.legacyJobLogsSnapshot(
      "C:\\work\\ferry",
      "job-1"
    )).resolves.toMatchObject({ response: { local_job_id: "job-1" } });
    const legacyRequest = requests[2];
    expect(legacyRequest?.args[1]).toBe(jobIdeCommands.logs);
    expect(legacyRequest?.args).toContain("--since");
    expect(legacyRequest?.args).not.toContain("--after-sequence");
    expect(legacyRequest?.args).not.toContain("--limit");
    expect(legacyRequest?.args).not.toContain("--refresh");
    expect(legacyRequest?.args).not.toContain("--wait");
  });

  it("uses distinct durable cancel/retry receipts with cancellable no-timeout processes", async () => {
    const requests: ProcessRequest[] = [];
    const parent = {
      ...showJob("job-1"),
      retry: { attempt: 0, parent_job_id: null, child_job_ids: ["job-2"] }
    };
    const child = {
      ...showJob("job-2"),
      operation_id: "operation-2",
      retry: { attempt: 1, parent_job_id: "job-1", child_job_ids: [] }
    };
    const runner = bufferedRunner(requests, (command) => {
      if (command === "handshake") {
        return handshake([jobIdeCommands.cancel, jobIdeCommands.retry]);
      }
      if (command === jobIdeCommands.cancel) {
        return {
          protocol_version: 1,
          workspace: "C:\\work\\ferry",
          parent: { ...parent, revision: 5, cancellation_status: "requested" },
          receipt: {
            kind: "cancellation_requested",
            parent_local_job_id: "job-1",
            durable: true,
            revision: 5
          }
        };
      }
      return {
        protocol_version: 1,
        workspace: "C:\\work\\ferry",
        parent,
        child,
        lineage: {
          parent_local_job_id: "job-1",
          child_local_job_id: "job-2",
          attempt: 1
        },
        receipt: { kind: "retry_created", disposition: "created", durable: true }
      };
    });
    const client = testClient(runner);
    const signal = new AbortController().signal;

    await expect(client.cancelJob("C:\\work\\ferry", "job-1", signal)).resolves.toMatchObject({
      response: { parent: { local_job_id: "job-1", cancellation_status: "requested" } }
    });
    await expect(client.retryJob("C:\\work\\ferry", "job-1", signal)).resolves.toMatchObject({
      response: {
        parent: { local_job_id: "job-1" },
        child: { local_job_id: "job-2" }
      }
    });
    expect(requests[1]).toMatchObject({ timeoutMs: 0, signal });
    expect(requests[3]).toMatchObject({ timeoutMs: 0, signal });
  });

  it("loads and follows bounded log pages without accumulating or repolling while draining", async () => {
    const requests: ProcessRequest[] = [];
    const pages = [
      logPage("0", "1", true, false, "1"),
      logPage("1", "2", false, false, "2"),
      logPage("2", "3", false, true, "3")
    ];
    const runner = bufferedRunner(requests, (command) => command === "handshake"
      ? handshake([jobIdeCommands.logsPage])
      : pages.shift());
    const client = testClient(runner);
    const pageCursors: string[] = [];
    const eventSequences: string[] = [];
    const signal = new AbortController().signal;

    await client.followJobLogs(
      "C:\\work\\ferry",
      "job-1",
      { afterSequence: "0", limit: 2, refresh: true },
      {
        onPage: (page) => {
          pageCursors.push(page.next_after_sequence);
        },
        onEvent: (event) => {
          eventSequences.push(event.sequence);
        }
      },
      signal
    );

    expect(pageCursors).toEqual(["1", "2", "3"]);
    expect(eventSequences).toEqual(["1", "2", "3"]);
    const logRequests = requests.filter((request) => request.args[1] === jobIdeCommands.logsPage);
    expect(logRequests).toHaveLength(3);
    expect(logRequests[0]?.args).toContain("--refresh");
    expect(logRequests[1]?.args).not.toContain("--refresh");
    expect(logRequests[1]?.args).not.toContain("--wait");
    expect(logRequests[2]?.args).toContain("--refresh");
    expect(logRequests[2]?.args).toContain("--wait");
    expect(logRequests[2]).toMatchObject({ timeoutMs: 0, signal });
  });

  it("stops log following on cancellation without issuing another request", async () => {
    const requests: ProcessRequest[] = [];
    const runner = bufferedRunner(requests, (command) => command === "handshake"
      ? handshake([jobIdeCommands.logsPage])
      : {
          ...logPage("0", "1", false, false, "1"),
          returned: 0,
          next_after_sequence: "0",
          events: []
        });
    const client = testClient(runner);
    const controller = new AbortController();

    await expect(client.followJobLogs(
      "C:\\work\\ferry",
      "job-1",
      { afterSequence: "0", limit: 2 },
      {
        onPage: () => {
          controller.abort();
        }
      },
      controller.signal
    )).rejects.toMatchObject({ name: "ProcessCancelledError" });
    expect(requests).toHaveLength(2);
  });

  it("rejects a jobs-list response that does not bind the requested limit", async () => {
    const requests: ProcessRequest[] = [];
    const runner = bufferedRunner(requests, (command) => command === "handshake"
      ? handshake([jobIdeCommands.list])
      : {
          protocol_version: 1,
          workspace: "C:\\work\\ferry",
          limit: 49,
          returned: 0,
          jobs: []
        });

    await expect(testClient(runner).jobsList("C:\\work\\ferry")).rejects.toMatchObject({
      code: "protocol.request_mismatch"
    });
    expect(requests[1]?.args).toContain("50");
  });

  it("keeps remove confirmation server-authoritative and path-free reveal in Rust", async () => {
    const requests: ProcessRequest[] = [];
    const runner = bufferedRunner(requests, (command) => {
      if (command === "handshake") {
        return handshake([jobIdeCommands.artifactReveal, jobIdeCommands.artifactRemove]);
      }
      if (command === jobIdeCommands.artifactReveal) {
        return {
          ...artifactActionIdentity(),
          receipt: {
            launcher: "explorer.exe",
            environment_policy: "fixed_no_inheritance",
            launch_requested: true,
            exact_path_bound_during_launch: true,
            post_launch_revalidation: "passed"
          }
        };
      }
      return {
        ...artifactActionIdentity(),
        receipt: {
          confirmation_provided: true,
          executed: true,
          result_state: "removed",
          already_complete: false,
          replacement_preserved: false
        }
      };
    });
    const client = testClient(runner);
    const signal = new AbortController().signal;
    await expect(client.revealJobArtifact(
      "C:\\work\\ferry",
      "job-1",
      "artifact-1",
      signal
    )).resolves.toMatchObject({ response: { status: "revealed" } });
    await client.removeJobArtifact("C:\\work\\ferry", "job-1", "artifact-1", signal);

    const revealRequest = requests.find(
      (request) => request.args[1] === jobIdeCommands.artifactReveal
    );
    const removeRequest = requests.find(
      (request) => request.args[1] === jobIdeCommands.artifactRemove
    );
    expect(revealRequest?.args).not.toContain("--path");
    expect(revealRequest).toMatchObject({ timeoutMs: 0, signal });
    expect(removeRequest?.args).toContain("--yes");
    expect(removeRequest).toMatchObject({ timeoutMs: 0, signal });
  });

  it("submits only a workspace-bound parsed snapshot consent through stdin", async () => {
    const requests: ProcessRequest[] = [];
    const runner = bufferedRunner(requests, (command) => {
      if (command === "handshake") {
        return handshake([
          remoteIdeCommands.buildPreview,
          remoteIdeCommands.buildSubmit
        ]);
      }
      if (command === remoteIdeCommands.buildPreview) {
        return {
          protocol_version: 1,
          workspace: "C:\\work\\ferry",
          provider: "github",
          target: "ios-device",
          profile: "release",
          signing_mode: "unsigned",
          source_mode: "snapshot",
          preview_sha256: digest,
          consent_token: "c".repeat(32),
          source: { manifest_sha256: digest, file_count: "12", total_bytes: "4096" },
          effects: ["create_private_snapshot", "submit_remote_job"],
          consent_required: true
        };
      }
      return {
        protocol_version: 1,
        workspace: "C:\\work\\ferry",
        job: { ...showJob("job-remote"), target: "iphone" },
        receipt: {
          kind: "remote_build_submitted",
          durable: true,
          source_mode: "snapshot",
          preview_sha256: digest
        }
      };
    });
    const client = testClient(runner);
    const preview = await client.remoteBuildPreview("C:\\work\\ferry", { profile: "release" });
    expect(Object.isFrozen(preview.response)).toBe(true);
    expect(Object.isFrozen(preview.response.source)).toBe(true);
    expect(Object.isFrozen(preview.response.effects)).toBe(true);
    expect(() => approveRemoteBuildPreview({ ...preview.response })).toThrow(ProtocolError);
    const consent = approveRemoteBuildPreview(preview.response);
    const signal = new AbortController().signal;

    await expect(client.submitRemoteBuild(
      "C:\\other",
      consent,
      signal
    )).rejects.toMatchObject({ code: "protocol.consent_required" });
    await client.submitRemoteBuild("C:\\work\\ferry", consent, signal);

    const submitRequest = requests.find(
      (request) => request.args[1] === remoteIdeCommands.buildSubmit
    );
    expect(submitRequest).toMatchObject({ timeoutMs: 0, signal });
    expect(submitRequest?.args).toContain("--consent-stdin");
    expect(submitRequest?.args.join(" ")).not.toContain("c".repeat(32));
    expect(submitRequest?.args.join(" ")).not.toContain(digest);
    expect(JSON.parse(submitRequest?.stdin ?? "{}")).toEqual({
      consent_token: "c".repeat(32),
      preview_sha256: digest,
      approved: true
    });
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

function testClient(runner: ProcessRunner): CliClient {
  return new CliClient(
    invocation,
    runner,
    { appendLine: () => undefined } as unknown as vscode.OutputChannel,
    1_048_576
  );
}

function bufferedRunner(
  requests: ProcessRequest[],
  response: (command: string | undefined) => unknown
): ProcessRunner {
  return {
    runBuffered: (request: ProcessRequest): Promise<ProcessResult> => {
      requests.push(request);
      const value = response(request.args[1]);
      if (value === undefined) {
        throw new Error(`Missing test response for ${request.args[1] ?? "unknown command"}.`);
      }
      return Promise.resolve({ ...success, stdout: JSON.stringify(value) });
    }
  } as unknown as ProcessRunner;
}

function showJob(localJobId: string): Record<string, unknown> {
  return {
    local_job_id: localJobId,
    revision: 1,
    provider: {
      name: "github",
      config_sha256: digest,
      principal: { kind: "user", id: "1", login: "owner" },
      execution_repository_id: "2"
    },
    provider_job_id: "101",
    provider_run_id: "201",
    operation_id: "operation-1",
    request_sha256: digest,
    semantic_retry_sha256: digest,
    application_identifier: "com.example.ferry",
    source_revision: "b".repeat(40),
    source_manifest_sha256: digest,
    target: "aarch64-apple-ios",
    profile: "release",
    signing_mode: "unsigned-compile-only",
    created_at_ms: 1_700_000_000_000,
    submitted_at_ms: 1_700_000_000_100,
    updated_at_ms: 1_700_000_000_200,
    state: "running",
    last_confirmed_state: "running",
    terminal_outcome: null,
    cleanup_status: "pending",
    cancellation_status: "none",
    retry: { attempt: 0, parent_job_id: null, child_job_ids: [] },
    failure: null,
    artifact_count: 0,
    event_journal_bound: true,
    provider_resume_available: true
  };
}

function logPage(
  afterSequence: string,
  nextAfterSequence: string,
  hasMore: boolean,
  terminal: boolean,
  eventSequence: string
): Record<string, unknown> {
  return {
    protocol_version: 1,
    workspace: "C:\\work\\ferry",
    local_job_id: "job-1",
    log_scope: "durable_sanitized_job_events",
    provider_full_logs: false,
    after_sequence: afterSequence,
    limit: 2,
    returned: 1,
    next_after_sequence: nextAfterSequence,
    has_more: hasMore,
    terminal,
    events: [{
      record_kind: "sanitized_lifecycle_event",
      sequence: eventSequence,
      occurred_at_ms: 1_700_000_000_000,
      source: "controller",
      level: "info",
      code: "job.progress"
    }]
  };
}

function legacyLogSnapshot(): Record<string, unknown> {
  return {
    protocol_version: 1,
    workspace: "C:\\work\\ferry",
    local_job_id: "job-1",
    log_scope: "durable_sanitized_lifecycle_events",
    provider_full_logs: false,
    since_ms: 0,
    phase: null,
    returned: 0,
    next_sequence: 0,
    terminal: false,
    events: []
  };
}

function artifactActionIdentity(): Record<string, unknown> {
  return {
    protocol_version: 1,
    workspace: "C:\\work\\ferry",
    local_job_id: "job-1",
    artifact_id: "artifact-1",
    revision: 1
  };
}

function handshake(supportedCommands: readonly string[]): Record<string, unknown> {
  return {
    protocol_version: 1,
    tool: { name: "cargo-ferry", version: "0.1.0" },
    host: { os: "windows", arch: "x86_64" },
    supported_protocol_versions: [1],
    supported_platforms: ["android", "ios-simulator", "ios-device"],
    supported_commands: supportedCommands,
    supported_event_types: [],
    features: {
      android_build: true,
      ios_simulator_build: false,
      devices: true,
      install: true,
      run: true,
      logs: true,
      physical_ios: false,
      cancellation: true
    },
    build: { profile: "debug", target: "windows-x86_64", development: true },
    runtime_dependency: { usable: true, source: "path" },
    templates: []
  };
}
