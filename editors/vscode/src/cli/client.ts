import { randomUUID } from "node:crypto";

import type * as vscode from "vscode";

import type { CliInvocation } from "./discovery.js";
import {
  ProtocolError,
  assertProtocolVersion,
  isRecord,
  parseHandshake,
  parseDeviceSnapshotResponse,
  parseJsonObject,
  parseProjectResponse,
  parseSigningTeamsResponse,
  parseValidationResponse,
  type BuildProfile,
  type DeviceSnapshotResponse,
  type Handshake,
  type LegacyJsonError,
  type ProjectResponse,
  type SigningTeamsResponse,
  type ProtocolEvent,
  type ValidationResponse
} from "./protocol.js";
import { ProcessCancelledError, ProcessExecutionError, ProcessRunner, type ProcessResult } from "./process.js";

const UNARY_TIMEOUT_MS = 20_000;

export type ValidationRequest = Readonly<{
  manifestSource?: string;
  signal?: AbortSignal;
}>;

export type StreamRequest = Readonly<{
  operation: "check" | "build" | "install" | "run" | "logs";
  workspace: string;
  platform?: string;
  profile?: BuildProfile;
  device?: string;
  artifact?: string;
  team?: string;
  allowProvisioningUpdates?: boolean;
  provisioningProfile?: string;
  operationId?: string;
  parentOperationId?: string;
}>;

export function deploymentStreamRequest(
  operation: "install" | "run",
  workspace: string,
  platform: string,
  device: string,
  operationId: string,
  team?: string
): StreamRequest {
  return {
    operation,
    workspace,
    platform,
    device,
    operationId,
    ...(team === undefined ? {} : { team })
  };
}

export type CapabilityMetadata = Readonly<{
  name: string;
  enabled?: boolean | null;
  runtime?: string;
  android?: string;
  ios?: string;
}>;

export type TemplateMetadata = Readonly<{
  name: string;
  purpose?: string;
}>;

export type NewProjectRequest = Readonly<{
  parent: string;
  name: string;
  displayName: string;
  identifier: string;
  template: string;
  platform: "android" | "ios" | "both";
  initializeGit: boolean;
  runtimePath?: string;
  skipCheck?: boolean;
}>;

export class CliCommandError extends Error {
  public constructor(
    message: string,
    readonly code = "cli.failed",
    readonly help?: string,
    readonly details: readonly string[] = []
  ) {
    super(message);
    this.name = "CliCommandError";
  }
}

export class CliClient {
  public constructor(
    readonly invocation: CliInvocation,
    readonly runner: ProcessRunner,
    readonly output: vscode.OutputChannel,
    readonly maxProtocolLineBytes: number
  ) {}

  public async handshake(cwd: string, signal?: AbortSignal): Promise<Handshake> {
    const result = await this.#unary(["ide", "handshake", "--json"], cwd, signal);
    return parseHandshake(result.stdout);
  }

  public async project(workspace: string, signal?: AbortSignal): Promise<ProjectResponse> {
    const result = await this.#unary(["ide", "project", "--workspace", workspace, "--json"], workspace, signal);
    return parseProjectResponse(result.stdout);
  }

  public async validate(workspace: string, request: ValidationRequest = {}): Promise<ValidationResponse> {
    const args = ["ide", "validate", "--workspace", workspace];
    if (request.manifestSource !== undefined) {
      args.push("--manifest-stdin");
    }
    args.push("--json");
    const result = await this.#unary(
      args,
      workspace,
      request.signal,
      UNARY_TIMEOUT_MS,
      request.manifestSource
    );
    return parseValidationResponse(result.stdout);
  }

  public async devices(platform: "all" | "android" | "ios", cwd: string, signal?: AbortSignal): Promise<DeviceSnapshotResponse> {
    const result = await this.#unary(["ide", "devices", "--platform", platform, "--json-stream"], cwd, signal, 60_000);
    return parseDeviceSnapshotResponse(result.stdout);
  }

  public async signingTeams(workspace: string, signal?: AbortSignal): Promise<SigningTeamsResponse> {
    const result = await this.#unary(
      ["ide", "signing-teams", "--workspace", workspace, "--json"],
      workspace,
      signal,
      60_000
    );
    return parseSigningTeamsResponse(result.stdout);
  }

  public async stream(
    request: StreamRequest,
    onEvent: (event: ProtocolEvent) => void | Promise<void>,
    signal?: AbortSignal
  ): Promise<string> {
    const operationId = request.operationId ?? randomUUID();
    let terminalEvent: ProtocolEvent | undefined;
    let started = false;
    const args = ["ide", request.operation];
    args.push("--workspace", request.workspace);
    if (request.platform !== undefined) {
      args.push("--platform", request.platform);
    }
    if (request.profile !== undefined) {
      args.push("--profile", request.profile);
    }
    if (request.device !== undefined) {
      args.push("--device", request.device);
    }
    if (request.artifact !== undefined) {
      args.push("--artifact", request.artifact);
    }
    if (request.team !== undefined) {
      args.push("--team", request.team);
    }
    if (request.allowProvisioningUpdates === true) {
      args.push("--allow-provisioning-updates");
    }
    if (request.provisioningProfile !== undefined) {
      args.push("--provisioning-profile", request.provisioningProfile);
    }
    args.push("--json-stream");
    args.push("--operation-id", operationId);
    if (request.parentOperationId !== undefined) {
      args.push("--parent-operation-id", request.parentOperationId);
    }
    const fullArgs = this.#arguments(args);
    this.#logCommand(fullArgs, request.workspace, operationId);
    const result = await this.runner.runNdjson(
      {
        executable: this.invocation.executable,
        args: fullArgs,
        cwd: request.workspace,
        ...(signal === undefined ? {} : { signal }),
        timeoutMs: 0
      },
      this.maxProtocolLineBytes,
      async (event) => {
        if (event.operation_id !== operationId) {
          throw new ProtocolError(
            `cargo-ferry emitted operation ${event.operation_id}; expected ${operationId}.`,
            "protocol.operation_mismatch"
          );
        }
        if (terminalEvent !== undefined) {
          throw new ProtocolError(
            `cargo-ferry emitted ${event.event} after terminal event ${terminalEvent.event}.`,
            "protocol.event_after_terminal"
          );
        }
        if (event.event === "operation_started") {
          if (started) {
            throw new ProtocolError(
              "cargo-ferry emitted operation_started more than once.",
              "protocol.duplicate_start"
            );
          }
          started = true;
        } else if (!started) {
          throw new ProtocolError(
            `cargo-ferry emitted ${event.event} before operation_started.`,
            "protocol.missing_start"
          );
        }
        if (event.event === "operation_finished" || event.event === "operation_cancelled") {
          terminalEvent = event;
        }
        this.#logEvent(event);
        await onEvent(event);
      }
    );
    if (terminalEvent === undefined) {
      throw new ProtocolError(
        "cargo-ferry ended without operation_finished or operation_cancelled.",
        "protocol.missing_terminal"
      );
    }
    if (terminalEvent.event === "operation_cancelled") {
      throw new ProcessCancelledError();
    }
    if (terminalEvent.event === "operation_finished" && terminalEvent.success !== true) {
      throw streamCommandError(terminalEvent, request.operation);
    }
    this.#ensureSuccess(result, `${request.operation} operation`);
    return operationId;
  }

  public async check(
    workspace: string,
    onEvent: (event: ProtocolEvent) => void | Promise<void>,
    signal?: AbortSignal
  ): Promise<string> {
    return await this.stream(
      { operation: "check", workspace, operationId: randomUUID() },
      onEvent,
      signal
    );
  }

  public async doctor(workspace: string, signal?: AbortSignal): Promise<unknown> {
    const result = await this.#unary(["ide", "doctor", "--workspace", workspace, "--all", "--json"], workspace, signal, 60_000);
    const value = parseJsonObject(result.stdout, "cargo-ferry doctor");
    assertProtocolVersion(value, "cargo-ferry doctor");
    return value.report;
  }

  public async clean(workspace: string, signal?: AbortSignal): Promise<unknown> {
    return await this.#legacy(["clean", "generated", "--project-dir", workspace, "--json"], workspace, signal, 0);
  }

  public async templates(cwd: string, signal?: AbortSignal): Promise<readonly TemplateMetadata[]> {
    const handshake = await this.handshake(cwd, signal);
    return handshake.templates.map((entry) => ({ name: entry.id, purpose: entry.description }));
  }

  public async capabilities(workspace: string, signal?: AbortSignal): Promise<readonly CapabilityMetadata[]> {
    const value = await this.#legacy<unknown>(["capabilities", "--json"], workspace, signal);
    if (!Array.isArray(value)) {
      throw new ProtocolError("cargo-ferry capabilities returned an invalid metadata list.");
    }
    return value.map((entry, index) => {
      if (!isRecord(entry) || typeof entry.name !== "string") {
        throw new ProtocolError(`cargo-ferry capability entry ${index} is invalid.`);
      }
      return {
        name: entry.name,
        ...(typeof entry.enabled === "boolean" || entry.enabled === null ? { enabled: entry.enabled } : {}),
        ...(typeof entry.runtime === "string" ? { runtime: entry.runtime } : {}),
        ...(typeof entry.android === "string" ? { android: entry.android } : {}),
        ...(typeof entry.ios === "string" ? { ios: entry.ios } : {})
      };
    });
  }

  public async previewCapability(
    workspace: string,
    capability: string,
    enable: boolean,
    signal?: AbortSignal
  ): Promise<unknown> {
    return await this.#legacy(
      [enable ? "add" : "remove", capability, "--project-dir", workspace, "--dry-run", "--json"],
      workspace,
      signal
    );
  }

  public async mutateCapability(
    workspace: string,
    capability: string,
    enable: boolean,
    signal?: AbortSignal
  ): Promise<unknown> {
    return await this.#legacy(
      [enable ? "add" : "remove", capability, "--project-dir", workspace, "--json"],
      workspace,
      signal,
      0
    );
  }

  public async newProject(request: NewProjectRequest, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const args = [
      "new",
      request.name,
      "--parent",
      request.parent,
      "--display-name",
      request.displayName,
      "--id",
      request.identifier,
      "--template",
      request.template,
      "--platform",
      request.platform
    ];
    if (request.runtimePath !== undefined) {
      args.push("--runtime-source", "path", "--runtime-path", request.runtimePath);
    }
    args.push("--json");
    if (!request.initializeGit) {
      args.push("--no-git");
    }
    if (request.skipCheck === true) {
      args.push("--no-check");
    }
    const result = await this.#legacy<unknown>(args, request.parent, signal, 0);
    if (!isRecord(result)) {
      throw new ProtocolError("cargo-ferry new returned invalid project metadata.");
    }
    return result;
  }

  async #unary(
    args: readonly string[],
    cwd: string,
    signal?: AbortSignal,
    timeoutMs = UNARY_TIMEOUT_MS,
    stdin?: string
  ): Promise<ProcessResult> {
    const fullArgs = this.#arguments(args);
    this.#logCommand(fullArgs, cwd);
    const result = await this.runner.runBuffered({
      executable: this.invocation.executable,
      args: fullArgs,
      cwd,
      ...(signal === undefined ? {} : { signal }),
      timeoutMs,
      ...(stdin === undefined ? {} : { stdin })
    });
    if (result.code !== 0) {
      try {
        const value = parseJsonObject(result.stdout, `cargo-ferry ${args.slice(0, 2).join(" ")}`);
        if (value.protocol_version === 1 && isRecord(value.error)) {
          throw new CliCommandError(
            typeof value.error.message === "string" ? value.error.message : "cargo-ferry IDE command failed.",
            typeof value.error.code === "string" ? value.error.code : "ide.failed",
            typeof value.error.help === "string" ? value.error.help : undefined,
            Array.isArray(value.error.details)
              ? value.error.details.filter((detail): detail is string => typeof detail === "string")
              : []
          );
        }
      } catch (error) {
        if (error instanceof CliCommandError) {
          throw error;
        }
      }
      this.#ensureSuccess(result, args.slice(0, 2).join(" "));
    }
    return result;
  }

  async #legacy<T>(
    args: readonly string[],
    cwd: string,
    signal?: AbortSignal,
    timeoutMs = UNARY_TIMEOUT_MS
  ): Promise<T> {
    const fullArgs = this.#arguments(args);
    this.#logCommand(fullArgs, cwd);
    const result = await this.runner.runBuffered({
      executable: this.invocation.executable,
      args: fullArgs,
      cwd,
      ...(signal === undefined ? {} : { signal }),
      timeoutMs
    });
    let value: Record<string, unknown>;
    try {
      value = parseJsonObject(result.stdout, `cargo-ferry ${args[0] ?? "command"}`);
    } catch (error) {
      if (result.code !== 0) {
        this.#ensureSuccess(result, args[0] ?? "command");
      }
      throw error;
    }
    if (value.schema_version !== 1) {
      throw new ProtocolError("cargo-ferry command JSON uses an unsupported schema version.");
    }
    if (value.status === "error") {
      const failure = value as LegacyJsonError;
      throw new CliCommandError(
        failure.error.message,
        failure.error.code,
        failure.error.help ?? undefined,
        failure.error.details ?? []
      );
    }
    if (value.status !== "ok" || !("data" in value)) {
      throw new ProtocolError("cargo-ferry command JSON did not contain a successful data envelope.");
    }
    if (result.code !== 0) {
      this.#ensureSuccess(result, args[0] ?? "command");
    }
    return value.data as T;
  }

  #arguments(args: readonly string[]): string[] {
    return [...this.invocation.prefixArgs, ...args];
  }

  #ensureSuccess(result: ProcessResult, operation: string): void {
    if (result.code === 0) {
      return;
    }
    const summary = sanitizeBootstrapError(result.stderr);
    throw new ProcessExecutionError(
      `${operation} failed${result.code === null ? "" : ` with exit code ${result.code}`}${summary.length === 0 ? "." : `: ${summary}`}`,
      result.code,
      summary
    );
  }

  #logCommand(args: readonly string[], cwd: string, operationId?: string): void {
    const id = operationId === undefined ? "" : ` [${operationId}]`;
    this.output.appendLine(`${new Date().toISOString()}${id} ${cwd}`);
    this.output.appendLine(`> ${this.invocation.executable} ${sanitizeArguments(args).join(" ")}`);
  }

  #logEvent(event: ProtocolEvent): void {
    const prefix = `[${event.operation_id}] ${event.event}`;
    switch (event.event) {
      case "phase_started":
      case "phase_finished":
        this.output.appendLine(`${prefix}: ${stringField(event, "phase")}`);
        break;
      case "progress":
        this.output.appendLine(`${prefix}: ${stringField(event, "message")}`);
        break;
      case "warning":
        this.output.appendLine(`${prefix}: ${stringField(event, "message")}`);
        break;
      case "artifact":
        this.output.appendLine(
          `${prefix}: ${isRecord(event.artifact) ? stringField(event.artifact, "kind") : "received"} ${isRecord(event.artifact) ? stringField(event.artifact, "path") : "received"}`
        );
        break;
      case "diagnostic": {
        const diagnostic = isRecord(event.diagnostic) ? event.diagnostic : undefined;
        this.output.appendLine(`${prefix}: ${diagnostic === undefined ? "received" : stringField(diagnostic, "code")}`);
        break;
      }
      case "command_started":
        this.output.appendLine(`${prefix}: ${stringField(event, "tool")}`);
        break;
      case "log":
        this.output.appendLine(`${prefix}: application log routed to RustFerry Logs`);
        break;
      default:
        this.output.appendLine(prefix);
    }
  }
}

function streamCommandError(event: ProtocolEvent, operation: string): CliCommandError {
  const error = isRecord(event.error) ? event.error : undefined;
  return new CliCommandError(
    error !== undefined && typeof error.message === "string"
      ? error.message
      : `cargo-ferry ${operation} did not complete successfully.`,
    error !== undefined && typeof error.code === "string" ? error.code : "ide.operation_failed",
    error !== undefined && typeof error.help === "string" ? error.help : undefined,
    error !== undefined && Array.isArray(error.details)
      ? error.details.filter((detail): detail is string => typeof detail === "string")
      : []
  );
}

function sanitizeArguments(args: readonly string[]): string[] {
  const sensitive = /(?:password|passphrase|secret|token|private-key|provisioning)/i;
  let redactNext = false;
  return args.map((argument) => {
    if (redactNext) {
      redactNext = false;
      return "<redacted>";
    }
    if (sensitive.test(argument)) {
      redactNext = !argument.includes("=");
      return argument.includes("=") ? `${argument.slice(0, argument.indexOf("=") + 1)}<redacted>` : argument;
    }
    return argument;
  });
}

function sanitizeBootstrapError(value: string): string {
  const ansi = new RegExp(`${String.fromCodePoint(27)}\\[[0-?]*[ -/]*[@-~]`, "gu");
  const withoutAnsi = value.replaceAll(ansi, "");
  return withoutAnsi.replaceAll(/(password|passphrase|secret|token)\s*[:=]\s*\S+/gi, "$1=<redacted>").trim().slice(0, 8_000);
}

function stringField(value: Readonly<Record<string, unknown>>, field: string): string {
  return typeof value[field] === "string" ? value[field] : "received";
}
