import { randomUUID } from "node:crypto";

import type * as vscode from "vscode";

import {
  jobIdeCommands,
  remoteIdeCommands,
  type JobIdeCommand,
  type RemoteIdeCommand
} from "../constants.js";
import type { CliInvocation } from "./discovery.js";
import {
  ProtocolError,
  assertProtocolVersion,
  isRecord,
  parseArtifactRemoveResponse,
  parseArtifactRevealResponse,
  parseArtifactVerifyResponse,
  parseCancelJobResponse,
  parseHandshake,
  parseJobArtifactsResponse,
  parseJobLogsPageResponse,
  parseLegacyJobLogsSnapshotResponse,
  parseJobsListResponse,
  parseJobShowResponse,
  parseRemoteBuildPreviewResponse,
  parseRemoteBuildSubmissionResponse,
  parseRetryJobResponse,
  parseDeviceSnapshotResponse,
  parseJsonObject,
  parseProjectResponse,
  parseSigningReadinessResponse,
  parseSigningTeamsResponse,
  requireDecimalString,
  parseValidationResponse,
  type ArtifactRemoveResponse,
  type ArtifactRevealResponse,
  type ArtifactVerifyResponse,
  type BuildProfile,
  type CancelJobResponse,
  type DeviceSnapshotResponse,
  type Handshake,
  type JobArtifactsResponse,
  type JobLogEvent,
  type JobLogsPageRequest,
  type JobLogsPageResponse,
  type LegacyJobLogsSnapshotResponse,
  type JobsListResponse,
  type JobShowResponse,
  type LegacyJsonError,
  type ProjectResponse,
  type RemoteBuildConsent,
  type RemoteBuildPreviewRequest,
  type RemoteBuildPreviewResponse,
  type RemoteBuildSubmissionResponse,
  type RetryJobResponse,
  type SigningReadinessResponse,
  type SigningTeamsResponse,
  type ProtocolEvent,
  type ValidationResponse
} from "./protocol.js";
import { ProcessCancelledError, ProcessExecutionError, ProcessRunner, type ProcessResult } from "./process.js";

const UNARY_TIMEOUT_MS = 20_000;
const JOB_LIST_LIMIT = 50;
const DEFAULT_JOB_LOG_PAGE_LIMIT = 256;
const MAX_JOB_LOG_PAGE_LIMIT = 1_000;
const FOLLOW_RETRY_DELAY_MS = 250;

type ExactIdeCommand = JobIdeCommand | RemoteIdeCommand;

const parsedRemoteBuildPreviews = new WeakSet();
const approvedRemoteBuildConsents = new WeakMap<object, Readonly<{
  workspace: string;
  sourceManifestSha256: string;
  profile: BuildProfile;
}>>();

export type GatedJobResponse<T> = Readonly<{
  response: T;
  supportedCommands: readonly string[];
}>;

export type JobLogsFollowHandlers = Readonly<{
  onPage: (page: JobLogsPageResponse) => void | Promise<void>;
  onEvent?: (event: JobLogEvent) => void | Promise<void>;
}>;

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

export function approveRemoteBuildPreview(
  preview: RemoteBuildPreviewResponse
): RemoteBuildConsent {
  if (!parsedRemoteBuildPreviews.has(preview)) {
    throw new ProtocolError(
      "Remote build consent requires a preview returned by this client.",
      "protocol.preview_required"
    );
  }
  parsedRemoteBuildPreviews.delete(preview);
  const consent: RemoteBuildConsent = Object.freeze({
    consent_token: preview.consent_token,
    preview_sha256: preview.preview_sha256,
    approved: true
  });
  approvedRemoteBuildConsents.set(consent, {
    workspace: preview.workspace,
    sourceManifestSha256: preview.source.manifest_sha256,
    profile: preview.profile
  });
  return consent;
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

  public async jobsList(
    workspace: string,
    signal?: AbortSignal
  ): Promise<GatedJobResponse<JobsListResponse>> {
    const result = await this.#jobUnary(
      jobIdeCommands.list,
      workspace,
      ["--limit", String(JOB_LIST_LIMIT)],
      parseJobsListResponse,
      signal
    );
    if (result.response.limit !== JOB_LIST_LIMIT) {
      throw new ProtocolError(
        "jobs-list response does not bind the requested page limit.",
        "protocol.request_mismatch"
      );
    }
    return result;
  }

  public async jobShow(
    workspace: string,
    localJobId: string,
    signal?: AbortSignal
  ): Promise<GatedJobResponse<JobShowResponse>> {
    const result = await this.#jobUnary(
      jobIdeCommands.show,
      workspace,
      ["--job", localJobId],
      parseJobShowResponse,
      signal
    );
    this.#assertJobId(result.response.job.local_job_id, localJobId, jobIdeCommands.show);
    return result;
  }

  public async legacyJobLogsSnapshot(
    workspace: string,
    localJobId: string,
    signal?: AbortSignal
  ): Promise<GatedJobResponse<LegacyJobLogsSnapshotResponse>> {
    const result = await this.#jobUnary(
      jobIdeCommands.logs,
      workspace,
      ["--job", localJobId, "--since", "0"],
      parseLegacyJobLogsSnapshotResponse,
      signal,
      60_000
    );
    this.#assertJobId(result.response.local_job_id, localJobId, jobIdeCommands.logs);
    return result;
  }

  public async jobLogsPage(
    workspace: string,
    localJobId: string,
    request: JobLogsPageRequest = {},
    signal?: AbortSignal
  ): Promise<GatedJobResponse<JobLogsPageResponse>> {
    const afterSequence = requireDecimalString(
      request.afterSequence ?? "0",
      "job log afterSequence"
    );
    const limit = request.limit ?? DEFAULT_JOB_LOG_PAGE_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_JOB_LOG_PAGE_LIMIT) {
      throw new ProtocolError(
        `job log limit must be an integer from 1 through ${MAX_JOB_LOG_PAGE_LIMIT}.`,
        "protocol.invalid_request"
      );
    }
    const args = [
      "--job",
      localJobId,
      "--after-sequence",
      afterSequence,
      "--limit",
      String(limit)
    ];
    if (request.refresh === true) {
      args.push("--refresh");
    }
    if (request.waitForEvents === true) {
      requireAbortSignal(signal, "jobs-logs --wait");
      args.push("--wait");
    }
    if (request.phase !== undefined) {
      args.push("--phase", requireBoundedArgument(request.phase, "job log phase"));
    }
    const result = await this.#jobUnary(
      jobIdeCommands.logsPage,
      workspace,
      args,
      parseJobLogsPageResponse,
      signal,
      request.waitForEvents === true ? 0 : UNARY_TIMEOUT_MS
    );
    this.#assertJobId(result.response.local_job_id, localJobId, jobIdeCommands.logsPage);
    if (
      result.response.after_sequence !== afterSequence
      || result.response.limit !== limit
      || result.response.phase !== request.phase
    ) {
      throw new ProtocolError(
        "jobs-logs response does not bind the requested cursor, page limit, and phase.",
        "protocol.request_mismatch"
      );
    }
    return result;
  }

  public async followJobLogs(
    workspace: string,
    localJobId: string,
    request: JobLogsPageRequest,
    handlers: JobLogsFollowHandlers,
    signal: AbortSignal
  ): Promise<void> {
    let afterSequence = requireDecimalString(
      request.afterSequence ?? "0",
      "job log afterSequence"
    );
    let waitForEvents = request.waitForEvents ?? false;
    let refresh = request.refresh ?? false;
    for (;;) {
      throwIfAborted(signal);
      const page = await this.jobLogsPage(
        workspace,
        localJobId,
        {
          ...request,
          afterSequence,
          refresh,
          waitForEvents
        },
        signal
      );
      await handlers.onPage(page.response);
      for (const event of page.response.events) {
        await handlers.onEvent?.(event);
      }
      if (page.response.terminal && !page.response.has_more) {
        return;
      }
      const advanced = page.response.next_after_sequence !== afterSequence;
      afterSequence = page.response.next_after_sequence;
      waitForEvents = !page.response.has_more;
      refresh = !page.response.has_more;
      if (!advanced) {
        await waitForAbortableDelay(FOLLOW_RETRY_DELAY_MS, signal);
      }
    }
  }

  public async jobArtifacts(
    workspace: string,
    localJobId: string,
    signal?: AbortSignal
  ): Promise<GatedJobResponse<JobArtifactsResponse>> {
    const result = await this.#jobUnary(
      jobIdeCommands.artifacts,
      workspace,
      ["--job", localJobId],
      parseJobArtifactsResponse,
      signal
    );
    this.#assertJobId(result.response.local_job_id, localJobId, jobIdeCommands.artifacts);
    return result;
  }

  public async cancelJob(
    workspace: string,
    localJobId: string,
    signal: AbortSignal
  ): Promise<GatedJobResponse<CancelJobResponse>> {
    requireAbortSignal(signal, jobIdeCommands.cancel);
    const result = await this.#jobUnary(
      jobIdeCommands.cancel,
      workspace,
      ["--job", localJobId],
      parseCancelJobResponse,
      signal,
      0
    );
    this.#assertJobId(result.response.parent.local_job_id, localJobId, jobIdeCommands.cancel);
    return result;
  }

  public async retryJob(
    workspace: string,
    localJobId: string,
    signal: AbortSignal
  ): Promise<GatedJobResponse<RetryJobResponse>> {
    requireAbortSignal(signal, jobIdeCommands.retry);
    const result = await this.#jobUnary(
      jobIdeCommands.retry,
      workspace,
      ["--job", localJobId],
      parseRetryJobResponse,
      signal,
      0
    );
    this.#assertJobId(result.response.parent.local_job_id, localJobId, jobIdeCommands.retry);
    return result;
  }

  public async verifyJobArtifact(
    workspace: string,
    localJobId: string,
    artifactId: string,
    signal: AbortSignal
  ): Promise<GatedJobResponse<ArtifactVerifyResponse>> {
    requireAbortSignal(signal, jobIdeCommands.artifactVerify);
    const result = await this.#jobUnary(
      jobIdeCommands.artifactVerify,
      workspace,
      ["--job", localJobId, "--artifact", artifactId],
      parseArtifactVerifyResponse,
      signal,
      0
    );
    this.#assertArtifactIdentity(result.response, localJobId, artifactId, jobIdeCommands.artifactVerify);
    return result;
  }

  public async revealJobArtifact(
    workspace: string,
    localJobId: string,
    artifactId: string,
    signal: AbortSignal
  ): Promise<GatedJobResponse<ArtifactRevealResponse>> {
    requireAbortSignal(signal, jobIdeCommands.artifactReveal);
    const result = await this.#jobUnary(
      jobIdeCommands.artifactReveal,
      workspace,
      ["--job", localJobId, "--artifact", artifactId],
      parseArtifactRevealResponse,
      signal,
      0
    );
    this.#assertArtifactIdentity(result.response, localJobId, artifactId, jobIdeCommands.artifactReveal);
    return result;
  }

  public async removeJobArtifact(
    workspace: string,
    localJobId: string,
    artifactId: string,
    signal: AbortSignal
  ): Promise<GatedJobResponse<ArtifactRemoveResponse>> {
    requireAbortSignal(signal, jobIdeCommands.artifactRemove);
    const result = await this.#jobUnary(
      jobIdeCommands.artifactRemove,
      workspace,
      ["--job", localJobId, "--artifact", artifactId, "--yes"],
      parseArtifactRemoveResponse,
      signal,
      0
    );
    this.#assertArtifactIdentity(result.response, localJobId, artifactId, jobIdeCommands.artifactRemove);
    return result;
  }

  public async remoteBuildPreview(
    workspace: string,
    request: RemoteBuildPreviewRequest,
    signal?: AbortSignal
  ): Promise<GatedJobResponse<RemoteBuildPreviewResponse>> {
    const result = await this.#jobUnary(
      remoteIdeCommands.buildPreview,
      workspace,
      [
        "--provider",
        "github",
        "--target",
        "ios-device",
        "--profile",
        request.profile,
        "--unsigned",
        "--snapshot"
      ],
      parseRemoteBuildPreviewResponse,
      signal
    );
    if (result.response.workspace !== workspace || result.response.profile !== request.profile) {
      throw new ProtocolError(
        "remote-build-preview response does not bind the requested workspace and profile.",
        "protocol.request_mismatch"
      );
    }
    Object.freeze(result.response.source);
    Object.freeze(result.response.effects);
    Object.freeze(result.response);
    parsedRemoteBuildPreviews.add(result.response);
    return result;
  }

  public async submitRemoteBuild(
    workspace: string,
    consent: RemoteBuildConsent,
    signal: AbortSignal
  ): Promise<GatedJobResponse<RemoteBuildSubmissionResponse>> {
    requireAbortSignal(signal, remoteIdeCommands.buildSubmit);
    const provenance = approvedRemoteBuildConsents.get(consent);
    if (provenance?.workspace !== workspace) {
      throw new ProtocolError(
        "remote-build-submit requires consent created from the exact parsed preview.",
        "protocol.consent_required"
      );
    }
    approvedRemoteBuildConsents.delete(consent);
    const result = await this.#jobUnary(
      remoteIdeCommands.buildSubmit,
      workspace,
      ["--consent-stdin"],
      parseRemoteBuildSubmissionResponse,
      signal,
      0,
      JSON.stringify(consent)
    );
    if (
      result.response.receipt.preview_sha256 !== consent.preview_sha256
      || result.response.job.provider.name !== "github"
      || result.response.job.target !== "iphone"
      || result.response.job.profile !== provenance.profile
      || result.response.job.signing_mode !== "unsigned-compile-only"
      || result.response.job.source_manifest_sha256 !== provenance.sourceManifestSha256
    ) {
      throw new ProtocolError(
        "remote-build-submit job and receipt do not bind the approved preview.",
        "protocol.consent_mismatch"
      );
    }
    return result;
  }

  public async signingReadiness(
    workspace: string,
    signal?: AbortSignal
  ): Promise<GatedJobResponse<SigningReadinessResponse>> {
    return await this.#jobUnary(
      remoteIdeCommands.signingReadiness,
      workspace,
      ["--provider", "github", "--target", "ios-device"],
      parseSigningReadinessResponse,
      signal
    );
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

  async #jobUnary<T extends Readonly<{ workspace: string }>>(
    command: ExactIdeCommand,
    workspace: string,
    args: readonly string[],
    parse: (source: string) => T,
    signal?: AbortSignal,
    timeoutMs = UNARY_TIMEOUT_MS,
    stdin?: string
  ): Promise<GatedJobResponse<T>> {
    const handshake = await this.handshake(workspace, signal);
    if (!handshake.supported_commands.includes(command)) {
      throw new ProtocolError(
        `Installed cargo-ferry does not advertise the exact ${command} IDE command.`,
        "protocol.command_unsupported"
      );
    }
    const result = await this.#unary(
      ["ide", command, "--workspace", workspace, ...args, "--json"],
      workspace,
      signal,
      timeoutMs,
      stdin
    );
    const response = parse(result.stdout);
    if (response.workspace !== workspace) {
      throw new ProtocolError(
        `${command} returned workspace ${response.workspace}; expected ${workspace}.`,
        "protocol.workspace_mismatch"
      );
    }
    return {
      response,
      supportedCommands: handshake.supported_commands
    };
  }

  #assertArtifactIdentity(
    response: Readonly<{ local_job_id: string; artifact_id: string }>,
    localJobId: string,
    artifactId: string,
    command: JobIdeCommand
  ): void {
    this.#assertJobId(response.local_job_id, localJobId, command);
    if (response.artifact_id !== artifactId) {
      throw new ProtocolError(
        `${command} returned artifact ${response.artifact_id}; expected ${artifactId}.`,
        "protocol.artifact_mismatch"
      );
    }
  }

  #assertJobId(actual: string, expected: string, command: ExactIdeCommand): void {
    if (actual !== expected) {
      throw new ProtocolError(
        `${command} returned job ${actual}; expected ${expected}.`,
        "protocol.job_mismatch"
      );
    }
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

function requireAbortSignal(signal: AbortSignal | undefined, operation: string): AbortSignal {
  if (signal === undefined) {
    throw new ProtocolError(
      `${operation} requires an explicit cancellation signal.`,
      "protocol.cancellation_required"
    );
  }
  return signal;
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) {
    throw new ProcessCancelledError();
  }
}

function requireBoundedArgument(value: string, name: string): string {
  if (
    value.length === 0
    || Buffer.byteLength(value, "utf8") > 4_096
    || hasControlCharacter(value)
  ) {
    throw new ProtocolError(
      `${name} must be bounded text without control characters.`,
      "protocol.invalid_request"
    );
  }
  return value;
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint < 32 || codePoint === 127) {
      return true;
    }
  }
  return false;
}

async function waitForAbortableDelay(delayMs: number, signal: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, delayMs);
    const onAbort = (): void => {
      clearTimeout(timeout);
      reject(new ProcessCancelledError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
