import * as vscode from "vscode";

import { approveRemoteBuildPreview } from "../cli/client.js";
import type { JobArtifact } from "../cli/protocol.js";
import { remoteIdeCommands, type RemoteIdeCommand } from "../constants.js";
import { advertisesRemoteCommand } from "../jobs/capabilities.js";
import {
  jobLogEmptyText,
  jobLogScopeNotice,
  renderJobLogEvent
} from "../jobs/logPresentation.js";
import {
  remoteBuildPreviewDetail,
  submitAfterRemoteBuildConsent
} from "../jobs/remoteBuildConsent.js";
import type { WorkspaceProject } from "../workspace/project.js";
import { requireExecution, UserActionError } from "./navigation.js";
import type { CommandServices } from "./types.js";

type JobArgument = Readonly<{
  project: WorkspaceProject;
  job: Readonly<{
    local_job_id: string;
    app_label?: string;
    state?: string;
    can_cancel: boolean;
    cancel_reason_code?: string;
    can_retry: boolean;
    retry_reason_code?: string;
  }>;
}>;

type JobArtifactArgument = Readonly<{
  project: WorkspaceProject;
  localJobId: string;
  artifact: JobArtifact;
}>;

const JOB_LOG_PAGE_LIMIT = 256;

export async function showJob(services: CommandServices, argument?: unknown): Promise<void> {
  const value = requireJobArgument(services, argument);
  const result = await (await services.clientFor(value.project)).jobShow(
    value.project.root.fsPath,
    value.job.local_job_id
  );
  const document = await vscode.workspace.openTextDocument({
    content: `${JSON.stringify(result.response.job, null, 2)}\n`,
    language: "json"
  });
  await vscode.window.showTextDocument(document, { preview: true });
}

export async function showJobLogs(services: CommandServices, argument?: unknown): Promise<void> {
  const value = requireJobArgument(services, argument);
  const result = await (await services.clientFor(value.project)).jobLogsPage(
    value.project.root.fsPath,
    value.job.local_job_id,
    { afterSequence: "0", limit: JOB_LOG_PAGE_LIMIT, refresh: true }
  );
  services.jobLogs.clear();
  services.jobLogs.appendLine(`${displayText(value.project.displayName)} | ${value.job.local_job_id}`);
  services.jobLogs.appendLine(jobLogScopeNotice(result.response));
  for (const event of result.response.events) {
    services.jobLogs.appendLine(renderJobLogEvent(event));
  }
  if (result.response.events.length === 0) {
    services.jobLogs.appendLine(jobLogEmptyText(result.response));
  }
  if (result.response.has_more) {
    services.jobLogs.appendLine(
      `More events are available after sequence ${result.response.next_after_sequence}; use Load More in the Jobs view or Follow Job Logs.`
    );
  }
  services.jobLogs.show(true);
}

export async function followJobLogs(services: CommandServices, argument?: unknown): Promise<void> {
  const value = requireJobArgument(services, argument);
  const client = await services.clientFor(value.project);
  services.jobLogs.clear();
  services.jobLogs.appendLine(`${displayText(value.project.displayName)} | ${value.job.local_job_id}`);
  services.jobLogs.show(true);
  let coverageWritten = false;
  await withAbortableNotification(
    `Following logs for ${jobLabel(value)}`,
    async (signal) => await client.followJobLogs(
      value.project.root.fsPath,
      value.job.local_job_id,
      {
        afterSequence: "0",
        limit: JOB_LOG_PAGE_LIMIT,
        refresh: true,
        waitForEvents: false
      },
      {
        onPage: (page) => {
          if (!coverageWritten) {
            services.jobLogs.appendLine(jobLogScopeNotice(page));
            coverageWritten = true;
          }
        },
        onEvent: (event) => services.jobLogs.appendLine(renderJobLogEvent(event))
      },
      signal
    )
  );
  services.jobLogs.appendLine("Job reached a terminal state; log follow completed.");
}

export async function cancelJob(services: CommandServices, argument?: unknown): Promise<void> {
  const value = requireJobAction(services, argument, "cancel");
  const confirmation = await vscode.window.showWarningMessage(
    `Request cancellation of ${jobLabel(value)}?`,
    {
      modal: true,
      detail: "cargo-ferry will revalidate the workspace, job ownership, provider identity, and current state."
    },
    "Cancel Job"
  );
  if (confirmation !== "Cancel Job") {
    return;
  }
  const client = await services.clientFor(value.project);
  const result = await withJobRefresh(
    services,
    async () => await withAbortableNotification(
      `Cancelling ${jobLabel(value)}`,
      async (signal) => await client.cancelJob(
        value.project.root.fsPath,
        value.job.local_job_id,
        signal
      )
    )
  );
  await vscode.window.showInformationMessage(
    `Cancellation status: ${displayText(result.response.parent.cancellation_status)}.`
  );
}

export async function retryJob(services: CommandServices, argument?: unknown): Promise<void> {
  const value = requireJobAction(services, argument, "retry");
  const confirmation = await vscode.window.showWarningMessage(
    `Retry ${jobLabel(value)} from its exact stored source?`,
    {
      modal: true,
      detail: "cargo-ferry will revalidate the workspace binding, terminal state, retry policy, and source identity."
    },
    "Retry Job"
  );
  if (confirmation !== "Retry Job") {
    return;
  }
  const client = await services.clientFor(value.project);
  const result = await withJobRefresh(
    services,
    async () => await withAbortableNotification(
      `Retrying ${jobLabel(value)}`,
      async (signal) => await client.retryJob(
        value.project.root.fsPath,
        value.job.local_job_id,
        signal
      )
    )
  );
  const disposition = result.response.receipt.disposition === "created"
    ? "Created retry"
    : "Resumed existing retry";
  await vscode.window.showInformationMessage(
    `${disposition} ${result.response.child.local_job_id} from ${result.response.parent.local_job_id}.`
  );
}

export async function verifyJobArtifact(
  services: CommandServices,
  argument?: unknown
): Promise<void> {
  const value = requireJobArtifactAction(services, argument, "verify");
  const client = await services.clientFor(value.project);
  const result = await withJobRefresh(
    services,
    async () => await withAbortableNotification(
      `Verifying ${displayText(value.artifact.file_name)}`,
      async (signal) => await client.verifyJobArtifact(
        value.project.root.fsPath,
        value.localJobId,
        value.artifact.artifact_id,
        signal
      )
    )
  );
  await showJsonDocument(result.response);
  await vscode.window.showInformationMessage(
    `${displayText(value.artifact.file_name)}: ${displayText(result.response.status)}.`
  );
}

export async function revealJobArtifact(
  services: CommandServices,
  argument?: unknown
): Promise<void> {
  const value = requireJobArtifactAction(services, argument, "reveal");
  const client = await services.clientFor(value.project);
  const result = await withJobRefresh(
    services,
    async () => await withAbortableNotification(
      `Revealing ${displayText(value.artifact.file_name)}`,
      async (signal) => await client.revealJobArtifact(
        value.project.root.fsPath,
        value.localJobId,
        value.artifact.artifact_id,
        signal
      )
    )
  );
  const identityEvidence = result.response.receipt.exact_path_bound_during_launch
    ? "cargo-ferry retained the exact artifact path binding during launch and revalidated it afterward"
    : "cargo-ferry performed the guarded platform launch and passed post-launch identity revalidation; this platform cannot retain an exact path binding during launch";
  await vscode.window.showInformationMessage(
    `${displayText(value.artifact.file_name)}: ${displayText(result.response.status)}; ${identityEvidence}.`
  );
}

export async function removeJobArtifact(
  services: CommandServices,
  argument?: unknown
): Promise<void> {
  const value = requireJobArtifactAction(services, argument, "remove");
  const confirmation = await vscode.window.showWarningMessage(
    `Remove the managed copy of ${displayText(value.artifact.file_name)}?`,
    {
      modal: true,
      detail: "cargo-ferry will revalidate the workspace, stored file identity, and managed-root boundary. Replacements are preserved."
    },
    "Remove Artifact"
  );
  if (confirmation !== "Remove Artifact") {
    return;
  }
  const client = await services.clientFor(value.project);
  const result = await withJobRefresh(
    services,
    async () => await withAbortableNotification(
      `Removing ${displayText(value.artifact.file_name)}`,
      async (signal) => await client.removeJobArtifact(
        value.project.root.fsPath,
        value.localJobId,
        value.artifact.artifact_id,
        signal
      )
    )
  );
  const suffix = result.response.replacement_preserved
    ? " The replacement was preserved."
    : "";
  await vscode.window.showInformationMessage(
    `${displayText(value.artifact.file_name)}: ${displayText(result.response.status)}.${suffix}`
  );
}

export async function runRemoteSnapshotBuild(
  services: CommandServices,
  argument?: unknown
): Promise<void> {
  const project = requireProjectArgument(services, argument);
  requireRemoteCommand(project, remoteIdeCommands.buildPreview);
  requireRemoteCommand(project, remoteIdeCommands.buildSubmit);
  const client = await services.clientFor(project);
  const preview = await client.remoteBuildPreview(
    project.root.fsPath,
    { profile: project.selectedProfile }
  );
  const response = preview.response;
  const submission = await submitAfterRemoteBuildConsent(
    response,
    async () => await vscode.window.showWarningMessage(
      `Build an unsigned ${response.profile} iPhone XCArchive from this workspace snapshot?`,
      {
        modal: true,
        detail: remoteBuildPreviewDetail(response)
      },
      "Build Snapshot"
    ) === "Build Snapshot",
    approveRemoteBuildPreview,
    async (consent) => await withJobRefresh(
      services,
      async () => await withAbortableNotification(
        "Submitting remote iPhone snapshot build",
        async (signal) => await client.submitRemoteBuild(
          project.root.fsPath,
          consent,
          signal
        )
      )
    )
  );
  if (submission === undefined) {
    return;
  }
  await vscode.window.showInformationMessage(
    `Submitted remote snapshot job ${submission.response.job.local_job_id}.`
  );
}

export async function showSigningReadiness(
  services: CommandServices,
  argument?: unknown
): Promise<void> {
  const project = requireProjectArgument(services, argument);
  requireRemoteCommand(project, remoteIdeCommands.signingReadiness);
  const result = await (await services.clientFor(project)).signingReadiness(project.root.fsPath);
  await showJsonDocument(result.response);
}

function requireJobArgument(services: CommandServices, argument: unknown): JobArgument {
  if (
    typeof argument !== "object"
    || argument === null
    || !("project" in argument)
    || !("job" in argument)
    || typeof argument.job !== "object"
    || argument.job === null
    || !("local_job_id" in argument.job)
    || typeof argument.job.local_job_id !== "string"
  ) {
    throw new UserActionError("Select a RustFerry job first.");
  }
  const value = argument as JobArgument;
  requireCurrentProject(services, value.project);
  return value;
}

function requireJobAction(
  services: CommandServices,
  argument: unknown,
  action: "cancel" | "retry"
): JobArgument {
  const value = requireJobArgument(services, argument);
  const allowed = action === "cancel" ? value.job.can_cancel : value.job.can_retry;
  if (!allowed) {
    const reason = action === "cancel"
      ? value.job.cancel_reason_code
      : value.job.retry_reason_code;
    throw new UserActionError(
      `${action === "cancel" ? "Cancellation" : "Retry"} is unavailable${reason === undefined ? "" : ` (${displayText(reason)})`}. Refresh Jobs for the current state.`
    );
  }
  return value;
}

function requireJobArtifactArgument(
  services: CommandServices,
  argument: unknown
): JobArtifactArgument {
  if (
    typeof argument !== "object"
    || argument === null
    || !("project" in argument)
    || !("localJobId" in argument)
    || typeof argument.localJobId !== "string"
    || !("artifact" in argument)
    || typeof argument.artifact !== "object"
    || argument.artifact === null
    || !("artifact_id" in argument.artifact)
    || typeof argument.artifact.artifact_id !== "string"
  ) {
    throw new UserActionError("Select a RustFerry job artifact first.");
  }
  const value = argument as JobArtifactArgument;
  requireCurrentProject(services, value.project);
  return value;
}

function requireJobArtifactAction(
  services: CommandServices,
  argument: unknown,
  action: "verify" | "reveal" | "remove"
): JobArtifactArgument {
  const value = requireJobArtifactArgument(services, argument);
  const allowed = action === "verify"
    ? value.artifact.can_verify
    : action === "reveal"
      ? value.artifact.can_reveal
      : value.artifact.can_remove;
  if (!allowed) {
    const reason = action === "verify"
      ? value.artifact.verify_reason_code
      : action === "reveal"
        ? value.artifact.reveal_reason_code
        : value.artifact.remove_reason_code;
    throw new UserActionError(
      `${action[0]?.toUpperCase()}${action.slice(1)} is unavailable${reason === undefined ? "" : ` (${displayText(reason)})`}. Refresh Jobs for the current state.`
    );
  }
  return value;
}

function requireCurrentProject(services: CommandServices, project: WorkspaceProject): void {
  if (!services.projects.all.includes(project)) {
    throw new UserActionError("Refresh Jobs and select an item from the current workspace.");
  }
  requireExecution(project);
}

function requireProjectArgument(
  services: CommandServices,
  argument: unknown
): WorkspaceProject {
  if (
    typeof argument !== "object"
    || argument === null
    || !("project" in argument)
  ) {
    throw new UserActionError("Select a RustFerry project in the Jobs view first.");
  }
  const project = argument.project as WorkspaceProject;
  requireCurrentProject(services, project);
  return project;
}

function requireRemoteCommand(project: WorkspaceProject, command: RemoteIdeCommand): void {
  if (!advertisesRemoteCommand(project.handshake?.supported_commands ?? [], command)) {
    throw new UserActionError(
      `Installed cargo-ferry does not advertise the exact ${command} IDE command.`
    );
  }
}

function jobLabel(value: JobArgument): string {
  return displayText(value.job.app_label ?? value.job.local_job_id);
}

function displayText(value: string): string {
  return value.replaceAll(/[\r\n\t]+/gu, " ").trim().slice(0, 512);
}

async function showJsonDocument(value: unknown): Promise<void> {
  const document = await vscode.workspace.openTextDocument({
    content: `${JSON.stringify(value, null, 2)}\n`,
    language: "json"
  });
  await vscode.window.showTextDocument(document, { preview: true });
}

async function withAbortableNotification<T>(
  title: string,
  operation: (signal: AbortSignal) => Promise<T>
): Promise<T> {
  return await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title, cancellable: true },
    async (_progress, token) => {
      const controller = new AbortController();
      const subscription = token.onCancellationRequested(() => controller.abort());
      try {
        return await operation(controller.signal);
      } finally {
        subscription.dispose();
      }
    }
  );
}

async function withJobRefresh<T>(
  services: CommandServices,
  operation: () => Promise<T>
): Promise<T> {
  try {
    return await operation();
  } finally {
    services.refreshJobs();
  }
}
