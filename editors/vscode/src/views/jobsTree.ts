import * as vscode from "vscode";

import type { CliClient } from "../cli/client.js";
import type {
  JobArtifact,
  JobListItem,
  JobLogEvent,
  JobLogsPageResponse
} from "../cli/protocol.js";
import { commands, jobIdeCommands } from "../constants.js";
import {
  advertisesJobCommand,
  jobArtifactContextValue,
  jobContextValue,
  jobProjectContextValue
} from "../jobs/capabilities.js";
import {
  jobLogCoveragePresentation,
  jobLogEmptyText,
  jobLogTreePresentation,
  type JobLogCoveragePresentation
} from "../jobs/logPresentation.js";
import { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";

type JobElement =
  | JobProjectItem
  | JobItem
  | JobSectionItem
  | JobArtifactItem
  | JobLogCoverageItem
  | JobLogItem
  | DetailItem
  | MessageItem;

type ClientFor = (project: WorkspaceProject) => Promise<CliClient>;

const JOB_LOG_PAGE_LIMIT = 256;

export class JobsTreeProvider implements vscode.TreeDataProvider<JobElement>, vscode.Disposable {
  readonly #changed = new vscode.EventEmitter<JobElement | undefined>();
  readonly #subscription: vscode.Disposable;
  readonly #logPages = new Map<string, JobLogsPageResponse>();
  public readonly onDidChangeTreeData = this.#changed.event;

  public constructor(
    readonly projects: WorkspaceProjects,
    readonly clientFor: ClientFor,
    readonly output: vscode.LogOutputChannel
  ) {
    this.#subscription = projects.onDidChange(() => this.refresh());
  }

  public getTreeItem(element: JobElement): vscode.TreeItem {
    return element;
  }

  public async getChildren(element?: JobElement): Promise<JobElement[]> {
    if (element === undefined) {
      return this.projects.all.map((project) => new JobProjectItem(project));
    }
    if (element instanceof JobProjectItem) {
      return await this.#projectChildren(element.project);
    }
    if (element instanceof JobItem) {
      return jobChildren(element);
    }
    if (element instanceof JobSectionItem) {
      return await this.#sectionChildren(element);
    }
    return [];
  }

  public refresh(): void {
    this.#logPages.clear();
    this.#changed.fire(undefined);
  }

  public async loadMoreLogs(argument: unknown): Promise<void> {
    if (!(argument instanceof JobSectionItem) || argument.kind !== "logs") {
      return;
    }
    const key = logPageKey(argument);
    const current = this.#logPages.get(key) ?? await this.#loadLogPage(argument, "0", true);
    if (!current.has_more) {
      return;
    }
    await this.#loadLogPage(argument, current.next_after_sequence, false);
    this.#changed.fire(argument);
  }

  public dispose(): void {
    this.#subscription.dispose();
    this.#changed.dispose();
  }

  async #projectChildren(project: WorkspaceProject): Promise<JobElement[]> {
    if (!vscode.workspace.isTrusted) {
      return [new MessageItem("Trust the workspace to inspect remote jobs", "lock")];
    }
    if (project.root.scheme !== "file") {
      return [new MessageItem("Jobs are unavailable in a virtual workspace", "remote")];
    }
    try {
      const result = await (await this.clientFor(project)).jobsList(project.root.fsPath);
      if (result.response.jobs.length === 0) {
        return [new MessageItem("No remote-build jobs for this workspace", "info")];
      }
      return result.response.jobs.map(
        (job) => new JobItem(project, job, result.supportedCommands)
      );
    } catch (error) {
      if (!isUnsupportedCommand(error)) {
        this.output.error(
          `Jobs refresh failed for ${project.root.fsPath}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      return [new MessageItem(jobErrorMessage(error), "warning")];
    }
  }

  async #sectionChildren(section: JobSectionItem): Promise<JobElement[]> {
    try {
      const client = await this.clientFor(section.project);
      if (section.kind === "artifacts") {
        const result = await client.jobArtifacts(
          section.project.root.fsPath,
          section.job.local_job_id
        );
        if (result.response.artifacts.length === 0) {
          return [new MessageItem("No artifacts recorded", "info")];
        }
        return result.response.artifacts.map(
          (artifact) => new JobArtifactItem(
            section.project,
            section.job.local_job_id,
            artifact,
            result.supportedCommands
          )
        );
      }
      const result = this.#logPages.get(logPageKey(section))
        ?? await this.#loadLogPage(section, "0", true);
      const children: JobElement[] = [new JobLogCoverageItem(
        jobLogCoveragePresentation(result)
      )];
      children.push(new DetailItem(
        "Log page",
        `${result.returned} event${result.returned === 1 ? "" : "s"} after sequence ${result.after_sequence}`,
        "list-ordered"
      ));
      if (result.events.length === 0) {
        children.push(new MessageItem(jobLogEmptyText(result), "info"));
      } else {
        children.push(...result.events.map((event) => new JobLogItem(event)));
      }
      if (result.has_more) {
        children.push(new JobLogLoadMoreItem(section, result.next_after_sequence));
      }
      if (!result.terminal) {
        children.push(new JobLogFollowItem(section));
      }
      return children;
    } catch (error) {
      if (!isUnsupportedCommand(error)) {
        this.output.error(
          `Jobs ${section.kind} refresh failed for ${section.job.local_job_id}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      return [new MessageItem(jobErrorMessage(error), "warning")];
    }
  }

  async #loadLogPage(
    section: JobSectionItem,
    afterSequence: string,
    refresh: boolean
  ): Promise<JobLogsPageResponse> {
    const result = await (await this.clientFor(section.project)).jobLogsPage(
      section.project.root.fsPath,
      section.job.local_job_id,
      { afterSequence, limit: JOB_LOG_PAGE_LIMIT, refresh }
    );
    this.#logPages.set(logPageKey(section), result.response);
    return result.response;
  }
}

class JobProjectItem extends vscode.TreeItem {
  public constructor(readonly project: WorkspaceProject) {
    super(project.displayName, vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = jobProjectContextValue(project.handshake?.supported_commands ?? []);
    this.iconPath = new vscode.ThemeIcon("package");
  }
}

export class JobItem extends vscode.TreeItem {
  public override readonly contextValue: string;

  public constructor(
    readonly project: WorkspaceProject,
    readonly job: JobListItem,
    readonly supportedCommands: readonly string[]
  ) {
    super(displayText(job.app_label), vscode.TreeItemCollapsibleState.Collapsed);
    this.contextValue = jobContextValue(supportedCommands, job);
    this.description = [job.state, job.target, job.profile].map(displayText).join(" | ");
    this.tooltip = [
      `Job: ${job.local_job_id}`,
      `State: ${displayText(job.state)}`,
      `Application: ${displayText(job.application_identifier)}`,
      `Provider: ${displayText(job.provider)}`,
      `Updated: ${formatTimestamp(job.updated_at_ms)}`,
      job.can_cancel ? "Cancellation: available" : `Cancellation unavailable: ${job.cancel_reason_code}`,
      job.can_retry ? "Retry: available" : `Retry unavailable: ${job.retry_reason_code}`
    ].join("\n");
    this.iconPath = new vscode.ThemeIcon(jobIcon(job.state), jobColor(job.state));
    if (advertisesJobCommand(supportedCommands, jobIdeCommands.show)) {
      this.command = {
        command: commands.showJob,
        title: "Show Job",
        arguments: [this]
      };
    }
  }
}

class JobSectionItem extends vscode.TreeItem {
  public constructor(
    readonly project: WorkspaceProject,
    readonly job: JobListItem,
    readonly kind: "artifacts" | "logs"
  ) {
    super(kind === "artifacts" ? "Artifacts" : "Logs", vscode.TreeItemCollapsibleState.Collapsed);
    this.iconPath = new vscode.ThemeIcon(kind === "artifacts" ? "package" : "output");
    if (kind === "logs") {
      this.tooltip = "Durable sanitized job events; sanitized worker-log coverage is reported after loading.";
    }
  }
}

export class JobArtifactItem extends vscode.TreeItem {
  public override readonly contextValue: string;

  public constructor(
    readonly project: WorkspaceProject,
    readonly localJobId: string,
    readonly artifact: JobArtifact,
    supportedCommands: readonly string[]
  ) {
    super(displayText(artifact.file_name), vscode.TreeItemCollapsibleState.None);
    this.contextValue = jobArtifactContextValue(supportedCommands, artifact);
    this.description = [
      displayText(artifact.current_status),
      artifact.locally_validated ? "stored validation" : undefined,
      formatSize(artifact.size)
    ].filter((value): value is string => value !== undefined).join(" | ");
    this.tooltip = [
      `Artifact: ${artifact.artifact_id}`,
      `Kind: ${displayText(artifact.kind)}`,
      `SHA-256: ${artifact.sha256}`,
      `Stored validation: ${artifact.locally_validated ? "passed" : "not recorded"}`,
      `Current status: ${displayText(artifact.current_status)}`,
      artifact.local_path === undefined
        ? "Not downloaded"
        : `Recorded local path: ${displayText(artifact.local_path)}`,
      artifact.can_verify ? "Verification: available" : `Verification unavailable: ${artifact.verify_reason_code}`,
      artifact.can_reveal ? "Reveal: available" : `Reveal unavailable: ${artifact.reveal_reason_code}`,
      artifact.can_remove ? "Removal: available" : `Removal unavailable: ${artifact.remove_reason_code}`
    ].join("\n");
    this.iconPath = new vscode.ThemeIcon("file-zip");
    if (
      artifact.can_reveal
      && advertisesJobCommand(supportedCommands, jobIdeCommands.artifactReveal)
    ) {
      this.command = {
        command: commands.revealJobArtifact,
        title: "Reveal Job Artifact",
        arguments: [this]
      };
    }
  }
}

class JobLogCoverageItem extends vscode.TreeItem {
  public constructor(presentation: JobLogCoveragePresentation) {
    super(presentation.label, vscode.TreeItemCollapsibleState.None);
    this.description = presentation.description;
    this.tooltip = presentation.tooltip;
    this.iconPath = new vscode.ThemeIcon(presentation.icon);
  }
}

class JobLogItem extends vscode.TreeItem {
  public constructor(readonly event: JobLogEvent) {
    const presentation = jobLogTreePresentation(event);
    super(presentation.label, vscode.TreeItemCollapsibleState.None);
    this.description = presentation.description;
    this.tooltip = presentation.tooltip;
    this.iconPath = new vscode.ThemeIcon(presentation.icon);
  }
}

class JobLogLoadMoreItem extends vscode.TreeItem {
  public constructor(section: JobSectionItem, nextAfterSequence: string) {
    super("Load more logs", vscode.TreeItemCollapsibleState.None);
    this.description = `after sequence ${nextAfterSequence}`;
    this.iconPath = new vscode.ThemeIcon("chevron-down");
    this.command = {
      command: commands.loadMoreJobLogs,
      title: "Load More Job Logs",
      arguments: [section]
    };
  }
}

class JobLogFollowItem extends vscode.TreeItem {
  public constructor(section: JobSectionItem) {
    super("Follow logs until terminal", vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon("eye");
    this.command = {
      command: commands.followJobLogs,
      title: "Follow Job Logs",
      arguments: [section]
    };
  }
}

class DetailItem extends vscode.TreeItem {
  public constructor(label: string, description: string, icon: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.description = displayText(description);
    this.iconPath = new vscode.ThemeIcon(icon);
  }
}

class MessageItem extends vscode.TreeItem {
  public constructor(label: string, icon: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon(icon);
  }
}

function jobChildren(item: JobItem): JobElement[] {
  const children: JobElement[] = [
    new DetailItem("State", item.job.state, "pulse"),
    new DetailItem("Job ID", item.job.local_job_id, "symbol-key"),
    new DetailItem("Provider", item.job.provider, "cloud"),
    new DetailItem("Target", `${item.job.target} (${item.job.profile})`, "device-mobile"),
    new DetailItem("Cleanup", item.job.cleanup_status, "trash"),
    new DetailItem("Cancellation", item.job.cancellation_status, "circle-slash"),
    new DetailItem("Updated", formatTimestamp(item.job.updated_at_ms), "history")
  ];
  if (advertisesJobCommand(item.supportedCommands, jobIdeCommands.artifacts)) {
    children.push(new JobSectionItem(item.project, item.job, "artifacts"));
  }
  if (advertisesJobCommand(item.supportedCommands, jobIdeCommands.logsPage)) {
    children.push(new JobSectionItem(item.project, item.job, "logs"));
  }
  return children;
}

function jobErrorMessage(error: unknown): string {
  if (isUnsupportedCommand(error)) {
    return "Installed cargo-ferry does not support workspace-bound jobs";
  }
  return "Could not load jobs; see RustFerry output";
}

function logPageKey(section: JobSectionItem): string {
  return `${section.project.key}\0${section.job.local_job_id}`;
}

function isUnsupportedCommand(error: unknown): boolean {
  return error instanceof Error
    && "code" in error
    && error.code === "protocol.command_unsupported";
}

function displayText(value: string): string {
  return value.replaceAll(/[\r\n\t]+/gu, " ").trim().slice(0, 512);
}

function formatTimestamp(timestampMs: number): string {
  const date = new Date(timestampMs);
  return Number.isNaN(date.valueOf()) ? String(timestampMs) : date.toLocaleString();
}

function formatSize(size: number): string {
  if (size < 1_024) {
    return `${size} B`;
  }
  if (size < 1_024 * 1_024) {
    return `${(size / 1_024).toFixed(1)} KiB`;
  }
  return `${(size / (1_024 * 1_024)).toFixed(1)} MiB`;
}

function jobIcon(state: string): string {
  if (state === "succeeded") {
    return "pass-filled";
  }
  if (state === "failed" || state === "cleanup_failed") {
    return "error";
  }
  if (state === "cancelled" || state === "expired") {
    return "circle-slash";
  }
  if (state === "queued") {
    return "clock";
  }
  if (state.endsWith("ing") || state === "running") {
    return "sync~spin";
  }
  return "circle-outline";
}

function jobColor(state: string): vscode.ThemeColor | undefined {
  if (state === "succeeded") {
    return new vscode.ThemeColor("testing.iconPassed");
  }
  if (state === "failed" || state === "cleanup_failed") {
    return new vscode.ThemeColor("testing.iconFailed");
  }
  return undefined;
}
