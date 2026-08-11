import { performance } from "node:perf_hooks";

import * as vscode from "vscode";

import { CliClient } from "./cli/client.js";
import { discoverCli, CliDiscoveryError, type CliInvocation } from "./cli/discovery.js";
import { ProcessRunner } from "./cli/process.js";
import { ProtocolError } from "./cli/protocol.js";
import { registerCommands } from "./commands/index.js";
import type { CommandServices } from "./commands/types.js";
import { settings } from "./config/settings.js";
import {
  commands,
  INSTALLATION_URL,
  JOB_LOGS_CHANNEL,
  LOGS_CHANNEL,
  OUTPUT_CHANNEL
} from "./constants.js";
import { RustFerryDiagnostics } from "./diagnostics/collection.js";
import { ConfigValidationCoordinator } from "./diagnostics/configValidation.js";
import { RustFerryTaskProvider } from "./tasks/provider.js";
import { RustFerryStatusBar } from "./ui/statusBar.js";
import { ArtifactsTreeProvider } from "./views/artifactsTree.js";
import { DevicesTreeProvider } from "./views/devicesTree.js";
import { JobsTreeProvider } from "./views/jobsTree.js";
import { ProjectTreeProvider } from "./views/projectTree.js";
import { WorkspaceProjects } from "./workspace/discovery.js";
import type { WorkspaceProject } from "./workspace/project.js";

let active: ExtensionController | undefined;

export type ExtensionPerformanceSnapshot = Readonly<{
  activationMs: number;
  projectDiscoveryMs: number;
  treeRefreshMs: number;
  projectCount: number;
  validProjectCount: number;
}>;

export type RustFerryExtensionApi = Readonly<{
  performanceSnapshot: () => ExtensionPerformanceSnapshot;
}>;

export async function activate(context: vscode.ExtensionContext): Promise<RustFerryExtensionApi> {
  const started = performance.now();
  const controller = new ExtensionController(context);
  active = controller;
  context.subscriptions.push(controller);
  await controller.start();
  controller.recordActivation(performance.now() - started);
  return Object.freeze({
    performanceSnapshot: () => controller.performanceSnapshot()
  });
}

export function deactivate(): void {
  active?.dispose();
  active = undefined;
}

class ExtensionController implements vscode.Disposable {
  readonly #runner = new ProcessRunner();
  readonly #output = vscode.window.createOutputChannel(OUTPUT_CHANNEL, { log: true });
  readonly #logs = vscode.window.createOutputChannel(LOGS_CHANNEL);
  readonly #jobLogs = vscode.window.createOutputChannel(JOB_LOGS_CHANNEL);
  readonly #projects: WorkspaceProjects;
  readonly #diagnostics = new RustFerryDiagnostics();
  readonly #validation: ConfigValidationCoordinator;
  readonly #disposables: vscode.Disposable[] = [];
  readonly #invocations = new Map<string, Promise<CliInvocation>>();
  readonly #clients = new Map<string, Promise<CliClient>>();
  #missingCliNotified = false;
  #protocolNotified = false;
  #activationMs = 0;
  #treeRefreshMs = 0;
  #disposed = false;

  public constructor(readonly context: vscode.ExtensionContext) {
    this.#projects = new WorkspaceProjects(context);
    this.#validation = new ConfigValidationCoordinator(
      this.#projects,
      this.#diagnostics,
      async (project) => await this.clientFor(project),
      (error, label) => this.#output.appendLine(`${label}: ${error instanceof Error ? error.message : String(error)}`)
    );

    const projectTree = new ProjectTreeProvider(this.#projects);
    const devicesTree = new DevicesTreeProvider(this.#projects);
    const artifactsTree = new ArtifactsTreeProvider(this.#projects);
    const jobsTree = new JobsTreeProvider(
      this.#projects,
      async (project) => await this.clientFor(project),
      this.#output
    );
    const statusBar = new RustFerryStatusBar(this.#projects);
    this.#disposables.push(
      this.#runner,
      this.#output,
      this.#logs,
      this.#jobLogs,
      this.#projects,
      this.#diagnostics,
      this.#validation,
      projectTree,
      devicesTree,
      artifactsTree,
      jobsTree,
      statusBar,
      vscode.window.createTreeView("rustferry.project", { treeDataProvider: projectTree, showCollapseAll: true }),
      vscode.window.createTreeView("rustferry.devices", { treeDataProvider: devicesTree, showCollapseAll: true }),
      vscode.window.createTreeView("rustferry.artifacts", { treeDataProvider: artifactsTree, showCollapseAll: true }),
      vscode.window.createTreeView("rustferry.jobs", { treeDataProvider: jobsTree, showCollapseAll: true }),
      vscode.languages.registerCodeActionsProvider(
        { language: "toml", pattern: "**/ferry.toml" },
        this.#diagnostics,
        { providedCodeActionKinds: this.#diagnostics.providedCodeActionKinds }
      )
    );

    const services: CommandServices = {
      context,
      projects: this.#projects,
      diagnostics: this.#diagnostics,
      validation: this.#validation,
      output: this.#output,
      logs: this.#logs,
      jobLogs: this.#jobLogs,
      clientFor: async (project) => await this.clientFor(project),
      clientAt: async (cwd, resource) => await this.clientAt(cwd, resource),
      invocationFor: async (project) => await this.invocationFor(project),
      refreshProject: async (project) => await this.refreshProject(project),
      refreshAll: async () => await this.refreshAll(),
      refreshJobs: () => jobsTree.refresh(),
      loadMoreJobLogs: async (argument) => await jobsTree.loadMoreLogs(argument)
    };
    this.#disposables.push(
      ...registerCommands(services),
      vscode.tasks.registerTaskProvider("rustferry", new RustFerryTaskProvider(this.#projects, services.invocationFor)),
      vscode.workspace.onDidChangeWorkspaceFolders(() => {
        void this.refreshAll();
      }),
      vscode.workspace.onDidGrantWorkspaceTrust(() => {
        this.#clearClients();
        void this.refreshAll();
      }),
      vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration("rustferry")) {
          this.#clearClients();
          void this.refreshAll();
        }
      }),
      vscode.workspace.onDidOpenTextDocument((document) => this.#validation.schedule(document, true)),
      vscode.workspace.onDidChangeTextDocument((event) => this.#validation.schedule(event.document)),
      vscode.workspace.onDidSaveTextDocument((document) => this.#validation.schedule(document, true))
    );
  }

  public async start(): Promise<void> {
    this.#output.appendLine(`RustFerry extension activated in ${environmentLabel()}.`);
    await this.refreshAll();
    for (const document of vscode.workspace.textDocuments) {
      this.#validation.schedule(document, true);
    }
    void this.#recommendRustAnalyzer().catch((error: unknown) => {
      this.#output.appendLine(
        `rust-analyzer recommendation failed: ${error instanceof Error ? error.message : String(error)}`
      );
    });
    const walkthroughKey = "rustferry.openWalkthroughAfterProjectCreation";
    if (this.context.globalState.get<boolean>(walkthroughKey, false)) {
      await this.context.globalState.update(walkthroughKey, false);
      await vscode.commands.executeCommand("workbench.action.openWalkthrough", "shiroksh.rustferry-vscode#rustferry.gettingStarted", false);
    }
  }

  public async refreshAll(): Promise<void> {
    const started = performance.now();
    try {
      await this.#refreshAll();
    } finally {
      this.#treeRefreshMs = performance.now() - started;
    }
  }

  public recordActivation(durationMs: number): void {
    this.#activationMs = durationMs;
  }

  public performanceSnapshot(): ExtensionPerformanceSnapshot {
    return {
      activationMs: this.#activationMs,
      projectDiscoveryMs: this.#projects.lastDiscoveryMs,
      treeRefreshMs: this.#treeRefreshMs,
      projectCount: this.#projects.all.length,
      validProjectCount: this.#projects.all.filter((project) => project.valid === true).length
    };
  }

  async #refreshAll(): Promise<void> {
    if (this.#disposed) {
      return;
    }
    await this.#projects.discover();
    if (!vscode.workspace.isTrusted) {
      this.#output.appendLine("Workspace is untrusted; process execution is disabled.");
      return;
    }
    for (const project of this.#projects.all) {
      await this.refreshProject(project);
    }
    for (const project of this.#projects.all) {
      if (project.executionAvailable && project.error === undefined) {
        const document = vscode.workspace.textDocuments.find((candidate) => candidate.uri.toString() === project.manifest.toString());
        if (document !== undefined) {
          this.#validation.schedule(document, true);
        } else {
          void this.#validation.validate(project);
        }
      }
    }
  }

  public async refreshProject(project: WorkspaceProject): Promise<void> {
    if (!project.executionAvailable) {
      project.error = undefined;
      this.#projects.refreshViews();
      return;
    }
    try {
      const client = await this.clientFor(project);
      const handshake = await client.handshake(project.root.fsPath);
      const response = await client.project(project.root.fsPath);
      project.handshake = handshake;
      project.metadata = response.project;
      if (response.project.artifacts !== undefined) {
        for (const artifact of response.project.artifacts) {
          await this.#projects.rememberArtifact(project, artifact);
        }
      }
      project.error = undefined;
      this.#protocolNotified = false;
      this.#missingCliNotified = false;
    } catch (error) {
      project.error = error instanceof Error ? error.message : String(error);
      if (error instanceof CliDiscoveryError) {
        await this.#notifyMissingCli();
      } else if (error instanceof ProtocolError && error.code === "protocol.incompatible") {
        await this.#notifyProtocolMismatch(error);
      } else {
        this.#output.appendLine(`Project refresh failed for ${project.root.fsPath}: ${project.error}`);
      }
    } finally {
      this.#projects.refreshViews();
    }
  }

  public async invocationFor(project: WorkspaceProject): Promise<CliInvocation> {
    const key = project.key;
    let value = this.#invocations.get(key);
    if (value === undefined) {
      value = discoverCli(project.root.fsPath, settings(project.root));
      this.#invocations.set(key, value);
    }
    try {
      return await value;
    } catch (error) {
      this.#invocations.delete(key);
      throw error;
    }
  }

  public async clientFor(project: WorkspaceProject): Promise<CliClient> {
    return await this.clientAt(project.root.fsPath, project.root, project.key);
  }

  public async clientAt(cwd: string, resource?: vscode.Uri, cacheKey?: string): Promise<CliClient> {
    if (!vscode.workspace.isTrusted) {
      throw new Error("Workspace Trust is required before starting cargo-ferry.");
    }
    const key = cacheKey ?? `${resource?.toString() ?? cwd}:${cwd}`;
    let value = this.#clients.get(key);
    if (value === undefined) {
      value = (async () => {
        const invocation = cacheKey === undefined
          ? await discoverCli(cwd, settings(resource))
          : await this.invocationFor(this.#projects.all.find((project) => project.key === cacheKey)!);
        return new CliClient(invocation, this.#runner, this.#output, settings(resource).maxProtocolLineBytes);
      })();
      this.#clients.set(key, value);
    }
    try {
      return await value;
    } catch (error) {
      this.#clients.delete(key);
      throw error;
    }
  }

  public dispose(): void {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    for (const disposable of this.#disposables.reverse()) {
      disposable.dispose();
    }
    this.#disposables.length = 0;
    this.#clearClients();
  }

  #clearClients(): void {
    this.#invocations.clear();
    this.#clients.clear();
  }

  async #notifyMissingCli(): Promise<void> {
    if (this.#missingCliNotified) {
      return;
    }
    this.#missingCliNotified = true;
    const selected = await vscode.window.showErrorMessage(
      "cargo-ferry was not found. Install it, select an executable, or retry discovery.",
      "Open Installation Guide",
      "Select Executable",
      "Retry"
    );
    if (selected === "Open Installation Guide") {
      await vscode.env.openExternal(vscode.Uri.parse(INSTALLATION_URL));
    } else if (selected === "Select Executable") {
      await vscode.commands.executeCommand(commands.selectCli);
    } else if (selected === "Retry") {
      this.#clearClients();
      await this.refreshAll();
    }
  }

  async #notifyProtocolMismatch(error: ProtocolError): Promise<void> {
    if (this.#protocolNotified) {
      return;
    }
    this.#protocolNotified = true;
    const selected = await vscode.window.showErrorMessage(error.message, "Open Installation Guide", "Retry");
    if (selected === "Open Installation Guide") {
      await vscode.env.openExternal(vscode.Uri.parse(INSTALLATION_URL));
    } else if (selected === "Retry") {
      this.#clearClients();
      await this.refreshAll();
    }
  }

  async #recommendRustAnalyzer(): Promise<void> {
    if (this.#projects.all.length === 0 || vscode.extensions.getExtension("rust-lang.rust-analyzer") !== undefined) {
      return;
    }
    const key = "rustferry.rustAnalyzerRecommendationShown";
    if (this.context.workspaceState.get<boolean>(key, false)) {
      return;
    }
    await this.context.workspaceState.update(key, true);
    const selected = await vscode.window.showInformationMessage(
      "Install rust-analyzer for Rust completion, navigation, and refactoring in RustFerry projects.",
      "Show rust-analyzer"
    );
    if (selected === "Show rust-analyzer") {
      await vscode.commands.executeCommand("workbench.extensions.search", "@id:rust-lang.rust-analyzer");
    }
  }
}

function environmentLabel(): string {
  if (vscode.env.remoteName === undefined) {
    return "Local";
  }
  return `Remote (${vscode.env.remoteName})`;
}
