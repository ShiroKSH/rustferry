import * as vscode from "vscode";

import { randomUUID } from "node:crypto";

import {
  artifactBuildPlatform,
  deviceMatchesBuildPlatform,
  eventArtifact,
  eventDiagnostic,
  type BuildPlatform,
  type ProtocolArtifact,
  type ProtocolDevice,
  type ProtocolDiagnostic,
  type ProtocolEvent
} from "../cli/protocol.js";
import { deploymentStreamRequest } from "../cli/client.js";
import { ProcessCancelledError } from "../cli/process.js";
import { setDevelopmentTeam, settings } from "../config/settings.js";
import { commands } from "../constants.js";
import { withCancellableProgress } from "../ui/progress.js";
import type { WorkspaceProject } from "../workspace/project.js";
import { buildTitle, platformLabel, requireExecution, selectedProject, UserActionError } from "./navigation.js";
import { runCheckAndPublish } from "./checkOperation.js";
import type { CommandServices } from "./types.js";

export class OperationCommands implements vscode.Disposable {
  #logsController: AbortController | undefined;

  public constructor(readonly services: CommandServices) {}

  public async check(argument?: unknown): Promise<void> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    await this.services.validation.validate(project);
    await withCancellableProgress("Checking RustFerry project", async (signal, report) => {
      const client = await this.services.clientFor(project);
      await runCheckAndPublish(
        client,
        project.root.fsPath,
        signal,
        report,
        (diagnostics) => this.services.diagnostics.publish(project, diagnostics)
      );
    });
    await this.services.refreshProject(project);
    await vscode.window.showInformationMessage("RustFerry project check passed.");
  }

  public async doctor(argument?: unknown): Promise<void> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    project.doctor = "running";
    this.services.projects.refreshViews();
    try {
      await withAbortableNotification("Running RustFerry Doctor", async (signal) => {
        const client = await this.services.clientFor(project);
        await client.doctor(project.root.fsPath, signal);
      });
      project.doctor = "passed";
      await vscode.window.showInformationMessage("RustFerry Doctor completed. See the RustFerry output channel for details.");
    } catch (error) {
      project.doctor = "failed";
      throw error;
    } finally {
      this.services.projects.refreshViews();
    }
  }

  public async selectDevelopmentTeam(argument?: unknown): Promise<string | undefined> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return undefined;
    }
    requireExecution(project);
    if (project.handshake?.features.physical_ios !== true) {
      throw new UserActionError("Physical iPhone development requires macOS and a compatible cargo-ferry build.");
    }
    const response = await withAbortableNotification(
      "Discovering Apple Development teams",
      async (signal) => {
        const client = await this.services.clientFor(project);
        return await client.signingTeams(project.root.fsPath, signal);
      }
    );
    if (response.teams.length === 0) {
      throw new UserActionError(
        "No usable Apple Development identity was found. Install a development certificate, then run RustFerry: Run iOS Doctor."
      );
    }
    const configured = settings().developmentTeam;
    const selected = await vscode.window.showQuickPick(
      response.teams.map((team) => ({
        label: team.team_id,
        description: team.identity,
        detail: `Certificate ${team.certificate_fingerprint}`,
        picked: team.team_id === configured,
        team
      })),
      {
        placeHolder: "Select an Apple Development Team",
        matchOnDescription: true,
        matchOnDetail: true
      }
    );
    if (selected === undefined) {
      return undefined;
    }
    await setDevelopmentTeam(selected.team.team_id);
    this.services.output.appendLine(`Selected Apple Development Team ${selected.team.team_id}.`);
    return selected.team.team_id;
  }

  public async build(argument: unknown, platform?: BuildPlatform): Promise<void> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    const target = platform ?? project.selectedPlatform;
    assertBuildSupported(project, target);
    await this.services.projects.setPlatform(project, target);
    const team = target === "ios-device" ? await this.#requireDevelopmentTeam(project) : undefined;
    const diagnostics: ProtocolDiagnostic[] = [];
    const artifacts: ProtocolArtifact[] = [];
    const outcome: { success?: boolean } = {};
    try {
      await withCancellableProgress(buildTitle(target, project.selectedProfile), async (signal, report) => {
        const client = await this.services.clientFor(project);
        await client.stream(
          {
            operation: "build",
            workspace: project.root.fsPath,
            platform: target,
            profile: project.selectedProfile,
            ...(team === undefined ? {} : { team }),
            operationId: randomUUID()
          },
          async (event) => {
            await report(event);
            await this.#consumeBuildEvent(project, event, diagnostics, artifacts);
            if (event.event === "operation_finished") {
              outcome.success = event.success === true;
            }
          },
          signal
        );
      });
    } finally {
      this.services.diagnostics.publish(project, diagnostics);
    }
    if (outcome.success !== true || artifacts.length === 0) {
      throw new UserActionError("The build ended without a validated artifact. Open the RustFerry output channel for the operation summary.");
    }
    const primary = artifacts[0]!;
    const platformName = platformLabel(target);
    const selected = await vscode.window.showInformationMessage(
      `${platformName} application built successfully.`,
      "Reveal Artifact",
      "Copy Path",
      ...(project.handshake?.features.install === true ? ["Install"] : [])
    );
    const item = { project, artifact: primary };
    if (selected === "Reveal Artifact") {
      await vscode.commands.executeCommand(commands.revealArtifact, item);
    } else if (selected === "Copy Path") {
      await vscode.commands.executeCommand(commands.copyArtifactPath, item);
    } else if (selected === "Install") {
      await vscode.commands.executeCommand(commands.install, item);
    }
  }

  public async clean(argument?: unknown): Promise<void> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    const confirmation = await vscode.window.showWarningMessage(
      "Remove generated platform files while retaining final artifacts and caches?",
      { modal: true },
      "Clean Generated Files"
    );
    if (confirmation !== "Clean Generated Files") {
      return;
    }
    await withAbortableNotification("Cleaning generated RustFerry files", async (signal) => {
      const client = await this.services.clientFor(project);
      await client.clean(project.root.fsPath, signal);
    });
    await this.services.refreshProject(project);
  }

  public async refreshDevices(argument?: unknown): Promise<void> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    if (project.handshake?.features.devices !== true) {
      throw new UserActionError("This cargo-ferry version does not support device discovery. Update cargo-ferry to enable the Devices view.");
    }
    const response = await withAbortableNotification("Discovering RustFerry devices", async (signal) => {
      const client = await this.services.clientFor(project);
      return await client.devices("all", project.root.fsPath, signal);
    });
    project.devices = response.devices;
    for (const warning of response.warnings) {
      this.services.output.appendLine(`Device discovery warning [${warning.code}/${warning.source}]: ${warning.message}`);
    }
    this.services.projects.restoreSelectedDevice(project);
    this.services.projects.refreshViews();
  }

  public async selectDevice(argument?: unknown): Promise<void> {
    const argumentDevice = deviceFromArgument(argument);
    if (argumentDevice !== undefined) {
      assertDeviceCompatible(argumentDevice.project, argumentDevice.device);
      await this.services.projects.select(argumentDevice.project);
      await this.services.projects.setDevice(argumentDevice.project, argumentDevice.device);
      return;
    }
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    if (project.devices.length === 0) {
      await this.refreshDevices(project);
    }
    const compatible = project.devices.filter((device) => deviceMatchesBuildPlatform(device, project.selectedPlatform));
    if (compatible.length === 0) {
      await vscode.window.showInformationMessage(
        `No compatible ${platformLabel(project.selectedPlatform)} device is currently available.`
      );
      return;
    }
    const choice = await vscode.window.showQuickPick(
      compatible.map((device) => ({
        label: device.name,
        description: [device.platform, device.state, device.os_version].filter(Boolean).join(" · "),
        detail: `${device.kind} · ${device.id}`,
        device,
        picked: device.id === project.selectedDevice?.id
      })),
      { placeHolder: "Select a RustFerry device", matchOnDescription: true, matchOnDetail: true }
    );
    if (choice !== undefined) {
      await this.services.projects.setDevice(project, choice.device);
    }
  }

  public async install(argument?: unknown): Promise<void> {
    await this.#deployment("install", argument);
  }

  public async run(argument?: unknown): Promise<void> {
    await this.#deployment("run", argument);
  }

  public async logs(argument?: unknown): Promise<void> {
    await this.#startLogs(argument);
  }

  public stopLogs(): void {
    this.#logsController?.abort();
    this.#logsController = undefined;
  }

  public dispose(): void {
    this.stopLogs();
  }

  async #consumeBuildEvent(
    project: WorkspaceProject,
    event: ProtocolEvent,
    diagnostics: ProtocolDiagnostic[],
    artifacts: ProtocolArtifact[]
  ): Promise<void> {
    const diagnostic = eventDiagnostic(event);
    if (diagnostic !== undefined) {
      diagnostics.push(diagnostic);
    }
    const artifact = eventArtifact(event);
    if (artifact !== undefined) {
      artifacts.push(artifact);
      await this.services.projects.rememberArtifact(project, artifact);
    }
    if (event.event === "log" && typeof event.message === "string") {
      this.services.logs.appendLine(event.message);
    }
  }

  async #deployment(operation: "install" | "run", argument?: unknown): Promise<void> {
    const artifactArgument = artifactFromArgument(argument);
    const project = await selectedProject(this.services, artifactArgument?.project ?? argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    if (artifactArgument !== undefined) {
      const platform = artifactBuildPlatform(artifactArgument.artifact);
      if (platform === undefined) {
        throw new UserActionError("This artifact target is not supported by the VS Code deployment flow.");
      }
      await this.services.projects.setPlatform(project, platform);
    }
    if (project.handshake?.features[operation] !== true) {
      throw new UserActionError(`This cargo-ferry version does not support ${operation}. Update cargo-ferry and run Doctor again.`);
    }
    if (
      project.selectedDevice === undefined
      || !deviceMatchesBuildPlatform(project.selectedDevice, project.selectedPlatform)
    ) {
      await this.selectDevice(project);
    }
    const device = project.selectedDevice;
    if (device === undefined) {
      return;
    }
    const team = project.selectedPlatform === "ios-device"
      ? await this.#requireDevelopmentTeam(project)
      : undefined;
    await withCancellableProgress(`${operation === "install" ? "Installing" : "Running"} ${project.displayName}`, async (signal, report) => {
      const client = await this.services.clientFor(project);
      await client.stream(
        deploymentStreamRequest(
          operation,
          project.root.fsPath,
          project.selectedPlatform,
          device.id,
          randomUUID(),
          team
        ),
        async (event) => {
          await report(event);
          const artifact = eventArtifact(event);
          if (artifact !== undefined) {
            await this.services.projects.rememberArtifact(project, artifact);
          }
        },
        signal
      );
    });
    await vscode.window.showInformationMessage(
      operation === "install" ? `Installed ${project.displayName} on ${device.name}.` : `Started ${project.displayName} on ${device.name}.`
    );
  }

  async #startLogs(argument?: unknown): Promise<void> {
    const project = await selectedProject(this.services, argument);
    if (project === undefined) {
      return;
    }
    requireExecution(project);
    if (project.handshake?.features.logs !== true) {
      throw new UserActionError("This cargo-ferry version does not support application logs.");
    }
    if (project.selectedPlatform === "ios-device") {
      throw new UserActionError(
        "Standalone physical-iPhone log streaming is unavailable because CoreDevice cannot provide the same application-only boundary."
      );
    }
    if (
      project.selectedDevice === undefined
      || !deviceMatchesBuildPlatform(project.selectedDevice, project.selectedPlatform)
    ) {
      await this.selectDevice(project);
    }
    const device = project.selectedDevice;
    if (device === undefined) {
      return;
    }
    this.stopLogs();
    const controller = new AbortController();
    this.#logsController = controller;
    this.services.logs.clear();
    this.services.logs.show(true);
    this.services.logs.appendLine(`RustFerry logs · ${project.displayName} · ${device.name}`);
    const client = await this.services.clientFor(project);
    void client.stream(
      {
        operation: "logs",
        workspace: project.root.fsPath,
        platform: project.selectedPlatform,
        device: device.id,
        operationId: randomUUID()
      },
      (event) => {
        if (event.event === "log" && typeof event.message === "string") {
          this.services.logs.appendLine(event.message);
        }
      },
      controller.signal
    ).catch((error: unknown) => {
      if (!(error instanceof ProcessCancelledError)) {
        this.services.logs.appendLine(`Logs stopped: ${error instanceof Error ? error.message : String(error)}`);
      }
    }).finally(() => {
      if (this.#logsController === controller) {
        this.#logsController = undefined;
      }
    });
  }

  async #requireDevelopmentTeam(project: WorkspaceProject): Promise<string> {
    const configured = settings().developmentTeam;
    if (configured !== undefined) {
      return configured;
    }
    const selected = await this.selectDevelopmentTeam(project);
    if (selected === undefined) {
      throw new UserActionError("Select an Apple Development Team before building for a physical iPhone.");
    }
    return selected;
  }
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

function assertBuildSupported(project: WorkspaceProject, platform: BuildPlatform): void {
  const features = project.handshake?.features;
  if (platform === "android" && features?.android_build === false) {
    throw new UserActionError("Android builds are unavailable in this cargo-ferry environment. Run RustFerry Doctor for setup actions.");
  }
  if (platform === "ios-simulator" && features?.ios_simulator_build === false) {
    throw new UserActionError("iOS Simulator builds require macOS, Xcode, and an installed Simulator SDK. Select Android or open the iOS setup guide.");
  }
  if (platform === "ios-device" && features?.physical_ios !== true) {
    throw new UserActionError(
      "Physical iPhone builds require macOS, full Xcode, and a cargo-ferry build with official signing support."
    );
  }
}

function deviceFromArgument(argument: unknown): { project: WorkspaceProject; device: ProtocolDevice } | undefined {
  if (typeof argument !== "object" || argument === null || !("project" in argument) || !("device" in argument)) {
    return undefined;
  }
  return { project: argument.project as WorkspaceProject, device: argument.device as ProtocolDevice };
}

function artifactFromArgument(argument: unknown): { project: WorkspaceProject; artifact: ProtocolArtifact } | undefined {
  if (typeof argument !== "object" || argument === null || !("project" in argument) || !("artifact" in argument)) {
    return undefined;
  }
  return { project: argument.project as WorkspaceProject, artifact: argument.artifact as ProtocolArtifact };
}

function assertDeviceCompatible(project: WorkspaceProject, device: ProtocolDevice): void {
  if (deviceMatchesBuildPlatform(device, project.selectedPlatform)) {
    return;
  }
  throw new UserActionError(`Select a device compatible with ${project.selectedPlatform}.`);
}
