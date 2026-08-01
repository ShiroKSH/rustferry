import { performance } from "node:perf_hooks";

import * as vscode from "vscode";

import {
  deviceMatchesBuildPlatform,
  ProtocolError,
  type BuildPlatform,
  type BuildProfile,
  type ProtocolArtifact,
  type ProtocolDevice
} from "../cli/protocol.js";
import { settings } from "../config/settings.js";
import { PROJECT_MANIFEST } from "../constants.js";
import { artifactPathWithinGeneratedRoot } from "./artifactSafety.js";
import { WorkspaceProject } from "./project.js";

const SELECTED_PROJECT_KEY = "rustferry.selectedProject";
const projectStateKey = (project: WorkspaceProject, field: string): string => `rustferry.project.${project.key}.${field}`;

export class WorkspaceProjects implements vscode.Disposable {
  readonly #changed = new vscode.EventEmitter<void>();
  readonly #context: vscode.ExtensionContext;
  #projects: WorkspaceProject[] = [];
  #selected: WorkspaceProject | undefined;
  #lastDiscoveryMs = 0;

  public readonly onDidChange = this.#changed.event;

  public constructor(context: vscode.ExtensionContext) {
    this.#context = context;
  }

  public get all(): readonly WorkspaceProject[] {
    return this.#projects;
  }

  public get selected(): WorkspaceProject | undefined {
    return this.#selected;
  }

  public get lastDiscoveryMs(): number {
    return this.#lastDiscoveryMs;
  }

  public async discover(): Promise<void> {
    const started = performance.now();
    const manifests = await findProjectManifests();
    const existing = new Map(this.#projects.map((project) => [project.key, project]));
    const projects = manifests.map((manifest) => {
      const root = vscode.Uri.joinPath(manifest, "..");
      const key = root.toString();
      const retained = existing.get(key);
      if (retained !== undefined) {
        return retained;
      }
      const defaults = settings(root);
      const platform = this.#context.workspaceState.get<BuildPlatform>(
        `rustferry.project.${key}.platform`,
        defaults.defaultPlatform
      );
      const profile = this.#context.workspaceState.get<BuildProfile>(
        `rustferry.project.${key}.profile`,
        defaults.defaultProfile
      );
      const project = new WorkspaceProject(root, manifest, platform, profile);
      project.artifacts = this.#context.workspaceState.get<readonly ProtocolArtifact[]>(
        `rustferry.project.${key}.artifacts`,
        []
      ).filter((artifact) => artifactPathWithinGeneratedRoot(project, artifact.path));
      return project;
    });
    projects.sort((left, right) => left.root.toString().localeCompare(right.root.toString()));
    this.#projects = projects;

    const selectedKey = this.#context.workspaceState.get<string>(SELECTED_PROJECT_KEY);
    this.#selected = projects.find((project) => project.key === selectedKey)
      ?? (projects.length === 1 ? projects[0] : projects.find((project) => project.key === this.#selected?.key));
    if (this.#selected === undefined && projects.length > 0) {
      this.#selected = projects[0];
    }
    await this.#updateContexts();
    this.#lastDiscoveryMs = performance.now() - started;
    this.#changed.fire();
  }

  public async select(project: WorkspaceProject): Promise<void> {
    if (!this.#projects.includes(project)) {
      return;
    }
    this.#selected = project;
    await this.#context.workspaceState.update(SELECTED_PROJECT_KEY, project.key);
    await this.#updateContexts();
    this.#changed.fire();
  }

  public async pick(placeHolder = "Select a RustFerry project"): Promise<WorkspaceProject | undefined> {
    if (this.#projects.length === 0) {
      return undefined;
    }
    if (this.#projects.length === 1) {
      return this.#projects[0];
    }
    const selected = await vscode.window.showQuickPick(
      this.#projects.map((project) => ({
        label: project.displayName,
        description: vscode.workspace.asRelativePath(project.root, false),
        project,
        picked: project === this.#selected
      })),
      { placeHolder, matchOnDescription: true }
    );
    if (selected === undefined) {
      return undefined;
    }
    await this.select(selected.project);
    return selected.project;
  }

  public async setPlatform(project: WorkspaceProject, platform: BuildPlatform): Promise<void> {
    project.selectedPlatform = platform;
    if (project.selectedDevice !== undefined && !deviceMatchesBuildPlatform(project.selectedDevice, platform)) {
      project.selectedDevice = undefined;
      await this.#context.workspaceState.update(projectStateKey(project, "device"), undefined);
    }
    await this.#context.workspaceState.update(projectStateKey(project, "platform"), platform);
    this.#changed.fire();
  }

  public async setProfile(project: WorkspaceProject, profile: BuildProfile): Promise<void> {
    project.selectedProfile = profile;
    await this.#context.workspaceState.update(projectStateKey(project, "profile"), profile);
    this.#changed.fire();
  }

  public async setDevice(project: WorkspaceProject, device: ProtocolDevice | undefined): Promise<void> {
    project.selectedDevice = device;
    await this.#context.workspaceState.update(projectStateKey(project, "device"), device?.id);
    this.#changed.fire();
  }

  public restoreSelectedDevice(project: WorkspaceProject): void {
    const id = this.#context.workspaceState.get<string>(projectStateKey(project, "device"));
    project.selectedDevice = project.devices.find(
      (device) => device.id === id && deviceMatchesBuildPlatform(device, project.selectedPlatform)
    );
  }

  public async rememberArtifact(project: WorkspaceProject, artifact: ProtocolArtifact): Promise<void> {
    if (!artifactPathWithinGeneratedRoot(project, artifact.path)) {
      throw new ProtocolError(
        "cargo-ferry reported an artifact outside this project's local target/ferry boundary.",
        "protocol.artifact_outside_target"
      );
    }
    const withoutOld = project.artifacts.filter((candidate) => candidate.path !== artifact.path);
    project.artifacts = [artifact, ...withoutOld].slice(0, 50);
    await this.#context.workspaceState.update(projectStateKey(project, "artifacts"), project.artifacts);
    this.#changed.fire();
  }

  public async forgetArtifact(project: WorkspaceProject, artifact: ProtocolArtifact): Promise<void> {
    project.artifacts = project.artifacts.filter((candidate) => candidate.path !== artifact.path);
    await this.#context.workspaceState.update(projectStateKey(project, "artifacts"), project.artifacts);
    this.#changed.fire();
  }

  public refreshViews(): void {
    this.#changed.fire();
  }

  public dispose(): void {
    this.#changed.dispose();
  }

  async #updateContexts(): Promise<void> {
    await Promise.all([
      vscode.commands.executeCommand("setContext", "rustferry.hasProjects", this.#projects.length > 0),
      vscode.commands.executeCommand(
        "setContext",
        "rustferry.executionAvailable",
        this.#selected?.executionAvailable === true
      )
    ]);
  }
}

export async function findProjectManifests(): Promise<readonly vscode.Uri[]> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  const discovered = new Map<string, vscode.Uri>();
  for (const folder of folders) {
    const pattern = new vscode.RelativePattern(folder, `**/${PROJECT_MANIFEST}`);
    const manifests = await vscode.workspace.findFiles(
      pattern,
      "**/{target,node_modules,.git}/**",
      100
    );
    for (const manifest of manifests) {
      discovered.set(manifest.toString(), manifest);
    }
  }
  for (const document of vscode.workspace.textDocuments) {
    if (document.uri.path.endsWith(`/${PROJECT_MANIFEST}`)) {
      discovered.set(document.uri.toString(), document.uri);
    }
  }
  return [...discovered.values()];
}
