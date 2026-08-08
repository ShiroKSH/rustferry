import * as vscode from "vscode";

import type { BuildPlatform, BuildProfile } from "../cli/protocol.js";
import { DOCUMENTATION_URL } from "../constants.js";
import { setCliPath } from "../config/settings.js";
import type { WorkspaceProject } from "../workspace/project.js";
import type { CommandServices } from "./types.js";

export async function selectedProject(
  services: CommandServices,
  argument?: unknown,
  prompt = "Select a RustFerry project"
): Promise<WorkspaceProject | undefined> {
  const fromArgument = projectFromArgument(argument);
  if (fromArgument !== undefined) {
    await services.projects.select(fromArgument);
    return fromArgument;
  }
  return await services.projects.pick(prompt);
}

export function requireExecution(project: WorkspaceProject): void {
  if (!vscode.workspace.isTrusted) {
    throw new UserActionError("Trust this workspace before running RustFerry commands.", "trust");
  }
  if (project.root.scheme !== "file") {
    throw new UserActionError("RustFerry commands require a file-backed workspace. This virtual workspace is read-only.");
  }
}

export async function selectTarget(services: CommandServices, argument?: unknown): Promise<void> {
  const project = await selectedProject(services, argument);
  if (project === undefined) {
    return;
  }
  const platforms = availablePlatforms(project);
  if (platforms.length === 0) {
    throw new UserActionError(
      "This project has no build target supported by both ferry.toml and the installed cargo-ferry. Run RustFerry Doctor or update the project platforms."
    );
  }
  const target = await vscode.window.showQuickPick(
    platforms.map((platform) => ({
      label: platformLabel(platform),
      description: platform,
      platform,
      picked: platform === project.selectedPlatform
    })),
    { placeHolder: "Select a RustFerry build target" }
  );
  if (target === undefined) {
    return;
  }
  const profile = await vscode.window.showQuickPick(
    (["debug", "release"] as const).map((value) => ({
      label: value === "debug" ? "Debug" : "Release",
      description: value === "debug" ? "Fast local iteration" : "Optimized artifact",
      value,
      picked: value === project.selectedProfile
    })),
    { placeHolder: "Select a build profile" }
  );
  if (profile === undefined) {
    return;
  }
  await services.projects.setPlatform(project, target.platform);
  await services.projects.setProfile(project, profile.value);
}

export async function openConfig(services: CommandServices, argument?: unknown): Promise<void> {
  const project = await selectedProject(services, argument);
  if (project === undefined) {
    return;
  }
  const document = await vscode.workspace.openTextDocument(project.manifest);
  await vscode.window.showTextDocument(document);
}

export async function openApp(services: CommandServices, argument?: unknown): Promise<void> {
  const project = await selectedProject(services, argument);
  if (project === undefined) {
    return;
  }
  const candidates = ["src/app.rs", "src/main.rs", "src/lib.rs"];
  for (const relative of candidates) {
    const uri = vscode.Uri.joinPath(project.root, relative);
    try {
      await vscode.workspace.fs.stat(uri);
      const document = await vscode.workspace.openTextDocument(uri);
      await vscode.window.showTextDocument(document);
      return;
    } catch {
      // Try the next documented Rust entry point.
    }
  }
  throw new UserActionError("Could not find src/app.rs, src/main.rs, or src/lib.rs in the selected project.");
}

export async function openDocumentation(): Promise<void> {
  await vscode.env.openExternal(vscode.Uri.parse(DOCUMENTATION_URL));
}

export async function manageTrust(): Promise<void> {
  await vscode.commands.executeCommand("workbench.trust.manage");
}

export async function selectCli(services: CommandServices): Promise<void> {
  const selected = await vscode.window.showOpenDialog({
    canSelectFiles: true,
    canSelectFolders: false,
    canSelectMany: false,
    openLabel: "Select cargo-ferry",
    title: "Select cargo-ferry or cargo executable"
  });
  const uri = selected?.[0];
  if (uri === undefined) {
    return;
  }
  if (uri.scheme !== "file") {
    throw new UserActionError("The cargo-ferry executable must use a local file path.");
  }
  await setCliPath(services.projects.selected?.root, uri.fsPath);
  await services.refreshAll();
}

export class UserActionError extends Error {
  public constructor(message: string, readonly action?: "trust") {
    super(message);
    this.name = "UserActionError";
  }
}

function projectFromArgument(argument: unknown): WorkspaceProject | undefined {
  if (isProject(argument)) {
    return argument;
  }
  if (typeof argument === "object" && argument !== null && "project" in argument && isProject(argument.project)) {
    return argument.project;
  }
  return undefined;
}

function isProject(value: unknown): value is WorkspaceProject {
  return typeof value === "object"
    && value !== null
    && "root" in value
    && value.root instanceof vscode.Uri
    && "manifest" in value;
}

function availablePlatforms(project: WorkspaceProject): readonly BuildPlatform[] {
  const declared = new Set(project.metadata?.platforms ?? ["android", "ios"]);
  const values: BuildPlatform[] = [];
  if (declared.has("android") && project.handshake?.features.android_build !== false) {
    values.push("android");
  }
  if (declared.has("ios") && project.handshake?.features.ios_simulator_build !== false) {
    values.push("ios-simulator");
  }
  if (declared.has("ios") && project.handshake?.features.physical_ios === true) {
    values.push("ios-device");
  }
  return values;
}

export function buildTitle(platform: BuildPlatform, profile: BuildProfile): string {
  return `Build ${platformLabel(platform)} (${profile})`;
}

export function platformLabel(platform: BuildPlatform): string {
  switch (platform) {
    case "android":
      return "Android";
    case "ios-simulator":
      return "iOS Simulator";
    case "ios-device":
      return "Physical iPhone";
  }
}
