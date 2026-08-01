import * as vscode from "vscode";

import { commands } from "../constants.js";
import type { ProtocolArtifact } from "../cli/protocol.js";
import { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";

type ArtifactElement = ArtifactProjectItem | ArtifactItem | MessageItem;

export class ArtifactsTreeProvider implements vscode.TreeDataProvider<ArtifactElement>, vscode.Disposable {
  readonly #changed = new vscode.EventEmitter<ArtifactElement | undefined>();
  readonly #subscription: vscode.Disposable;
  public readonly onDidChangeTreeData = this.#changed.event;

  public constructor(readonly projects: WorkspaceProjects) {
    this.#subscription = projects.onDidChange(() => this.#changed.fire(undefined));
  }

  public getTreeItem(element: ArtifactElement): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: ArtifactElement): ArtifactElement[] {
    if (element === undefined) {
      return this.projects.all.map((project) => new ArtifactProjectItem(project));
    }
    if (!(element instanceof ArtifactProjectItem)) {
      return [];
    }
    if (element.project.artifacts.length === 0) {
      return [new MessageItem("Build an application to produce an artifact")];
    }
    return element.project.artifacts.map((artifact) => new ArtifactItem(element.project, artifact));
  }

  public dispose(): void {
    this.#subscription.dispose();
    this.#changed.dispose();
  }
}

class ArtifactProjectItem extends vscode.TreeItem {
  public constructor(readonly project: WorkspaceProject) {
    super(project.displayName, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = new vscode.ThemeIcon("package");
  }
}

export class ArtifactItem extends vscode.TreeItem {
  public override readonly contextValue = "rustferry.artifact";

  public constructor(readonly project: WorkspaceProject, readonly artifact: ProtocolArtifact) {
    super(artifactLabel(artifact), vscode.TreeItemCollapsibleState.None);
    this.description = [artifact.platform, artifact.profile, formatSize(artifact.size_bytes)].filter(Boolean).join(" · ");
    this.tooltip = [
      artifact.path,
      `Package: ${artifact.package_identifier}`,
      `Architectures: ${artifact.architectures.join(", ") || "unknown"}`,
      `Validation: ${validationLabel(artifact.validation)}`
    ].join("\n");
    this.resourceUri = vscode.Uri.file(artifact.path);
    this.iconPath = new vscode.ThemeIcon(artifactIcon(artifact.kind));
    this.command = {
      command: commands.revealArtifact,
      title: "Reveal Artifact",
      arguments: [this]
    };
  }
}

class MessageItem extends vscode.TreeItem {
  public constructor(label: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon("info");
  }
}

function artifactLabel(artifact: ProtocolArtifact): string {
  const name = artifact.path.replaceAll("\\", "/").split("/").at(-1);
  return name === undefined || name.length === 0 ? artifact.kind.toUpperCase() : name;
}

function artifactIcon(kind: string): string {
  if (kind === "apk") {
    return "file-zip";
  }
  if (kind === "app") {
    return "device-mobile";
  }
  return "package";
}

function validationLabel(validation: Readonly<Record<string, unknown>>): string {
  const entries = Object.entries(validation);
  return entries.length === 0 ? "not reported" : entries.map(([key, value]) => `${key}=${String(value)}`).join(", ");
}

function formatSize(size: number | undefined): string | undefined {
  if (size === undefined) {
    return undefined;
  }
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KiB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
}
