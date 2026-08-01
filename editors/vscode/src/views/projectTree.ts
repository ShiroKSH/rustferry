import * as vscode from "vscode";

import { commands } from "../constants.js";
import { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";

type ProjectElement = ProjectItem | SectionItem | DetailItem | CapabilityItem;

export class ProjectTreeProvider implements vscode.TreeDataProvider<ProjectElement>, vscode.Disposable {
  readonly #changed = new vscode.EventEmitter<ProjectElement | undefined>();
  readonly #subscription: vscode.Disposable;
  public readonly onDidChangeTreeData = this.#changed.event;

  public constructor(readonly projects: WorkspaceProjects) {
    this.#subscription = projects.onDidChange(() => this.#changed.fire(undefined));
  }

  public getTreeItem(element: ProjectElement): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: ProjectElement): ProjectElement[] {
    if (element === undefined) {
      return this.projects.all.map((project) => new ProjectItem(project, project === this.projects.selected));
    }
    if (element instanceof ProjectItem) {
      return projectChildren(element.project);
    }
    if (element instanceof SectionItem && element.kind === "capabilities") {
      return (element.project.metadata?.capabilities ?? []).map((name) => new CapabilityItem(element.project, name));
    }
    if (element instanceof SectionItem && element.kind === "platforms") {
      return (element.project.metadata?.platforms ?? []).map((platform) => new DetailItem(platform, undefined, "device-mobile"));
    }
    return [];
  }

  public dispose(): void {
    this.#subscription.dispose();
    this.#changed.dispose();
  }
}

export class ProjectItem extends vscode.TreeItem {
  public override readonly contextValue = "rustferry.project";

  public constructor(readonly project: WorkspaceProject, selected: boolean) {
    super(project.displayName, vscode.TreeItemCollapsibleState.Expanded);
    if (selected) {
      this.description = "selected";
    }
    this.tooltip = `${project.root.fsPath}\n${project.environmentLabel}`;
    this.iconPath = new vscode.ThemeIcon(project.error === undefined ? "package" : "error");
    this.command = {
      command: commands.selectProject,
      title: "Select Project",
      arguments: [project]
    };
  }
}

class SectionItem extends vscode.TreeItem {
  public override readonly contextValue: string;

  public constructor(
    readonly project: WorkspaceProject,
    readonly kind: "capabilities" | "platforms",
    label: string,
    description?: string
  ) {
    super(label, vscode.TreeItemCollapsibleState.Expanded);
    if (description !== undefined) {
      this.description = description;
    }
    this.contextValue = `rustferry.${kind}`;
    this.iconPath = new vscode.ThemeIcon(kind === "capabilities" ? "extensions" : "device-mobile");
  }
}

class DetailItem extends vscode.TreeItem {
  public constructor(label: string, description?: string, icon = "symbol-field") {
    super(label, vscode.TreeItemCollapsibleState.None);
    if (description !== undefined) {
      this.description = description;
    }
    this.iconPath = new vscode.ThemeIcon(icon);
  }
}

class CapabilityItem extends vscode.TreeItem {
  public override readonly contextValue = "rustferry.capability";

  public constructor(readonly project: WorkspaceProject, readonly capability: string) {
    super(capability, vscode.TreeItemCollapsibleState.None);
    this.description = "enabled";
    this.iconPath = new vscode.ThemeIcon("pass-filled");
    this.tooltip = `${capability} is enabled in validated project metadata.`;
  }
}

function projectChildren(project: WorkspaceProject): ProjectElement[] {
  if (!vscode.workspace.isTrusted) {
    return [
      new DetailItem("Workspace is not trusted", "commands disabled", "lock"),
      new DetailItem(project.manifest.path.split("/").at(-1) ?? "ferry.toml", "read-only manifest", "file-code")
    ];
  }
  if (project.root.scheme !== "file") {
    return [new DetailItem("Virtual workspace", "project browsing only", "remote")];
  }
  if (project.error !== undefined) {
    return [new DetailItem(project.error, "Refresh after fixing", "error")];
  }
  const metadata = project.metadata;
  if (metadata === undefined) {
    return [new DetailItem("Loading project metadata…", undefined, "loading~spin")];
  }
  const doctorIcon = project.doctor === "passed" ? "pass-filled" : project.doctor === "failed" ? "error" : "question";
  const validationIcon = project.valid === false ? "error" : project.valid === true ? "pass-filled" : "question";
  return [
    new DetailItem("Crate", metadata.crate_name, "symbol-package"),
    new DetailItem("Identifier", metadata.identifier, "key"),
    new DetailItem("Version", metadata.version, "versions"),
    new DetailItem("Target", `${project.selectedPlatform} · ${project.selectedProfile}`, "device-mobile"),
    new DetailItem("Configuration", project.valid === false ? "invalid" : project.valid === true ? "valid" : "not checked", validationIcon),
    new DetailItem("Doctor", project.doctor, doctorIcon),
    new DetailItem("Environment", project.environmentLabel, "remote"),
    new SectionItem(project, "platforms", "Platforms", String(metadata.platforms.length)),
    new SectionItem(project, "capabilities", "Capabilities", String(metadata.capabilities.length))
  ];
}
