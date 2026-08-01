import * as vscode from "vscode";

import { commands } from "../constants.js";
import { platformLabel } from "../commands/navigation.js";
import type { WorkspaceProjects } from "../workspace/discovery.js";

export class RustFerryStatusBar implements vscode.Disposable {
  readonly #item: vscode.StatusBarItem;
  readonly #subscription: vscode.Disposable;

  public constructor(projects: WorkspaceProjects) {
    this.#item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
    this.#item.name = "RustFerry Target";
    this.#item.command = commands.selectTarget;
    this.#subscription = projects.onDidChange(() => this.update(projects));
    this.update(projects);
  }

  public update(projects: WorkspaceProjects): void {
    const project = projects.selected;
    if (project === undefined) {
      this.#item.hide();
      return;
    }
    const target = platformLabel(project.selectedPlatform);
    const device = project.selectedDevice?.name;
    if (project.error !== undefined || project.doctor === "failed") {
      this.#item.text = "$(error) RustFerry: setup required";
    } else {
      this.#item.text = `$(device-mobile) RustFerry: ${target}${device === undefined ? "" : ` · ${device}`}`;
    }
    this.#item.tooltip = `${project.displayName}\n${project.selectedProfile}\n${project.environmentLabel}`;
    this.#item.show();
  }

  public dispose(): void {
    this.#subscription.dispose();
    this.#item.dispose();
  }
}
