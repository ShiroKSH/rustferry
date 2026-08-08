import * as vscode from "vscode";

import { commands } from "../constants.js";
import type { ProtocolDevice } from "../cli/protocol.js";
import { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";

type DeviceElement = DeviceProjectItem | DeviceItem | MessageItem;

export class DevicesTreeProvider implements vscode.TreeDataProvider<DeviceElement>, vscode.Disposable {
  readonly #changed = new vscode.EventEmitter<DeviceElement | undefined>();
  readonly #subscription: vscode.Disposable;
  public readonly onDidChangeTreeData = this.#changed.event;

  public constructor(readonly projects: WorkspaceProjects) {
    this.#subscription = projects.onDidChange(() => this.#changed.fire(undefined));
  }

  public getTreeItem(element: DeviceElement): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: DeviceElement): DeviceElement[] {
    if (element === undefined) {
      return this.projects.all.map((project) => new DeviceProjectItem(project));
    }
    if (!(element instanceof DeviceProjectItem)) {
      return [];
    }
    const project = element.project;
    if (!vscode.workspace.isTrusted) {
      return [new MessageItem("Trust the workspace to discover devices", "lock")];
    }
    if (project.root.scheme !== "file") {
      return [new MessageItem("Devices are unavailable in a virtual workspace", "remote")];
    }
    if (project.handshake?.features.devices !== true) {
      return [new MessageItem("Installed cargo-ferry does not support device discovery", "info")];
    }
    if (project.devices.length === 0) {
      return [new MessageItem("Refresh to discover connected devices", "refresh", commands.refreshDevices)];
    }
    return project.devices.map((device) => new DeviceItem(project, device, project.selectedDevice?.id === device.id));
  }

  public dispose(): void {
    this.#subscription.dispose();
    this.#changed.dispose();
  }
}

class DeviceProjectItem extends vscode.TreeItem {
  public constructor(readonly project: WorkspaceProject) {
    super(project.displayName, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = new vscode.ThemeIcon("package");
  }
}

export class DeviceItem extends vscode.TreeItem {
  public override readonly contextValue = "rustferry.device";

  public constructor(
    readonly project: WorkspaceProject,
    readonly device: ProtocolDevice,
    selected: boolean
  ) {
    super(device.name, vscode.TreeItemCollapsibleState.None);
    this.description = [device.state, device.os_version, selected ? "selected" : undefined].filter(Boolean).join(" · ");
    this.tooltip = [
      `ID: ${device.id}`,
      `Platform: ${device.platform}`,
      `Kind: ${device.kind}`,
      `State: ${device.state}`,
      device.architecture === undefined ? undefined : `Architecture: ${device.architecture}`,
      device.transport === undefined ? undefined : `Transport: ${device.transport}`
    ].filter(Boolean).join("\n");
    this.iconPath = new vscode.ThemeIcon(deviceIcon(device), stateColor(device.state));
    this.command = {
      command: commands.selectDevice,
      title: "Select Device",
      arguments: [this]
    };
  }
}

class MessageItem extends vscode.TreeItem {
  public constructor(label: string, icon: string, command?: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon(icon);
    if (command !== undefined) {
      this.command = { command, title: label };
    }
  }
}

function deviceIcon(device: ProtocolDevice): string {
  if (device.kind.includes("emulator") || device.kind.includes("simulator")) {
    return "vm";
  }
  return "device-mobile";
}

function stateColor(state: string): vscode.ThemeColor | undefined {
  if (state === "online" || state === "booted") {
    return new vscode.ThemeColor("testing.iconPassed");
  }
  if (state === "unauthorized" || state === "offline") {
    return new vscode.ThemeColor("testing.iconFailed");
  }
  return undefined;
}
