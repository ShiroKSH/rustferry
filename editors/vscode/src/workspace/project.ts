import * as vscode from "vscode";

import type {
  BuildPlatform,
  BuildProfile,
  Handshake,
  ProtocolArtifact,
  ProtocolDevice,
  ProtocolProject
} from "../cli/protocol.js";

export type DoctorState = "unknown" | "running" | "passed" | "failed";

export class WorkspaceProject {
  public metadata: ProtocolProject | undefined;
  public handshake: Handshake | undefined;
  public selectedPlatform: BuildPlatform;
  public selectedProfile: BuildProfile;
  public selectedDevice: ProtocolDevice | undefined;
  public devices: readonly ProtocolDevice[] = [];
  public artifacts: readonly ProtocolArtifact[] = [];
  public doctor: DoctorState = "unknown";
  public valid: boolean | undefined;
  public error: string | undefined;

  public constructor(
    readonly root: vscode.Uri,
    readonly manifest: vscode.Uri,
    selectedPlatform: BuildPlatform,
    selectedProfile: BuildProfile
  ) {
    this.selectedPlatform = selectedPlatform;
    this.selectedProfile = selectedProfile;
  }

  public get key(): string {
    return this.root.toString();
  }

  public get displayName(): string {
    return this.metadata?.display_name ?? vscode.workspace.asRelativePath(this.root, false);
  }

  public get executionAvailable(): boolean {
    return vscode.workspace.isTrusted && this.root.scheme === "file";
  }

  public get environmentLabel(): string {
    if (this.root.scheme !== "file") {
      return "Virtual";
    }
    switch (vscode.env.remoteName) {
      case undefined:
        return "Local";
      case "ssh-remote":
        return "Remote SSH";
      case "dev-container":
        return "Dev Container";
      case "wsl":
        return "WSL";
      case "codespaces":
        return "Codespace";
      default:
        return `Remote (${vscode.env.remoteName})`;
    }
  }
}
