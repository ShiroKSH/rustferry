import * as vscode from "vscode";

import type { BuildPlatform, BuildProfile } from "../cli/protocol.js";

const SECTION = "rustferry";

export type ExtensionSettings = Readonly<{
  cliPath?: string;
  developmentMode: boolean;
  defaultPlatform: BuildPlatform;
  defaultProfile: BuildProfile;
  developmentTeam?: string;
  validationDebounceMs: number;
  maxProtocolLineBytes: number;
}>;

export function settings(resource?: vscode.Uri): ExtensionSettings {
  const configuration = vscode.workspace.getConfiguration(SECTION, resource);
  const cliPath = configuration.get<string>("cliPath", "").trim();
  const developmentTeam = configuration.get<string>("ios.developmentTeam", "").trim();
  return {
    ...(cliPath.length > 0 ? { cliPath } : {}),
    developmentMode: configuration.get<boolean>("developmentMode", false),
    defaultPlatform: configuration.get<BuildPlatform>("defaultPlatform", "android"),
    defaultProfile: configuration.get<BuildProfile>("defaultProfile", "debug"),
    ...(developmentTeam.length > 0 ? { developmentTeam } : {}),
    validationDebounceMs: configuration.get<number>("validation.debounceMs", 350),
    maxProtocolLineBytes: configuration.get<number>("maxProtocolLineBytes", 1_048_576)
  };
}

export async function setDevelopmentTeam(value: string): Promise<void> {
  await vscode.workspace
    .getConfiguration(SECTION)
    .update("ios.developmentTeam", value, vscode.ConfigurationTarget.Global);
}

export async function setCliPath(resource: vscode.Uri | undefined, value: string): Promise<void> {
  const configuration = vscode.workspace.getConfiguration(SECTION, resource);
  const inspection = configuration.inspect<string>("cliPath");
  const target = inspection?.workspaceFolderValue === undefined
    ? vscode.ConfigurationTarget.Workspace
    : vscode.ConfigurationTarget.WorkspaceFolder;
  await configuration.update("cliPath", value, target);
}
