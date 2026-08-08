import * as vscode from "vscode";

import { isRecord } from "../cli/protocol.js";
import { requireExecution, selectedProject, UserActionError } from "./navigation.js";
import type { CommandServices } from "./types.js";

export async function changeCapability(
  services: CommandServices,
  enable: boolean,
  argument?: unknown
): Promise<void> {
  const project = await selectedProject(services, argument);
  if (project === undefined) {
    return;
  }
  requireExecution(project);
  const client = await services.clientFor(project);
  const capabilities = await client.capabilities(project.root.fsPath);
  const choices = capabilities.filter((capability) => enable ? capability.enabled !== true : capability.enabled === true);
  if (choices.length === 0) {
    throw new UserActionError(enable ? "All reported RustFerry capabilities are already enabled." : "No RustFerry capabilities are enabled.");
  }
  type CapabilityPick = vscode.QuickPickItem & { capability: (typeof choices)[number] };
  const items: CapabilityPick[] = choices.map((capability) => ({
      label: capability.name,
      ...(capability.runtime === undefined ? {} : { description: capability.runtime }),
      detail: [capability.android, capability.ios].filter(Boolean).join(" · "),
      capability
    }));
  const choice = await vscode.window.showQuickPick<CapabilityPick>(
    items,
    {
      title: enable ? "RustFerry: Add Capability" : "RustFerry: Remove Capability",
      placeHolder: "Select a CLI-reported capability",
      matchOnDescription: true,
      matchOnDetail: true
    }
  );
  if (choice === undefined) {
    return;
  }
  const preview = await client.previewCapability(project.root.fsPath, choice.capability.name, enable);
  const details = previewDetails(preview, choice.capability.android, choice.capability.ios);
  services.output.appendLine(`Capability ${enable ? "add" : "remove"} preview: ${JSON.stringify(preview, null, 2)}`);
  const action = enable ? "Add Capability" : "Remove Capability";
  const confirmation = await vscode.window.showInformationMessage(
    `${enable ? "Add" : "Remove"} ${choice.capability.name}?`,
    { modal: true, detail: details },
    action
  );
  if (confirmation !== action) {
    return;
  }
  await client.mutateCapability(project.root.fsPath, choice.capability.name, enable);
  await services.refreshProject(project);
  await services.validation.validate(project);
  await vscode.window.showInformationMessage(
    `${choice.capability.name} ${enable ? "enabled" : "disabled"} for ${project.displayName}.`
  );
}

function previewDetails(value: unknown, android?: string, ios?: string): string {
  if (!isRecord(value)) {
    return [android, ios].filter(Boolean).join("\n");
  }
  const files = Array.isArray(value.files) ? value.files.filter((file): file is string => typeof file === "string") : [];
  const notes = Array.isArray(value.platform_notes)
    ? value.platform_notes.filter((note): note is string => typeof note === "string")
    : [];
  return [
    files.length === 0 ? "No file changes reported." : `Files:\n${files.map((file) => `• ${file}`).join("\n")}`,
    ...notes,
    android,
    ios
  ].filter((line): line is string => typeof line === "string" && line.length > 0).join("\n\n");
}
