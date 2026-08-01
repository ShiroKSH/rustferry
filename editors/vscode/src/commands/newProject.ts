import * as path from "node:path";

import * as vscode from "vscode";

import { EXTENSION_ID } from "../constants.js";
import { UserActionError } from "./navigation.js";
import {
  deriveDefaultIdentifier,
  validateIdentifier,
  validateProjectName
} from "./newProjectValidation.js";
import type { CommandServices } from "./types.js";

type OpenMode = "current" | "new" | "workspace";

export async function createNewProject(services: CommandServices): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    throw new UserActionError("Trust this workspace before creating a RustFerry project.", "trust");
  }
  const parentSelection = await vscode.window.showOpenDialog({
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
    openLabel: "Select Parent Directory",
    title: "RustFerry: Create New Project"
  });
  const parentUri = parentSelection?.[0];
  if (parentUri === undefined) {
    return;
  }
  if (parentUri.scheme !== "file") {
    throw new UserActionError("RustFerry project generation requires a local file-system directory.");
  }
  const client = await services.clientAt(parentUri.fsPath, parentUri);
  const handshake = await client.handshake(parentUri.fsPath);
  if (client.invocation.developmentRoot === undefined && !handshake.runtime_dependency.usable) {
    throw new UserActionError(
      "This cargo-ferry build cannot resolve its registry runtime yet. Use a published cargo-ferry release, or enable RustFerry development mode for this source checkout."
    );
  }

  const name = await vscode.window.showInputBox({
    title: "RustFerry: Create New Project",
    prompt: "Project directory and Rust crate name",
    placeHolder: "weather",
    validateInput: validateProjectName,
    ignoreFocusOut: true
  });
  if (name === undefined) {
    return;
  }
  const displayName = await vscode.window.showInputBox({
    title: "RustFerry: Display Name",
    prompt: "Name shown on the device home screen",
    value: titleCase(name),
    validateInput: (value) => value.trim().length === 0 ? "Display name cannot be empty." : undefined,
    ignoreFocusOut: true
  });
  if (displayName === undefined) {
    return;
  }
  const identifier = await vscode.window.showInputBox({
    title: "RustFerry: Application Identifier",
    prompt: "Reverse-DNS Android application ID and Apple bundle identifier",
    value: deriveDefaultIdentifier(name),
    validateInput: validateIdentifier,
    ignoreFocusOut: true
  });
  if (identifier === undefined) {
    return;
  }

  const templates = handshake.templates.map((entry) => ({
    name: entry.id,
    purpose: entry.description
  }));
  if (templates.length === 0) {
    throw new UserActionError("cargo-ferry did not report any project templates.");
  }
  type TemplatePick = vscode.QuickPickItem & { value: (typeof templates)[number] };
  const templateItems: TemplatePick[] = templates.map((value) => ({
    label: value.name,
    description: value.purpose,
    value
  }));
  const template = await vscode.window.showQuickPick<TemplatePick>(
    templateItems,
    { title: "RustFerry: Template", placeHolder: "Select a CLI-provided template", matchOnDescription: true }
  );
  if (template === undefined) {
    return;
  }
  const platform = await vscode.window.showQuickPick(
    [
      { label: "Android + iOS", description: "both", value: "both" as const },
      { label: "Android", description: "android", value: "android" as const },
      { label: "iOS", description: "ios", value: "ios" as const }
    ],
    { title: "RustFerry: Platforms", placeHolder: "Choose generated platform configuration" }
  );
  if (platform === undefined) {
    return;
  }
  const capabilities = await client.capabilities(parentUri.fsPath);
  type CapabilityPick = vscode.QuickPickItem & { capability: (typeof capabilities)[number] };
  const capabilityItems: CapabilityPick[] = capabilities.map((capability) => ({
      label: capability.name,
      ...(capability.runtime === undefined ? {} : { description: capability.runtime }),
      detail: [capability.android, capability.ios].filter(Boolean).join(" · "),
      capability
    }));
  const selectedCapabilities = await vscode.window.showQuickPick<CapabilityPick>(
    capabilityItems,
    {
      title: "RustFerry: Optional Capabilities",
      placeHolder: "Select capabilities to add after generation, or continue with none",
      canPickMany: true,
      matchOnDescription: true,
      matchOnDetail: true
    }
  );
  if (selectedCapabilities === undefined) {
    return;
  }
  const git = await vscode.window.showQuickPick(
    [
      { label: "Initialize Git", description: "recommended", value: true },
      { label: "Do not initialize Git", value: false }
    ],
    { title: "RustFerry: Version Control" }
  );
  if (git === undefined) {
    return;
  }
  const open = await vscode.window.showQuickPick(
    [
      { label: "Open in Current Window", value: "current" as const },
      { label: "Open in New Window", value: "new" as const },
      { label: "Add to Workspace", value: "workspace" as const }
    ],
    { title: "RustFerry: Open Project" }
  );
  if (open === undefined) {
    return;
  }

  const destination = path.join(parentUri.fsPath, name);
  await ensureDestinationAvailable(vscode.Uri.file(destination));
  const summary = [
    `Project: ${name}`,
    `Display name: ${displayName.trim()}`,
    `Identifier: ${identifier}`,
    `Template: ${template.value.name}`,
    `Platforms: ${platform.label}`,
    `Capabilities: ${selectedCapabilities.length === 0 ? "none" : selectedCapabilities.map((entry) => entry.capability.name).join(", ")}`,
    `Git: ${git.value ? "initialize" : "skip"}`
  ].join("\n");
  const confirmation = await vscode.window.showInformationMessage(
    summary,
    { modal: true, detail: `Destination: ${destination}\n\nNo build will start automatically.` },
    "Create Project"
  );
  if (confirmation !== "Create Project") {
    return;
  }

  const controller = new AbortController();
  const result = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Creating ${displayName.trim()}`,
      cancellable: true
    },
    async (_progress, token) => {
      const cancellation = token.onCancellationRequested(() => controller.abort());
      try {
        const generated = await client.newProject({
          parent: parentUri.fsPath,
          name,
          displayName: displayName.trim(),
          identifier,
          template: template.value.name,
          platform: platform.value,
          initializeGit: git.value,
          skipCheck: false,
          ...(client.invocation.developmentRoot === undefined
            ? {}
            : { runtimePath: path.join(client.invocation.developmentRoot, "crates", "rustferry") })
        }, controller.signal);
        const projectPath = typeof generated.project === "string" ? generated.project : destination;
        for (const [index, capability] of selectedCapabilities.entries()) {
          try {
            await client.mutateCapability(projectPath, capability.capability.name, true, controller.signal);
          } catch (error) {
            return {
              projectPath,
              incompleteCapabilities: selectedCapabilities
                .slice(index)
                .map((entry) => entry.capability.name),
              error
            };
          }
        }
        return { projectPath, incompleteCapabilities: [] as string[] };
      } finally {
        cancellation.dispose();
      }
    }
  );

  if ("error" in result) {
    const reason = result.error instanceof Error ? result.error.message : String(result.error);
    services.output.appendLine(`Project created at ${result.projectPath}; capability setup incomplete: ${reason}`);
    await vscode.window.showWarningMessage(
      `Created ${displayName.trim()}, but capability setup is incomplete.`,
      {
        modal: true,
        detail: `Project: ${result.projectPath}\nRemaining capabilities: ${result.incompleteCapabilities.join(", ")}\n\n${reason}\n\nThe project will now open so setup can be completed.`
      },
      "Open Project"
    );
  } else {
    await vscode.window.showInformationMessage(`Created RustFerry project ${displayName.trim()}.`);
  }
  if (open.value !== "workspace") {
    await services.context.globalState.update("rustferry.openWalkthroughAfterProjectCreation", true);
  }
  await openProject(result.projectPath, open.value);
  if (open.value === "workspace") {
    await services.refreshAll();
    const app = vscode.Uri.joinPath(vscode.Uri.file(result.projectPath), "src", "app.rs");
    try {
      const document = await vscode.workspace.openTextDocument(app);
      await vscode.window.showTextDocument(document);
    } catch {
      // Some minimal templates use a different Rust entry point; discovery still succeeds.
    }
    await vscode.commands.executeCommand("workbench.action.openWalkthrough", `${EXTENSION_ID}#rustferry.gettingStarted`, false);
  }
}

function titleCase(value: string): string {
  return value.split(/[-_]+/u).filter(Boolean).map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`).join(" ");
}

async function ensureDestinationAvailable(destination: vscode.Uri): Promise<void> {
  try {
    await vscode.workspace.fs.stat(destination);
    throw new UserActionError(`The destination already exists: ${destination.fsPath}`);
  } catch (error) {
    if (error instanceof UserActionError) {
      throw error;
    }
    if (!(error instanceof vscode.FileSystemError) || error.code !== "FileNotFound") {
      throw error;
    }
  }
}

async function openProject(projectPath: string, mode: OpenMode): Promise<void> {
  const uri = vscode.Uri.file(projectPath);
  if (mode === "workspace") {
    const folders = vscode.workspace.workspaceFolders ?? [];
    const added = vscode.workspace.updateWorkspaceFolders(folders.length, 0, { uri });
    if (!added) {
      throw new UserActionError("VS Code could not add the generated project to this workspace.");
    }
    return;
  }
  await vscode.commands.executeCommand("vscode.openFolder", uri, { forceNewWindow: mode === "new" });
}
