import * as vscode from "vscode";

import { CliCommandError } from "../cli/client.js";
import { CliDiscoveryError } from "../cli/discovery.js";
import { ProcessCancelledError, ProcessExecutionError } from "../cli/process.js";
import { ProtocolError } from "../cli/protocol.js";
import { commands, INSTALLATION_URL, IOS_SIGNING_URL } from "../constants.js";
import { deleteArtifact, inspectArtifact, copyArtifactPath, revealArtifact } from "./artifacts.js";
import { changeCapability } from "./capabilities.js";
import {
  manageTrust,
  openApp,
  openConfig,
  openDocumentation,
  selectCli,
  selectedProject,
  selectTarget,
  UserActionError
} from "./navigation.js";
import { createNewProject } from "./newProject.js";
import { OperationCommands } from "./operations.js";
import type { CommandServices } from "./types.js";

export function registerCommands(services: CommandServices): readonly vscode.Disposable[] {
  const operations = new OperationCommands(services);
  const subscriptions: vscode.Disposable[] = [operations];
  const register = (command: string, handler: (...args: readonly unknown[]) => unknown): void => {
    subscriptions.push(vscode.commands.registerCommand(command, async (...args: readonly unknown[]) => {
      try {
        await handler(...args);
      } catch (error) {
        await showFailure(services, error);
      }
    }));
  };

  register(commands.createProject, async () => await createNewProject(services));
  register(commands.refresh, async () => await services.refreshAll());
  register(commands.selectProject, async (argument) => {
    await selectedProject(services, argument);
  });
  register(commands.selectTarget, async (argument) => await selectTarget(services, argument));
  register(commands.check, async (argument) => await operations.check(argument));
  register(commands.doctor, async (argument) => await operations.doctor(argument));
  register(commands.buildAndroid, async (argument) => await operations.build(argument, "android"));
  register(commands.buildIosSimulator, async (argument) => await operations.build(argument, "ios-simulator"));
  register(commands.buildPhysicalIos, async (argument) => await operations.build(argument, "ios-device"));
  register(commands.buildSelected, async (argument) => await operations.build(argument));
  register(commands.clean, async (argument) => await operations.clean(argument));
  register(commands.addCapability, async (argument) => await changeCapability(services, true, argument));
  register(commands.removeCapability, async (argument) => await changeCapability(services, false, argument));
  register(commands.openConfig, async (argument) => await openConfig(services, argument));
  register(commands.openApp, async (argument) => await openApp(services, argument));
  register(commands.openDocumentation, openDocumentation);
  register(commands.refreshDevices, async (argument) => await operations.refreshDevices(argument));
  register(commands.selectDevice, async (argument) => await operations.selectDevice(argument));
  register(commands.selectDevelopmentTeam, async (argument) => await operations.selectDevelopmentTeam(argument));
  register(commands.runIosDoctor, async (argument) => await operations.doctor(argument));
  register(commands.openIosSigningGuide, async () => {
    await vscode.env.openExternal(vscode.Uri.parse(IOS_SIGNING_URL));
  });
  register(commands.install, async (argument) => await operations.install(argument));
  register(commands.run, async (argument) => await operations.run(argument));
  register(commands.logs, (argument) => operations.logs(argument));
  register(commands.stopLogs, () => operations.stopLogs());
  register(commands.revealArtifact, revealArtifact);
  register(commands.copyArtifactPath, copyArtifactPath);
  register(commands.inspectArtifact, inspectArtifact);
  register(commands.deleteArtifact, async (argument) => await deleteArtifact(services, argument));
  register(commands.applyValidatedFix, async (token) => await services.diagnostics.applyValidatedFix(token));
  register(commands.trustWorkspace, manageTrust);
  register(commands.selectCli, async () => await selectCli(services));
  return subscriptions;
}

export async function showFailure(services: CommandServices, error: unknown): Promise<void> {
  if (error instanceof ProcessCancelledError) {
    await vscode.window.showInformationMessage("RustFerry operation cancelled.");
    return;
  }
  services.output.appendLine(`Failure: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
  if (error instanceof UserActionError) {
    const selection = await vscode.window.showWarningMessage(
      error.message,
      ...(error.action === "trust" ? ["Manage Workspace Trust"] : [])
    );
    if (selection === "Manage Workspace Trust") {
      await manageTrust();
    }
    return;
  }
  if (error instanceof CliDiscoveryError) {
    const selection = await vscode.window.showErrorMessage(
      error.message,
      "Open Installation Guide",
      "Select Executable",
      "Retry"
    );
    if (selection === "Open Installation Guide") {
      await vscode.env.openExternal(vscode.Uri.parse(INSTALLATION_URL));
    } else if (selection === "Select Executable") {
      await selectCli(services);
    } else if (selection === "Retry") {
      await services.refreshAll();
    }
    return;
  }
  if (error instanceof ProtocolError && error.code === "protocol.incompatible") {
    const selection = await vscode.window.showErrorMessage(error.message, "Open Installation Guide", "Retry");
    if (selection === "Open Installation Guide") {
      await vscode.env.openExternal(vscode.Uri.parse(INSTALLATION_URL));
    } else if (selection === "Retry") {
      await services.refreshAll();
    }
    return;
  }
  if (error instanceof CliCommandError) {
    const message = error.help === undefined ? error.message : `${error.message} ${error.help}`;
    const selection = await vscode.window.showErrorMessage(message, "Show RustFerry Output");
    if (selection === "Show RustFerry Output") {
      services.output.show(true);
    }
    return;
  }
  const message = error instanceof ProcessExecutionError || error instanceof Error
    ? error.message
    : String(error);
  const selection = await vscode.window.showErrorMessage(message, "Show RustFerry Output");
  if (selection === "Show RustFerry Output") {
    services.output.show(true);
  }
}
