import type * as vscode from "vscode";

import type { CliClient } from "../cli/client.js";
import type { CliInvocation } from "../cli/discovery.js";
import type { RustFerryDiagnostics } from "../diagnostics/collection.js";
import type { ConfigValidationCoordinator } from "../diagnostics/configValidation.js";
import type { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";

export type CommandServices = Readonly<{
  context: vscode.ExtensionContext;
  projects: WorkspaceProjects;
  diagnostics: RustFerryDiagnostics;
  validation: ConfigValidationCoordinator;
  output: vscode.OutputChannel;
  logs: vscode.OutputChannel;
  jobLogs: vscode.OutputChannel;
  clientFor: (project: WorkspaceProject) => Promise<CliClient>;
  clientAt: (cwd: string, resource?: vscode.Uri) => Promise<CliClient>;
  invocationFor: (project: WorkspaceProject) => Promise<CliInvocation>;
  refreshProject: (project: WorkspaceProject) => Promise<void>;
  refreshAll: () => Promise<void>;
  refreshJobs: () => void;
  loadMoreJobLogs: (argument: unknown) => Promise<void>;
}>;
