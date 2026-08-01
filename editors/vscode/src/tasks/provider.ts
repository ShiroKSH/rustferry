import * as path from "node:path";

import * as vscode from "vscode";

import type { CliInvocation } from "../cli/discovery.js";
import type { BuildPlatform, BuildProfile } from "../cli/protocol.js";
import { settings } from "../config/settings.js";
import type { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";
import { commandArguments, type TaskCommandAction } from "./arguments.js";

export type RustFerryTaskAction = TaskCommandAction;

export type RustFerryTaskDefinition = vscode.TaskDefinition & Readonly<{
  type: "rustferry";
  action: RustFerryTaskAction;
  project?: string;
  platform?: BuildPlatform;
  profile?: BuildProfile;
  device?: string;
  team?: string;
}>;

export type InvocationResolver = (project: WorkspaceProject) => Promise<CliInvocation>;

export class RustFerryTaskProvider implements vscode.TaskProvider {
  public constructor(
    readonly projects: WorkspaceProjects,
    readonly invocationFor: InvocationResolver
  ) {}

  public async provideTasks(): Promise<vscode.Task[]> {
    if (!vscode.workspace.isTrusted) {
      return [];
    }
    const groups = await Promise.all(this.projects.all.filter((project) => project.executionAvailable).map(async (project) => {
      try {
        const invocation = await this.invocationFor(project);
        return tasksForProject(project, invocation);
      } catch {
        return [];
      }
    }));
    return groups.flat();
  }

  public async resolveTask(task: vscode.Task): Promise<vscode.Task | undefined> {
    const definition = task.definition as RustFerryTaskDefinition;
    const project = resolveProject(this.projects, definition.project);
    if (!project?.executionAvailable) {
      return undefined;
    }
    const invocation = await this.invocationFor(project);
    return createTask(project, invocation, definition, task.name);
  }
}

function tasksForProject(project: WorkspaceProject, invocation: CliInvocation): readonly vscode.Task[] {
  const team = settings().developmentTeam;
  const definitions: [string, RustFerryTaskDefinition][] = [
    ["Check", definition(project, "check")],
    ["Doctor", definition(project, "doctor")],
    ["Build Android", definition(project, "build", "android")],
    ["Build iOS Simulator", definition(project, "build", "ios-simulator")],
    ["Build Selected Target", definition(project, "build", project.selectedPlatform, project.selectedProfile, team)],
    ["Clean Generated", definition(project, "clean")]
  ];
  if (project.handshake?.features.physical_ios === true) {
    definitions.splice(4, 0, ["Build Physical iPhone", definition(project, "build", "ios-device", undefined, team)]);
  }
  const tasks = definitions.map(([name, value]) => createTask(project, invocation, value, name));
  const selected = tasks.find((task) => task.name === "Build Selected Target");
  if (selected !== undefined) {
    selected.group = vscode.TaskGroup.Build;
  }
  if (project.handshake?.features.install === true) {
    tasks.push(createTask(project, invocation, definition(project, "install", project.selectedPlatform, undefined, team), "Install Selected Target"));
  }
  if (project.handshake?.features.run === true) {
    tasks.push(createTask(project, invocation, definition(project, "run", project.selectedPlatform, undefined, team), "Run Selected Target"));
  }
  if (project.handshake?.features.logs === true) {
    tasks.push(createTask(project, invocation, definition(project, "logs", project.selectedPlatform), "Logs"));
  }
  return tasks;
}

function definition(
  project: WorkspaceProject,
  action: RustFerryTaskAction,
  platform?: BuildPlatform,
  profile?: BuildProfile,
  team?: string
): RustFerryTaskDefinition {
  return {
    type: "rustferry",
    action,
    project: project.root.fsPath,
    ...(platform === undefined ? {} : { platform }),
    ...(profile === undefined ? {} : { profile }),
    ...(team === undefined ? {} : { team }),
    ...(project.selectedDevice === undefined ? {} : { device: project.selectedDevice.id })
  };
}

function createTask(
  project: WorkspaceProject,
  invocation: CliInvocation,
  definition: RustFerryTaskDefinition,
  name: string
): vscode.Task {
  const args = [...invocation.prefixArgs, ...commandArguments(project, definition)];
  const execution = new vscode.ProcessExecution(invocation.executable, args, { cwd: project.root.fsPath });
  const folder = vscode.workspace.getWorkspaceFolder(project.root);
  const scope = folder ?? vscode.TaskScope.Workspace;
  const task = new vscode.Task(definition, scope, name, "RustFerry", execution, []);
  task.detail = `${path.basename(invocation.executable)} ${args.join(" ")}`;
  task.presentationOptions = {
    clear: false,
    echo: true,
    focus: false,
    panel: vscode.TaskPanelKind.Dedicated,
    reveal: vscode.TaskRevealKind.Always
  };
  return task;
}

function resolveProject(projects: WorkspaceProjects, configured: string | undefined): WorkspaceProject | undefined {
  if (configured === undefined) {
    return projects.selected;
  }
  const absolute = path.resolve(configured);
  return projects.all.find((project) => path.resolve(project.root.fsPath) === absolute);
}
