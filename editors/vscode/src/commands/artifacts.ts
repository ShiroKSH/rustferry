import { lstat, realpath } from "node:fs/promises";
import * as path from "node:path";

import * as vscode from "vscode";

import type { ProtocolArtifact } from "../cli/protocol.js";
import {
  artifactPathWithinGeneratedRoot,
  generatedArtifactRoot
} from "../workspace/artifactSafety.js";
import type { WorkspaceProject } from "../workspace/project.js";
import { UserActionError } from "./navigation.js";
import type { CommandServices } from "./types.js";

type ArtifactArgument = Readonly<{
  project: WorkspaceProject;
  artifact: ProtocolArtifact;
}>;

export async function revealArtifact(argument?: unknown): Promise<void> {
  const value = requireArtifact(argument);
  await vscode.commands.executeCommand("revealFileInOS", vscode.Uri.file(value.artifact.path));
}

export async function copyArtifactPath(argument?: unknown): Promise<void> {
  const value = requireArtifact(argument);
  await vscode.env.clipboard.writeText(value.artifact.path);
  await vscode.window.showInformationMessage("RustFerry artifact path copied.");
}

export async function inspectArtifact(argument?: unknown): Promise<void> {
  const value = requireArtifact(argument);
  const document = await vscode.workspace.openTextDocument({
    content: `${JSON.stringify(value.artifact, null, 2)}\n`,
    language: "json"
  });
  await vscode.window.showTextDocument(document, { preview: true });
}

export async function deleteArtifact(services: CommandServices, argument?: unknown): Promise<void> {
  const value = requireArtifact(argument);
  if (!vscode.workspace.isTrusted) {
    throw new UserActionError("Trust the workspace before deleting generated artifacts.", "trust");
  }
  if (
    !services.projects.all.includes(value.project)
    || !value.project.artifacts.some((artifact) => sameArtifact(artifact, value.artifact))
  ) {
    throw new UserActionError("Select an artifact registered by the active RustFerry project.");
  }
  await assertGeneratedArtifact(value.project, value.artifact);
  const name = path.basename(value.artifact.path);
  const confirmation = await vscode.window.showWarningMessage(
    `Delete generated artifact ${name}?`,
    { modal: true, detail: value.artifact.path },
    "Delete Artifact"
  );
  if (confirmation !== "Delete Artifact") {
    return;
  }
  // The modal creates an intentional race window. Re-resolve every boundary immediately before
  // the destructive operation so a swapped symlink or stale command argument fails closed.
  await assertGeneratedArtifact(value.project, value.artifact);
  const metadata = await vscode.workspace.fs.stat(vscode.Uri.file(value.artifact.path));
  await vscode.workspace.fs.delete(vscode.Uri.file(value.artifact.path), {
    recursive: (metadata.type & vscode.FileType.Directory) !== 0,
    useTrash: true
  });
  await services.projects.forgetArtifact(value.project, value.artifact);
  await vscode.window.showInformationMessage(`Moved ${name} to the Trash.`);
}

function sameArtifact(left: ProtocolArtifact, right: ProtocolArtifact): boolean {
  return left.path === right.path
    && left.kind === right.kind
    && left.platform === right.platform
    && left.package_identifier === right.package_identifier
    && left.profile === right.profile;
}

function requireArtifact(argument: unknown): ArtifactArgument {
  if (
    typeof argument !== "object"
    || argument === null
    || !("project" in argument)
    || !("artifact" in argument)
  ) {
    throw new UserActionError("Select a RustFerry artifact first.");
  }
  return argument as ArtifactArgument;
}

async function assertGeneratedArtifact(project: WorkspaceProject, artifact: ProtocolArtifact): Promise<void> {
  const target = generatedArtifactRoot(project);
  if (!artifactPathWithinGeneratedRoot(project, artifact.path)) {
    throw new UserActionError("RustFerry refuses to delete an artifact outside the target/ferry directory.");
  }
  if (
    project.metadata?.target_directory !== undefined
    && path.resolve(project.metadata.target_directory) !== path.resolve(target)
  ) {
    throw new UserActionError("RustFerry refuses protocol metadata that changes the local target/ferry authority.");
  }
  const absoluteTarget = path.resolve(target);
  const absoluteArtifact = path.resolve(artifact.path);
  const lexicalRelative = path.relative(absoluteTarget, absoluteArtifact);
  if (
    lexicalRelative.length === 0
    || lexicalRelative.startsWith("..")
    || path.isAbsolute(lexicalRelative)
  ) {
    throw new UserActionError("RustFerry refuses to delete an artifact outside the target/ferry directory.");
  }
  const [realTarget, realArtifact] = await Promise.all([realpath(target), realpath(artifact.path)]);
  const relative = path.relative(realTarget, realArtifact);
  if (relative.length === 0 || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new UserActionError("RustFerry refuses to delete an artifact outside the validated target/ferry directory.");
  }
  const metadata = await lstat(artifact.path);
  if (metadata.isSymbolicLink()) {
    throw new UserActionError("RustFerry refuses to delete a symbolic-link artifact.");
  }
  const relativeParts = lexicalRelative.split(path.sep).filter(Boolean);
  let cursor = absoluteTarget;
  if ((await lstat(cursor)).isSymbolicLink()) {
    throw new UserActionError("RustFerry refuses to delete through a symbolic-link target directory.");
  }
  for (const part of relativeParts) {
    cursor = path.join(cursor, part);
    if ((await lstat(cursor)).isSymbolicLink()) {
      throw new UserActionError("RustFerry refuses to delete through a symbolic-link boundary.");
    }
  }
}
