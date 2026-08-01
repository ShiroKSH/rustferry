import { readFile, realpath } from "node:fs/promises";

import * as vscode from "vscode";

import type { CliClient } from "../cli/client.js";
import { PROJECT_MANIFEST } from "../constants.js";
import { settings } from "../config/settings.js";
import type { WorkspaceProjects } from "../workspace/discovery.js";
import type { WorkspaceProject } from "../workspace/project.js";
import type { RustFerryDiagnostics, ValidationDocumentSnapshot } from "./collection.js";
import { sha256 } from "./fixSafety.js";
import {
  canIssueDiskBackedFix,
  isCurrentValidationText,
  type ValidationTextState
} from "./validationState.js";

export type ClientResolver = (project: WorkspaceProject) => Promise<CliClient>;

export class ConfigValidationCoordinator implements vscode.Disposable {
  readonly #timers = new Map<string, NodeJS.Timeout>();
  readonly #controllers = new Map<string, AbortController>();

  public constructor(
    readonly projects: WorkspaceProjects,
    readonly diagnostics: RustFerryDiagnostics,
    readonly clientFor: ClientResolver,
    readonly onError: (error: unknown, context: string) => void
  ) {}

  public schedule(document: vscode.TextDocument, immediate = false): void {
    if (!isManifest(document.uri)) {
      return;
    }
    const project = this.projects.all.find((candidate) => candidate.manifest.toString() === document.uri.toString());
    if (!project?.executionAvailable) {
      return;
    }
    const key = project.key;
    const previous = this.#timers.get(key);
    if (previous !== undefined) {
      clearTimeout(previous);
    }
    this.#controllers.get(key)?.abort();
    const delay = immediate ? 0 : settings(project.root).validationDebounceMs;
    const timer = setTimeout(() => {
      this.#timers.delete(key);
      void this.validate(project);
    }, delay);
    timer.unref();
    this.#timers.set(key, timer);
  }

  public async validate(project: WorkspaceProject): Promise<void> {
    if (!project.executionAvailable) {
      return;
    }
    this.#controllers.get(project.key)?.abort();
    const controller = new AbortController();
    this.#controllers.set(project.key, controller);
    try {
      const documentAtStart = openManifest(project);
      const sourceAtStart = documentAtStart?.getText();
      const textAtStart = documentAtStart === undefined || sourceAtStart === undefined
        ? undefined
        : textState(documentAtStart, sourceAtStart);
      const before = await fileSnapshot(project);
      if (textAtStart !== undefined && !textAtStart.dirty && textAtStart.sha256 !== before.sha256) {
        throw new Error("ferry.toml changed while validation was starting; stale diagnostics were discarded.");
      }
      const client = await this.clientFor(project);
      const response = await client.validate(project.root.fsPath, {
        signal: controller.signal,
        ...(textAtStart?.dirty === true && sourceAtStart !== undefined
          ? { manifestSource: sourceAtStart }
          : {})
      });
      if (!controller.signal.aborted) {
        const after = await fileSnapshot(project);
        if (
          before.realPath !== after.realPath
          || (textAtStart?.dirty !== true && before.sha256 !== after.sha256)
        ) {
          throw new Error("ferry.toml changed while validation was running; stale diagnostics were discarded.");
        }
        const document = openManifest(project);
        const currentText = document === undefined ? undefined : textState(document, document.getText());
        if (
          textAtStart !== undefined
            ? currentText === undefined || !isCurrentValidationText(textAtStart, currentText)
            : currentText?.dirty === true || (currentText !== undefined && currentText.sha256 !== after.sha256)
        ) {
          throw new Error("ferry.toml changed while validation was running; stale diagnostics were discarded.");
        }
        const snapshot: ValidationDocumentSnapshot | undefined = document !== undefined
          && currentText !== undefined
          && canIssueDiskBackedFix(currentText, after.sha256)
          ? {
              uri: document.uri.toString(),
              version: document.version,
              sha256: after.sha256,
              realPath: after.realPath
            }
          : undefined;
        this.diagnostics.update(project, response, snapshot);
        this.projects.refreshViews();
      }
    } catch (error) {
      if (!controller.signal.aborted) {
        this.onError(error, "Validate ferry.toml");
      }
    } finally {
      if (this.#controllers.get(project.key) === controller) {
        this.#controllers.delete(project.key);
      }
    }
  }

  public dispose(): void {
    for (const timer of this.#timers.values()) {
      clearTimeout(timer);
    }
    for (const controller of this.#controllers.values()) {
      controller.abort();
    }
    this.#timers.clear();
    this.#controllers.clear();
  }
}

function openManifest(project: WorkspaceProject): vscode.TextDocument | undefined {
  return vscode.workspace.textDocuments.find(
    (candidate) => candidate.uri.toString() === project.manifest.toString()
  );
}

function textState(document: vscode.TextDocument, contents: string): ValidationTextState {
  return {
    uri: document.uri.toString(),
    version: document.version,
    sha256: sha256(contents),
    dirty: document.isDirty
  };
}

async function fileSnapshot(project: WorkspaceProject): Promise<Readonly<{
  sha256: string;
  realPath: string;
}>> {
  const [contents, realPath] = await Promise.all([
    readFile(project.manifest.fsPath),
    realpath(project.manifest.fsPath)
  ]);
  return { sha256: sha256(contents), realPath };
}

function isManifest(uri: vscode.Uri): boolean {
  return uri.path.endsWith(`/${PROJECT_MANIFEST}`);
}
