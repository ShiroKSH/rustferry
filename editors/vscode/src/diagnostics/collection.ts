import { readFile } from "node:fs/promises";

import * as vscode from "vscode";

import type { ProtocolDiagnostic, ProtocolFix, ValidationResponse } from "../cli/protocol.js";
import { commands } from "../constants.js";
import type { WorkspaceProject } from "../workspace/project.js";
import { rangeWithinLines, sha256, validateSafeFilePath } from "./fixSafety.js";

export type ValidationDocumentSnapshot = Readonly<{
  uri: string;
  version: number;
  sha256: string;
  realPath: string;
}>;

type StoredFix = Readonly<{
  token: string;
  projectRoot: string;
  sourceUri: string;
  snapshot: ValidationDocumentSnapshot;
  fix: ProtocolFix;
}>;

export class RustFerryDiagnostics implements vscode.CodeActionProvider, vscode.Disposable {
  readonly #collection = vscode.languages.createDiagnosticCollection("rustferry");
  readonly #projectUris = new Map<string, Set<string>>();
  readonly #fixes = new Map<string, readonly StoredFix[]>();
  readonly #fixTokens = new Map<string, StoredFix>();

  public readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  public update(
    project: WorkspaceProject,
    response: ValidationResponse,
    snapshot?: ValidationDocumentSnapshot
  ): void {
    this.clearProject(project);
    const grouped = new Map<string, { uri: vscode.Uri; values: vscode.Diagnostic[] }>();
    for (const source of response.diagnostics) {
      const uri = diagnosticFileUri(source.file);
      const key = uri.toString();
      const group = grouped.get(key) ?? { uri, values: [] };
      const diagnostic = toDiagnostic(source);
      group.values.push(diagnostic);
      grouped.set(key, group);
      const diagnosticKey = fixKey(uri, diagnostic);
      const fixes = snapshot?.uri === uri.toString()
        ? source.fixes.map((fix, index) => ({
            token: `${diagnosticKey}:${index}:${snapshot.sha256}`,
            projectRoot: project.root.fsPath,
            sourceUri: uri.toString(),
            snapshot,
            fix
          }))
        : [];
      this.#fixes.set(diagnosticKey, fixes);
      for (const fix of fixes) {
        this.#fixTokens.set(fix.token, fix);
      }
    }
    const uris = new Set<string>();
    for (const [key, group] of grouped) {
      this.#collection.set(group.uri, group.values);
      uris.add(key);
    }
    this.#projectUris.set(project.key, uris);
    project.valid = response.valid;
  }

  public publish(project: WorkspaceProject, sources: readonly ProtocolDiagnostic[]): void {
    const response: ValidationResponse = {
      protocol_version: 1,
      workspace: project.root.fsPath,
      valid: !sources.some((diagnostic) => diagnostic.severity === "error"),
      diagnostics: sources
    };
    this.update(project, response);
  }

  public clearProject(project: WorkspaceProject): void {
    for (const key of this.#projectUris.get(project.key) ?? []) {
      const uri = vscode.Uri.parse(key);
      for (const diagnostic of this.#collection.get(uri) ?? []) {
        const key = fixKey(uri, diagnostic);
        for (const stored of this.#fixes.get(key) ?? []) {
          this.#fixTokens.delete(stored.token);
        }
        this.#fixes.delete(key);
      }
      this.#collection.delete(uri);
    }
    this.#projectUris.delete(project.key);
  }

  public provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    for (const diagnostic of context.diagnostics.filter((candidate) => candidate.source === "RustFerry")) {
      for (const stored of this.#fixes.get(fixKey(document.uri, diagnostic)) ?? []) {
        const edit = stored.fix.text_edit ?? stored.fix.edit;
        if (
          stored.fix.kind !== "text_edit"
          || edit === undefined
          || stored.sourceUri !== document.uri.toString()
          || stored.snapshot.version !== document.version
          || stored.snapshot.sha256 !== sha256(document.getText())
          || !rangeWithinLines(edit.range, document.getText().split(/\r?\n/u))
        ) {
          continue;
        }
        const action = new vscode.CodeAction(stored.fix.title, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.isPreferred = true;
        action.command = {
          command: "rustferry.applyValidatedFix",
          title: stored.fix.title,
          arguments: [stored.token]
        };
        actions.push(action);
      }
      const doctor = new vscode.CodeAction("Run RustFerry Doctor", vscode.CodeActionKind.QuickFix);
      doctor.command = { command: commands.doctor, title: "Run RustFerry Doctor" };
      doctor.diagnostics = [diagnostic];
      actions.push(doctor);
      if (typeof diagnostic.code === "object") {
        const docs = new vscode.CodeAction("Open RustFerry documentation", vscode.CodeActionKind.QuickFix);
        docs.command = {
          command: "vscode.open",
          title: "Open RustFerry documentation",
          arguments: [diagnostic.code.target]
        };
        docs.diagnostics = [diagnostic];
        actions.push(docs);
      }
    }
    return actions;
  }

  public async applyValidatedFix(token: unknown): Promise<void> {
    if (typeof token !== "string") {
      throw new Error("RustFerry quick-fix token is invalid.");
    }
    const stored = this.#fixTokens.get(token);
    const edit = stored?.fix.text_edit ?? stored?.fix.edit;
    if (stored?.fix.kind !== "text_edit" || edit === undefined) {
      throw new Error("RustFerry quick fix is stale. Validate the project again.");
    }
    const document = vscode.workspace.textDocuments.find(
      (candidate) => candidate.uri.toString() === stored.sourceUri
    );
    if (
      document?.uri.scheme !== "file"
      || document.isDirty
      || document.version !== stored.snapshot.version
      || sha256(document.getText()) !== stored.snapshot.sha256
      || vscode.Uri.file(edit.file).toString() !== stored.sourceUri
      || !rangeWithinLines(edit.range, document.getText().split(/\r?\n/u))
    ) {
      throw new Error("RustFerry quick fix is stale or does not match this document.");
    }
    await validateSafeFilePath(stored.projectRoot, edit.file, stored.snapshot.realPath);
    if (sha256(await readFile(edit.file)) !== stored.snapshot.sha256) {
      throw new Error("RustFerry quick-fix file changed after validation.");
    }
    // No asynchronous boundary after this final document check and before submitting the edit.
    if (document.version !== stored.snapshot.version || sha256(document.getText()) !== stored.snapshot.sha256) {
      throw new Error("RustFerry quick-fix document changed after validation.");
    }
    const workspaceEdit = new vscode.WorkspaceEdit();
    workspaceEdit.replace(document.uri, toRange(edit.range), edit.new_text);
    if (!await vscode.workspace.applyEdit(workspaceEdit)) {
      throw new Error("VS Code refused the RustFerry quick fix.");
    }
    this.#fixTokens.delete(token);
  }

  public dispose(): void {
    this.#fixes.clear();
    this.#fixTokens.clear();
    this.#projectUris.clear();
    this.#collection.dispose();
  }
}

function toDiagnostic(source: ProtocolDiagnostic): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(toRange(source.range), source.message, severity(source.severity));
  diagnostic.source = "RustFerry";
  diagnostic.code = source.documentation === undefined
    ? source.code
    : { value: source.code, target: vscode.Uri.parse(source.documentation) };
  if (source.help !== undefined) {
    diagnostic.message = `${source.message}\n${source.help}`;
  }
  return diagnostic;
}

function toRange(range: ProtocolDiagnostic["range"]): vscode.Range {
  return new vscode.Range(
    range.start.line,
    range.start.character,
    range.end.line,
    range.end.character
  );
}

function severity(value: ProtocolDiagnostic["severity"]): vscode.DiagnosticSeverity {
  switch (value) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    case "hint":
      return vscode.DiagnosticSeverity.Hint;
  }
}

function fixKey(uri: vscode.Uri, diagnostic: vscode.Diagnostic): string {
  const code = typeof diagnostic.code === "object" ? diagnostic.code.value : diagnostic.code;
  return `${uri.toString()}:${diagnostic.range.start.line}:${diagnostic.range.start.character}:${diagnostic.range.end.line}:${diagnostic.range.end.character}:${String(code)}`;
}

function diagnosticFileUri(file: string): vscode.Uri {
  if (process.platform === "win32") {
    if (file.startsWith("\\\\?\\UNC\\")) {
      return vscode.Uri.file(`\\\\${file.slice(8)}`);
    }
    if (/^\\\\\?\\[A-Za-z]:\\/u.test(file)) {
      return vscode.Uri.file(file.slice(4));
    }
  }
  return vscode.Uri.file(file);
}
