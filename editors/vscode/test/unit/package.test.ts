import { readFile } from "node:fs/promises";
import * as path from "node:path";

import { describe, expect, it } from "vitest";

type PackageManifest = Readonly<{
  main: string;
  files: readonly string[];
  activationEvents: readonly string[];
  contributes: Readonly<{
    commands: readonly Readonly<{ command: string }>[];
    views: Readonly<Record<string, readonly unknown[]>>;
    taskDefinitions: readonly unknown[];
    snippets: readonly unknown[];
  }>;
}>;

describe("extension manifest", () => {
  it("activates only for RustFerry surfaces and contributes the native MVP", async () => {
    const source = await readFile(path.resolve(process.cwd(), "package.json"), "utf8");
    const manifest = JSON.parse(source) as PackageManifest;
    expect(manifest.main).toBe("./dist/extension.js");
    expect(manifest.activationEvents).toContain("workspaceContains:**/ferry.toml");
    expect(manifest.activationEvents).not.toContain("*");
    expect(manifest.contributes.commands.map((entry) => entry.command)).toEqual(expect.arrayContaining([
      "rustferry.createProject",
      "rustferry.check",
      "rustferry.doctor",
      "rustferry.buildSelected",
      "rustferry.buildPhysicalIos",
      "rustferry.selectDevelopmentTeam",
      "rustferry.addCapability"
    ]));
    expect(manifest.contributes.views.rustferry).toHaveLength(3);
    expect(manifest.contributes.taskDefinitions).toHaveLength(1);
    expect(manifest.contributes.snippets).toHaveLength(1);
    expect(source).not.toContain("webview");
  });

  it("packages from an explicit production-file allowlist", async () => {
    const source = await readFile(path.resolve(process.cwd(), "package.json"), "utf8");
    const manifest = JSON.parse(source) as PackageManifest;
    expect(manifest.files).toEqual([
      "CHANGELOG.md",
      "LICENSE",
      "README.md",
      "SUPPORT.md",
      "dist/extension.js",
      "media/ferry.svg",
      "media/walkthrough/*.md",
      "snippets/rust.json"
    ]);
  });

  it("uses no shell process execution in extension source", async () => {
    const processSource = await readFile(path.resolve(process.cwd(), "src/cli/process.ts"), "utf8");
    const tasksSource = await readFile(path.resolve(process.cwd(), "src/tasks/provider.ts"), "utf8");
    expect(processSource).toContain("shell: false");
    expect(tasksSource).toContain("ProcessExecution");
    expect(tasksSource).not.toContain("ShellExecution");
  });
});
