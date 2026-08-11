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
    menus: Readonly<Record<string, readonly Readonly<{
      command: string;
      when?: string;
    }>[]>>;
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
    expect(manifest.contributes.views.rustferry).toHaveLength(4);
    expect(manifest.contributes.views.rustferry).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "rustferry.jobs" })
    ]));
    expect(manifest.contributes.commands.map((entry) => entry.command)).toEqual(expect.arrayContaining([
      "rustferry.jobs.show",
      "rustferry.jobs.logs",
      "rustferry.jobs.logs.follow",
      "rustferry.jobs.logs.loadMore",
      "rustferry.jobs.cancel",
      "rustferry.jobs.retry",
      "rustferry.jobs.artifact.verify",
      "rustferry.jobs.artifact.reveal",
      "rustferry.jobs.artifact.remove",
      "rustferry.jobs.remoteSnapshotBuild",
      "rustferry.jobs.signingReadiness"
    ]));
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
      "media/rustferry-icon.png",
      "media/walkthrough/*.md",
      "snippets/rust.json"
    ]);
  });

  it("shows job actions only through exact per-item handshake capability tokens", async () => {
    const source = await readFile(path.resolve(process.cwd(), "package.json"), "utf8");
    const manifest = JSON.parse(source) as PackageManifest;
    const actionTokens = new Map([
      ["rustferry.jobs.show", "jobs-show"],
      ["rustferry.jobs.logs", "jobs-logs-page"],
      ["rustferry.jobs.logs.follow", "jobs-logs-page"],
      ["rustferry.jobs.cancel", "jobs-cancel"],
      ["rustferry.jobs.retry", "jobs-retry"],
      ["rustferry.jobs.artifact.verify", "jobs-artifact-verify"],
      ["rustferry.jobs.artifact.reveal", "jobs-artifact-reveal"],
      ["rustferry.jobs.artifact.remove", "jobs-artifact-remove"]
    ]);
    const contextItems = manifest.contributes.menus["view/item/context"] ?? [];
    const paletteItems = manifest.contributes.menus.commandPalette ?? [];
    for (const [command, token] of actionTokens) {
      const context = contextItems.find((item) => item.command === command);
      expect(context?.when).toContain(`view == rustferry.jobs`);
      expect(context?.when).toContain(`${token}(\\.|$)`);
      expect(paletteItems).toContainEqual({ command, when: "false" });
    }
    const snapshot = contextItems.find((item) => item.command === "rustferry.jobs.remoteSnapshotBuild");
    expect(snapshot?.when).toContain("remote-build-preview(\\.|$)");
    expect(snapshot?.when).toContain("remote-build-submit(\\.|$)");
    const readiness = contextItems.find((item) => item.command === "rustferry.jobs.signingReadiness");
    expect(readiness?.when).toContain("signing-readiness(\\.|$)");
    for (const command of [
      "rustferry.jobs.logs.loadMore",
      "rustferry.jobs.remoteSnapshotBuild",
      "rustferry.jobs.signingReadiness"
    ]) {
      expect(paletteItems).toContainEqual({ command, when: "false" });
    }
  });

  it("uses no shell process execution in extension source", async () => {
    const processSource = await readFile(path.resolve(process.cwd(), "src/cli/process.ts"), "utf8");
    const tasksSource = await readFile(path.resolve(process.cwd(), "src/tasks/provider.ts"), "utf8");
    expect(processSource).toContain("shell: false");
    expect(tasksSource).toContain("ProcessExecution");
    expect(tasksSource).not.toContain("ShellExecution");
  });
});
