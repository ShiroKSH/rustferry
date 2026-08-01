import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { discoverCli, findExecutableOnPath } from "../../src/cli/discovery.js";
import type { ExtensionSettings } from "../../src/config/settings.js";

const temporary: string[] = [];
const defaults: ExtensionSettings = {
  developmentMode: false,
  defaultPlatform: "android",
  defaultProfile: "debug",
  validationDebounceMs: 350,
  maxProtocolLineBytes: 1_048_576
};

afterEach(async () => {
  await Promise.all(temporary.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true })));
});

describe("cargo-ferry discovery", () => {
  it.runIf(process.platform !== "win32")("prefers cargo-ferry over cargo on PATH", async () => {
    const directory = await executableDirectory(["cargo-ferry", "cargo"]);
    const invocation = await discoverCli(undefined, defaults, { PATH: directory, CARGO_HOME: path.join(directory, "missing") });
    expect(invocation.executable).toBe(path.join(directory, "cargo-ferry"));
    expect(invocation.prefixArgs).toEqual([]);
  });

  it.runIf(process.platform !== "win32")("falls back to cargo with a ferry subcommand argument", async () => {
    const directory = await executableDirectory(["cargo"]);
    const invocation = await discoverCli(undefined, defaults, { PATH: directory, CARGO_HOME: path.join(directory, "missing") });
    expect(invocation.executable).toBe(path.join(directory, "cargo"));
    expect(invocation.prefixArgs).toEqual(["ferry"]);
  });

  it.runIf(process.platform !== "win32")("honors an explicit absolute executable", async () => {
    const directory = await executableDirectory(["custom-ferry"]);
    const executable = path.join(directory, "custom-ferry");
    const invocation = await discoverCli(undefined, { ...defaults, cliPath: executable }, { PATH: "" });
    expect(invocation).toMatchObject({ executable, source: "setting", prefixArgs: [] });
  });

  it.runIf(process.platform !== "win32")("records the trusted repository root for explicit development mode", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "rustferry-vscode-development-"));
    temporary.push(root);
    const binary = path.join(root, "target", "debug", "cargo-ferry");
    await mkdir(path.join(root, "crates", "cargo-ferry"), { recursive: true });
    await mkdir(path.dirname(binary), { recursive: true });
    await writeFile(path.join(root, "Cargo.toml"), "[workspace]\n", "utf8");
    await writeFile(path.join(root, "crates", "cargo-ferry", "Cargo.toml"), "[package]\nname = \"cargo-ferry\"\nversion = \"0.1.0\"\n", "utf8");
    await writeFile(binary, "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(binary, 0o755);

    const invocation = await discoverCli(
      path.join(root, "examples", "counter"),
      { ...defaults, developmentMode: true },
      { PATH: "", CARGO_HOME: path.join(root, "missing-cargo-home") }
    );

    expect(invocation).toEqual({
      executable: binary,
      prefixArgs: [],
      source: "development",
      developmentRoot: root
    });
  });

  it("does not search an empty PATH", async () => {
    await expect(findExecutableOnPath("cargo-ferry", "")).resolves.toBeUndefined();
  });

  it.runIf(process.platform !== "win32")("rejects an executable directory", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "rustferry-vscode-discovery-"));
    temporary.push(directory);
    const fakeExecutable = path.join(directory, "cargo-ferry");
    await mkdir(fakeExecutable);
    await chmod(fakeExecutable, 0o755);

    await expect(discoverCli(undefined, { ...defaults, cliPath: fakeExecutable }, { PATH: "" }))
      .rejects.toMatchObject({ name: "CliDiscoveryError" });
  });
});

async function executableDirectory(names: readonly string[]): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "rustferry-vscode-discovery-"));
  temporary.push(directory);
  await Promise.all(names.map(async (name) => {
    const candidate = path.join(directory, name);
    await writeFile(candidate, "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(candidate, 0o755);
  }));
  return directory;
}
