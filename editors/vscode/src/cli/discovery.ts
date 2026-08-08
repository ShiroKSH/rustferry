import { constants as fsConstants } from "node:fs";
import { access, stat } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import type { ExtensionSettings } from "../config/settings.js";

export type CliInvocation = Readonly<{
  executable: string;
  prefixArgs: readonly string[];
  source: "setting" | "path" | "cargo-bin" | "development";
  developmentRoot?: string;
}>;

export class CliDiscoveryError extends Error {
  public constructor(message: string, readonly searched: readonly string[]) {
    super(message);
    this.name = "CliDiscoveryError";
  }
}

export async function discoverCli(
  projectRoot: string | undefined,
  extensionSettings: ExtensionSettings,
  environment: NodeJS.ProcessEnv = process.env
): Promise<CliInvocation> {
  const searched: string[] = [];
  if (extensionSettings.cliPath !== undefined) {
    if (!path.isAbsolute(extensionSettings.cliPath)) {
      throw new CliDiscoveryError("rustferry.cliPath must be an absolute path.", [extensionSettings.cliPath]);
    }
    searched.push(extensionSettings.cliPath);
    if (await isExecutable(extensionSettings.cliPath)) {
      return invocation(extensionSettings.cliPath, "setting");
    }
    throw new CliDiscoveryError("The configured cargo-ferry executable does not exist or cannot be executed.", searched);
  }

  const direct = await findExecutableOnPath("cargo-ferry", environment.PATH);
  searched.push("cargo-ferry in PATH");
  if (direct !== undefined) {
    return { executable: direct, prefixArgs: [], source: "path" };
  }

  const cargo = await findExecutableOnPath("cargo", environment.PATH);
  searched.push("cargo in PATH");
  if (cargo !== undefined) {
    return { executable: cargo, prefixArgs: ["ferry"], source: "path" };
  }

  const cargoHome = environment.CARGO_HOME ?? path.join(os.homedir(), ".cargo");
  const cargoBin = path.join(cargoHome, "bin", executableName("cargo-ferry"));
  searched.push(cargoBin);
  if (await isExecutable(cargoBin)) {
    return { executable: cargoBin, prefixArgs: [], source: "cargo-bin" };
  }

  if (extensionSettings.developmentMode && projectRoot !== undefined) {
    const development = await findDevelopmentCli(projectRoot);
    searched.push("ancestor RustFerry target/debug/cargo-ferry");
    if (development !== undefined) {
      return {
        executable: development.executable,
        prefixArgs: [],
        source: "development",
        developmentRoot: development.root
      };
    }
  }

  throw new CliDiscoveryError("cargo-ferry was not found.", searched);
}

export async function findExecutableOnPath(
  command: string,
  pathValue: string | undefined,
  platform = process.platform,
  pathExtValue = process.env.PATHEXT
): Promise<string | undefined> {
  if (pathValue === undefined || pathValue.length === 0) {
    return undefined;
  }
  const extensions = platform === "win32"
    ? (pathExtValue ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
    : [""];
  for (const directory of pathValue.split(path.delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = path.join(directory, platform === "win32" ? `${command}${extension.toLowerCase()}` : command);
      if (await isExecutable(candidate)) {
        return candidate;
      }
      if (platform === "win32") {
        const originalCase = path.join(directory, `${command}${extension}`);
        if (originalCase !== candidate && await isExecutable(originalCase)) {
          return originalCase;
        }
      }
    }
  }
  return undefined;
}

function invocation(executable: string, source: CliInvocation["source"]): CliInvocation {
  const base = path.basename(executable).toLowerCase();
  return {
    executable,
    prefixArgs: base === "cargo" || base === "cargo.exe" ? ["ferry"] : [],
    source
  };
}

async function isExecutable(candidate: string): Promise<boolean> {
  try {
    await access(candidate, process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
    return (await stat(candidate)).isFile();
  } catch {
    return false;
  }
}

async function findDevelopmentCli(
  projectRoot: string
): Promise<Readonly<{ executable: string; root: string }> | undefined> {
  let directory = path.resolve(projectRoot);
  for (let depth = 0; depth < 8; depth += 1) {
    const marker = path.join(directory, "crates", "cargo-ferry", "Cargo.toml");
    const rootManifest = path.join(directory, "Cargo.toml");
    if (await exists(marker) && await exists(rootManifest)) {
      const binary = path.join(directory, "target", "debug", executableName("cargo-ferry"));
      return await isExecutable(binary) ? { executable: binary, root: directory } : undefined;
    }
    const parent = path.dirname(directory);
    if (parent === directory) {
      break;
    }
    directory = parent;
  }
  return undefined;
}

async function exists(candidate: string): Promise<boolean> {
  try {
    await access(candidate, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function executableName(name: string): string {
  return process.platform === "win32" ? `${name}.exe` : name;
}
