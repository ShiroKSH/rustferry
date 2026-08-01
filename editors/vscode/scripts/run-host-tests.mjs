import { constants as fsConstants } from "node:fs";
import { access, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { downloadAndUnzipVSCode, runTests } from "@vscode/test-electron";

const VSCODE_VERSION = "1.100.0";
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const extensionRoot = path.resolve(scriptDirectory, "..");
const repositoryRoot = path.resolve(extensionRoot, "../..");
const executableName = process.platform === "win32" ? "cargo-ferry.exe" : "cargo-ferry";
const cliPath = path.resolve(
  process.env.RUSTFERRY_TEST_CLI ?? path.join(repositoryRoot, "target", "debug", executableName)
);
const cacheRoot = path.resolve(
  process.env.RUSTFERRY_VSCODE_TEST_CACHE
    ?? path.join(process.env.RUNNER_TEMP ?? os.tmpdir(), "rustferry-vscode-test-cache")
);
const runRoot = await mkdtemp(path.join(os.tmpdir(), "rf-host-"));

try {
  await access(cliPath, process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
  const vscodeExecutablePath = await downloadAndUnzipVSCode({
    version: VSCODE_VERSION,
    cachePath: cacheRoot,
    extensionDevelopmentPath: extensionRoot
  });
  await runScenario(vscodeExecutablePath, "ordinary", path.join(extensionRoot, "test", "fixtures", "ordinary-rust"));
  await runScenario(vscodeExecutablePath, "ferry", path.join(extensionRoot, "test", "fixtures", "ferry-project"));
} catch (error) {
  process.stderr.write(`Extension Host smoke failed: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
} finally {
  await rm(runRoot, { recursive: true, force: true });
}

async function runScenario(vscodeExecutablePath, scenario, workspace) {
  const profileRoot = path.join(runRoot, scenario === "ordinary" ? "o" : "f");
  const userData = path.join(profileRoot, "u");
  const extensions = path.join(profileRoot, "e");
  await mkdir(path.join(userData, "User"), { recursive: true });
  await mkdir(extensions, { recursive: true });
  await writeFile(
    path.join(userData, "User", "settings.json"),
    `${JSON.stringify({
      "extensions.ignoreRecommendations": true,
      "rustferry.cliPath": cliPath,
      "rustferry.validation.debounceMs": 100,
      "workbench.startupEditor": "none"
    }, null, 2)}\n`,
    "utf8"
  );
  const manifest = path.join(workspace, "ferry.toml");
  await runTests({
    vscodeExecutablePath,
    extensionDevelopmentPath: extensionRoot,
    extensionTestsPath: path.join(extensionRoot, "test", "host", "index.cjs"),
    launchArgs: [
      workspace,
      "--disable-extensions",
      "--new-window",
      `--user-data-dir=${userData}`,
      `--extensions-dir=${extensions}`
    ],
    extensionTestsEnv: {
      RUSTFERRY_EXPECTED_MANIFEST: scenario === "ferry" ? manifest : undefined,
      RUSTFERRY_HOST_SCENARIO: scenario,
      RUSTFERRY_HOST_STARTED_AT_MS: String(Date.now()),
      RUSTFERRY_TEST_CLI: cliPath
    }
  });
}
