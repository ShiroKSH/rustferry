import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { rangeWithinLines, sha256, validateSafeFilePath } from "../../src/diagnostics/fixSafety.js";

const temporary: string[] = [];

afterEach(async () => {
  await Promise.all(temporary.splice(0).map(async (directory) => await rm(directory, { recursive: true, force: true })));
});

describe("quick-fix safety", () => {
  it("binds hashes and validates exact ranges", () => {
    expect(sha256("name = 'ferry'\n")).toHaveLength(64);
    expect(rangeWithinLines({ start: { line: 0, character: 0 }, end: { line: 0, character: 4 } }, ["name"])).toBe(true);
    expect(rangeWithinLines({ start: { line: 0, character: 5 }, end: { line: 0, character: 6 } }, ["name"])).toBe(false);
    expect(rangeWithinLines({ start: { line: 1, character: 0 }, end: { line: 0, character: 0 } }, ["a", "b"])).toBe(false);
  });

  it.runIf(process.platform !== "win32")("rejects a symlink boundary even when it resolves inside the root", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "rustferry-fix-safety-"));
    temporary.push(root);
    const realDirectory = path.join(root, "real");
    const linkedDirectory = path.join(root, "linked");
    await mkdir(realDirectory);
    const target = path.join(realDirectory, "ferry.toml");
    await writeFile(target, "[package]\n", "utf8");
    await symlink(realDirectory, linkedDirectory);

    await expect(validateSafeFilePath(root, path.join(linkedDirectory, "ferry.toml"), await realpath(target)))
      .rejects.toThrow("symbolic-link");
  });
});
