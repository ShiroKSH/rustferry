import { readFile } from "node:fs/promises";
import * as path from "node:path";

import { describe, expect, it } from "vitest";

describe("job artifact reveal ownership", () => {
  it("never launches a path returned by cargo-ferry from the extension", async () => {
    const source = await readFile(
      path.resolve(process.cwd(), "src/commands/jobs.ts"),
      "utf8"
    );

    expect(source).not.toContain("revealFileInOS");
    expect(source).not.toContain("vscode.Uri.file");
  });
});
