import * as path from "node:path";

import { describe, expect, it } from "vitest";

import { artifactPathWithinGeneratedRoot } from "../../src/workspace/artifactSafety.js";

const project = {
  root: { scheme: "file", fsPath: path.resolve("/tmp/rustferry-project") }
} as never;

describe("artifact authority", () => {
  it("derives deletion authority from the local project root only", () => {
    expect(artifactPathWithinGeneratedRoot(
      project,
      path.resolve("/tmp/rustferry-project/target/ferry/android/debug/app.apk")
    )).toBe(true);
    expect(artifactPathWithinGeneratedRoot(project, path.resolve("/tmp/outside.app"))).toBe(false);
    expect(artifactPathWithinGeneratedRoot(project, path.parse(process.cwd()).root)).toBe(false);
  });

  it("rejects relative paths and the generated root itself", () => {
    expect(artifactPathWithinGeneratedRoot(project, "target/ferry/app.apk")).toBe(false);
    expect(artifactPathWithinGeneratedRoot(
      project,
      path.resolve("/tmp/rustferry-project/target/ferry")
    )).toBe(false);
  });
});
