import { describe, expect, it } from "vitest";

import {
  canIssueDiskBackedFix,
  isCurrentValidationText,
  type ValidationTextState
} from "../../src/diagnostics/validationState.js";

const dirty: ValidationTextState = {
  uri: "file:///workspace/ferry.toml",
  version: 7,
  sha256: "dirty-source",
  dirty: true
};

describe("validation document freshness", () => {
  it("rejects an edit-and-revert with a newer document version", () => {
    expect(isCurrentValidationText(dirty, { ...dirty, version: 9 })).toBe(false);
  });

  it("rejects a save transition while dirty-source validation is running", () => {
    expect(isCurrentValidationText(dirty, { ...dirty, dirty: false })).toBe(false);
  });

  it("never issues a disk-backed quick fix for dirty source", () => {
    expect(canIssueDiskBackedFix(dirty, dirty.sha256)).toBe(false);
    expect(canIssueDiskBackedFix({ ...dirty, dirty: false }, dirty.sha256)).toBe(true);
  });
});
