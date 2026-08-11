import { describe, expect, it, vi } from "vitest";

import type { RemoteBuildPreviewResponse } from "../../src/cli/protocol.js";
import {
  remoteBuildPreviewDetail,
  submitAfterRemoteBuildConsent
} from "../../src/jobs/remoteBuildConsent.js";

const preview: RemoteBuildPreviewResponse = {
  protocol_version: 1,
  workspace: "C:\\work\\ferry",
  provider: "github",
  target: "ios-device",
  profile: "release",
  signing_mode: "unsigned",
  source_mode: "snapshot",
  preview_sha256: "a".repeat(64),
  consent_token: "consent-token",
  source: {
    manifest_sha256: "b".repeat(64),
    file_count: "42",
    total_bytes: "9007199254740993"
  },
  effects: ["Create an immutable temporary snapshot ref"],
  consent_required: true
};

describe("remote snapshot build consent", () => {
  it("performs no submission when explicit confirmation is denied", async () => {
    const submit = vi.fn();

    await expect(submitAfterRemoteBuildConsent(
      preview,
      () => Promise.resolve(false),
      (value) => ({
        consent_token: value.consent_token,
        preview_sha256: value.preview_sha256,
        approved: true
      }),
      submit
    )).resolves.toBeUndefined();
    expect(submit).not.toHaveBeenCalled();
  });

  it("submits only the exact token and digest from the confirmed preview", async () => {
    const submit = vi.fn(() => Promise.resolve("submitted"));

    await expect(submitAfterRemoteBuildConsent(
      preview,
      (value) => Promise.resolve(value === preview),
      (value) => ({
        consent_token: value.consent_token,
        preview_sha256: value.preview_sha256,
        approved: true
      }),
      submit
    )).resolves.toBe("submitted");
    expect(submit).toHaveBeenCalledWith({
      consent_token: "consent-token",
      preview_sha256: "a".repeat(64),
      approved: true
    });
  });

  it("shows every bounded effect without silently truncating consent-critical text", () => {
    const effect = `prefix-${"x".repeat(2_048)}-material-suffix`;
    const detail = remoteBuildPreviewDetail({ ...preview, effects: [effect] });

    expect(detail).toContain(effect);
    expect(detail).toContain("Preview SHA-256:");
  });
});
