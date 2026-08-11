import { describe, expect, it } from "vitest";

import { jobIdeCommands, remoteIdeCommands } from "../../src/constants.js";
import {
  advertisesJobCommand,
  jobArtifactContextValue,
  jobContextValue,
  jobProjectContextValue
} from "../../src/jobs/capabilities.js";

describe("job action capability gates", () => {
  it("matches only exact handshake command identifiers", () => {
    const advertised = [
      `${jobIdeCommands.show}-future`,
      jobIdeCommands.logsPage,
      jobIdeCommands.cancel
    ];
    expect(advertisesJobCommand(advertised, jobIdeCommands.show)).toBe(false);
    expect(advertisesJobCommand(advertised, jobIdeCommands.logsPage)).toBe(true);
    expect(jobContextValue(advertised, {
      can_cancel: true,
      can_retry: false,
      retry_reason_code: "job_not_terminal"
    })).toBe("rustferry.job.jobs-logs-page.jobs-cancel");
    expect(jobContextValue([jobIdeCommands.logs], {
      can_cancel: false,
      cancel_reason_code: "job_terminal",
      can_retry: false,
      retry_reason_code: "job_not_retryable"
    })).toBe("rustferry.job");
  });

  it("never places job commands on artifact context values", () => {
    const value = jobArtifactContextValue(
      [
        jobIdeCommands.show,
        jobIdeCommands.artifactVerify,
        jobIdeCommands.artifactRemove,
        `${jobIdeCommands.artifactRemove}-future`
      ],
      {
        can_verify: true,
        can_reveal: false,
        reveal_reason_code: "artifact_not_downloaded",
        can_remove: false,
        remove_reason_code: "artifact_not_managed"
      }
    );
    expect(value).toBe("rustferry.jobArtifact.jobs-artifact-verify");
    expect(value).not.toContain(jobIdeCommands.show);
    expect(value).not.toContain(jobIdeCommands.artifactRemove);
  });

  it("requires both exact handshake support and current record eligibility", () => {
    expect(jobContextValue([jobIdeCommands.cancel, jobIdeCommands.retry], {
      can_cancel: false,
      cancel_reason_code: "job_terminal",
      can_retry: true
    })).toBe("rustferry.job.jobs-retry");
    expect(jobArtifactContextValue([
      jobIdeCommands.artifactVerify,
      jobIdeCommands.artifactReveal,
      jobIdeCommands.artifactRemove
    ], {
      can_verify: false,
      verify_reason_code: "verification_running",
      can_reveal: true,
      can_remove: false,
      remove_reason_code: "artifact_replaced"
    })).toBe("rustferry.jobArtifact.jobs-artifact-reveal");
  });

  it("keeps remote snapshot and readiness project actions on exact handshake tokens", () => {
    expect(jobProjectContextValue([
      remoteIdeCommands.buildPreview,
      `${remoteIdeCommands.buildSubmit}-future`,
      remoteIdeCommands.signingReadiness
    ])).toBe(
      "rustferry.jobProject.remote-build-preview.signing-readiness"
    );
  });
});
