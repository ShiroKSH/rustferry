import { describe, expect, it } from "vitest";

import {
  parseArtifactRemoveResponse,
  parseArtifactRevealResponse,
  parseArtifactVerifyResponse,
  parseCancelJobResponse,
  parseJobArtifactsResponse,
  parseJobLogsPageResponse,
  parseJobShowResponse,
  parseJobsListResponse,
  parseRemoteBuildPreviewResponse,
  parseRemoteBuildSubmissionResponse,
  parseRetryJobResponse,
  parseSigningReadinessResponse,
  ProtocolError
} from "../../src/cli/protocol.js";

const digest = "a".repeat(64);

describe("workspace-bound IDE job protocol", () => {
  it("parses bounded list, artifact, and log DTOs", () => {
    expect(parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [listJob()]
    }))).toMatchObject({
      workspace: "C:\\work\\ferry",
      jobs: [{ local_job_id: "job-1", state: "running", provider: "github" }]
    });

    expect(parseJobArtifactsResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      local_job_id: "job-1",
      revision: 4,
      artifacts: [{
        artifact_id: "artifact-1",
        kind: "xcarchive",
        file_name: "Ferry.xcarchive.zip",
        size: 42,
        sha256: digest,
        media_type: "application/zip",
        download_destination: "C:\\work\\ferry\\target\\ferry\\Ferry.xcarchive.zip",
        download_parent_identity: "volume:directory",
        local_path: "C:\\work\\ferry\\target\\ferry\\Ferry.xcarchive.zip",
        local_file_identity: "volume:file",
        locally_validated: true,
        current_status: "verified"
      }]
    }))).toMatchObject({
      local_job_id: "job-1",
      artifacts: [{ artifact_id: "artifact-1", locally_validated: true }]
    });

    const logs = parseJobLogsPageResponse(JSON.stringify(jobLogs()));
    expect(logs).toMatchObject({
      log_scope: "durable_sanitized_job_events",
      provider_full_logs: true,
      after_sequence: "0",
      next_after_sequence: "3",
      has_more: false,
      terminal: true,
      events: [
        { sequence: "1", source: "controller", code: "job.created" },
        { sequence: "2", source: "worker", code: "worker.log_line", message: "Compiling Ferry" },
        { sequence: "3", source: "worker", code: "worker.logs_complete" }
      ]
    });
    expect(logs.events[1]).toMatchObject({
      record_kind: "sanitized_lifecycle_event",
      source_sequence: "1",
      source_event_sha256: digest,
      level: "info",
      phase: "github_actions"
    });
    expect(logs.events[1]).not.toHaveProperty("raw_provider_payload");
  });

  it("rejects job lists that exceed or misstate their bounded page", () => {
    const response = {
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 1,
      returned: 1,
      jobs: [listJob()]
    };
    expect(() => parseJobsListResponse(JSON.stringify({
      ...response,
      limit: 0
    }))).toThrow(ProtocolError);
    expect(() => parseJobsListResponse(JSON.stringify({
      ...response,
      returned: 2
    }))).toThrow(ProtocolError);
  });

  it("accepts legacy and filtered job-event coverage without inferring completion from events", () => {
    expect(parseJobLogsPageResponse(JSON.stringify({
      ...jobLogs(),
      log_scope: "durable_sanitized_lifecycle_events",
      provider_full_logs: false,
      returned: 0,
      next_after_sequence: "0",
      terminal: false,
      events: []
    }))).toMatchObject({
      log_scope: "durable_sanitized_lifecycle_events",
      provider_full_logs: false
    });

    expect(parseJobLogsPageResponse(JSON.stringify({
      ...jobLogs(),
      returned: 0,
      next_after_sequence: "0",
      events: []
    }))).toMatchObject({
      log_scope: "durable_sanitized_job_events",
      provider_full_logs: true,
      events: []
    });

    expect(parseJobLogsPageResponse(JSON.stringify({
      ...jobLogs(),
      provider_full_logs: false
    }))).toMatchObject({ provider_full_logs: false });
  });

  it("rejects invalid scopes, coverage flags, event kinds, enums, and source identities", () => {
    const cases: readonly Record<string, unknown>[] = [
      { ...jobLogs(), log_scope: "provider_raw_logs" },
      { ...jobLogs(), provider_full_logs: "true" },
      {
        ...jobLogs(),
        log_scope: "durable_sanitized_lifecycle_events",
        provider_full_logs: true
      },
      jobLogsWithEvent({ record_kind: "provider_payload" }),
      jobLogsWithEvent({ source: "remote" }),
      jobLogsWithEvent({ level: "information" }),
      jobLogsWithEvent({ source_sequence: null, source_event_sha256: null }),
      jobLogsWithEvent({ source_sequence: "0" }),
      jobLogsWithEvent({ source_sequence: "18446744073709551616" }),
      jobLogsWithEvent({ source_sequence: "9".repeat(100_000) }),
      jobLogsWithEvent({ source_event_sha256: null })
    ];
    for (const value of cases) {
      expect(() => parseJobLogsPageResponse(JSON.stringify(value))).toThrow(ProtocolError);
    }
  });

  it("whitelists show fields instead of surfacing provider resume internals", () => {
    const parsed = parseJobShowResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      job: {
        ...showJob(),
        provider_resume: { access_token: "must-not-surface" },
        future_private_field: "must-not-surface"
      }
    }));
    expect(parsed.job).not.toHaveProperty("provider_resume");
    expect(parsed.job).not.toHaveProperty("future_private_field");
    expect(JSON.stringify(parsed)).not.toContain("must-not-surface");
  });

  it("rejects malformed present optional job and artifact fields", () => {
    expect(() => parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [{ ...listJob(), submitted_at_ms: "soon" }]
    }))).toThrow(ProtocolError);
    expect(() => parseJobShowResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      job: { ...showJob(), retry: { attempt: 0, parent_job_id: 7, child_job_ids: [] } }
    }))).toThrow(ProtocolError);
    expect(() => parseJobArtifactsResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      local_job_id: "job-1",
      revision: 4,
      artifacts: [{
        artifact_id: "artifact-1",
        kind: "xcarchive",
        file_name: "Ferry.xcarchive.zip",
        size: 42,
        sha256: digest,
        local_path: 7,
        locally_validated: true,
        current_status: "verified"
      }]
    }))).toThrow(ProtocolError);
  });

  it("rejects unsafe identifiers and malformed digests", () => {
    expect(() => parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [{ ...listJob(), local_job_id: "../job" }]
    }))).toThrow(ProtocolError);

    expect(() => parseJobShowResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      job: { ...showJob(), request_sha256: "not-a-digest" }
    }))).toThrow(/SHA-256/u);

    expect(() => parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [{ ...listJob(), provider_job_id: 9_007_199_254_740_992 }]
    }))).toThrow(/string/u);

    expect(() => parseJobShowResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      job: {
        ...showJob(),
        provider: {
          ...(showJob().provider as Record<string, unknown>),
          execution_repository_id: 2
        }
      }
    }))).toThrow(/string/u);
  });

  it("preserves unsigned 64-bit provider and sequence identities above JS safe integer", () => {
    const exact = "9007199254740993";
    const list = parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [{ ...listJob(), provider_job_id: exact, provider_run_id: exact }]
    }));
    expect(list.jobs[0]).toMatchObject({ provider_job_id: exact, provider_run_id: exact });

    const details = parseJobShowResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      job: {
        ...showJob(),
        provider: {
          ...(showJob().provider as Record<string, unknown>),
          principal: { kind: "user", id: exact, login: "owner" },
          execution_repository_id: exact
        }
      }
    }));
    expect(details.job.provider).toMatchObject({
      principal: { id: exact },
      execution_repository_id: exact
    });

    const logs = parseJobLogsPageResponse(JSON.stringify({
      ...jobLogs(),
      after_sequence: "9007199254740992",
      limit: 1,
      returned: 1,
      next_after_sequence: exact,
      events: [{
        record_kind: "sanitized_lifecycle_event",
        sequence: exact,
        occurred_at_ms: 1_700_000_000_000,
        source: "worker",
        source_sequence: exact,
        source_event_sha256: digest,
        level: "info",
        code: "worker.log_line"
      }]
    }));
    expect(logs).toMatchObject({
      next_after_sequence: exact,
      events: [{ sequence: exact, source_sequence: exact }]
    });
  });

  it("fails closed for absent eligibility and rejects partial or contradictory eligibility", () => {
    const legacy = parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [listJob()]
    }));
    expect(legacy.jobs[0]).toMatchObject({
      can_cancel: false,
      cancel_reason_code: "server_action_eligibility_unavailable",
      can_retry: false,
      retry_reason_code: "server_action_eligibility_unavailable"
    });

    const eligible = parseJobsListResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      limit: 50,
      returned: 1,
      jobs: [{
        ...listJob(),
        can_cancel: true,
        can_retry: false,
        retry_reason_code: "job.not_terminal"
      }]
    }));
    expect(eligible.jobs[0]).toMatchObject({
      can_cancel: true,
      can_retry: false,
      retry_reason_code: "job.not_terminal"
    });
    expect(eligible.jobs[0]).not.toHaveProperty("cancel_reason_code");

    for (const actions of [
      { can_cancel: true },
      { can_cancel: true, cancel_reason_code: "unexpected", can_retry: true },
      { can_cancel: false, can_retry: true }
    ]) {
      expect(() => parseJobsListResponse(JSON.stringify({
        protocol_version: 1,
        workspace: "C:\\work\\ferry",
        limit: 50,
        returned: 1,
        jobs: [{ ...listJob(), ...actions }]
      }))).toThrow(ProtocolError);
    }
  });

  it("parses distinct durable cancel and retry receipts and rejects same-job retries", () => {
    const cancelledParent = {
      ...showJob(),
      revision: 5,
      cancellation_status: "requested"
    };
    expect(parseCancelJobResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      parent: cancelledParent,
      receipt: {
        kind: "cancellation_requested",
        parent_local_job_id: "job-1",
        durable: true,
        revision: 5
      }
    }))).toMatchObject({ parent: { local_job_id: "job-1", revision: 5 } });

    const parent = {
      ...showJob(),
      retry: { attempt: 0, parent_job_id: null, child_job_ids: ["job-2"] }
    };
    const child = {
      ...showJob(),
      local_job_id: "job-2",
      revision: 1,
      operation_id: "operation-2",
      retry: { attempt: 1, parent_job_id: "job-1", child_job_ids: [] }
    };
    const response = {
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      parent,
      child,
      lineage: {
        parent_local_job_id: "job-1",
        child_local_job_id: "job-2",
        attempt: 1
      },
      receipt: { kind: "retry_created", disposition: "created", durable: true }
    };
    expect(parseRetryJobResponse(JSON.stringify(response))).toMatchObject({
      parent: { local_job_id: "job-1" },
      child: { local_job_id: "job-2" },
      lineage: { attempt: 1 },
      receipt: { disposition: "created" }
    });
    expect(parseRetryJobResponse(JSON.stringify({
      ...response,
      receipt: { ...response.receipt, disposition: "resumed_existing" }
    }))).toMatchObject({ receipt: { disposition: "resumed_existing" } });
    expect(() => parseRetryJobResponse(JSON.stringify({
      ...response,
      receipt: { kind: "retry_created", durable: true }
    }))).toThrow(ProtocolError);
    expect(() => parseRetryJobResponse(JSON.stringify({
      ...response,
      receipt: { ...response.receipt, disposition: "recreated" }
    }))).toThrow(ProtocolError);
    expect(() => parseRetryJobResponse(JSON.stringify({
      ...response,
      child: { ...child, local_job_id: "job-1" },
      lineage: { ...response.lineage, child_local_job_id: "job-1" }
    }))).toThrow(/lineage/u);
    expect(() => parseRetryJobResponse(JSON.stringify({
      ...response,
      child: { ...child, semantic_retry_sha256: "b".repeat(64) }
    }))).toThrow(/lineage/u);
  });

  it("preserves artifact evidence while keeping reveal receipts path-free", () => {
    expect(parseArtifactVerifyResponse(JSON.stringify({
      ...artifactActionIdentity(),
      outcome: "verified",
      evidence_level: "cross_validated",
      integrity: {
        size: "42",
        sha256: digest,
        filesystem_identity: "volume:file",
        container: { kind: "zip", entry_count: "4", expanded_size: "200" }
      },
      product: { status: "verified", kind: "unsigned_xcarchive" },
      validation_levels: ["archive_safety", "product"],
      signed_cleanup_evidence_bound: false
    }))).toMatchObject({
      outcome: "verified",
      evidence_level: "cross_validated",
      integrity: { size: "42", sha256: digest },
      product: { status: "verified", kind: "unsigned_xcarchive" }
    });

    const reveal = {
      ...artifactActionIdentity(),
      receipt: {
        launcher: "explorer.exe",
        environment_policy: "fixed_no_inheritance",
        launch_requested: true,
        exact_path_bound_during_launch: true,
        post_launch_revalidation: "passed"
      }
    };
    expect(parseArtifactRevealResponse(JSON.stringify(reveal))).toMatchObject({
      status: "revealed",
      receipt: { post_launch_revalidation: "passed" }
    });
    expect(() => parseArtifactRevealResponse(JSON.stringify({
      ...reveal,
      path: "C:\\work\\ferry\\artifact.zip"
    }))).toThrow(/not a path/u);
    expect(() => parseArtifactRevealResponse(JSON.stringify({
      ...reveal,
      receipt: { ...reveal.receipt, local_path: "C:\\work\\ferry\\artifact.zip" }
    }))).toThrow(/not a path/u);
    expect(parseArtifactRevealResponse(JSON.stringify({
      ...reveal,
      receipt: { ...reveal.receipt, exact_path_bound_during_launch: false }
    }))).toMatchObject({
      receipt: { exact_path_bound_during_launch: false, post_launch_revalidation: "passed" }
    });

    expect(parseArtifactRemoveResponse(JSON.stringify({
      ...artifactActionIdentity(),
      receipt: {
        confirmation_provided: true,
        executed: false,
        result_state: "replacement_preserved",
        already_complete: false,
        replacement_preserved: true
      }
    }))).toMatchObject({
      status: "replacement_preserved",
      replacement_preserved: true
    });
  });

  it("parses snapshot consent, durable submission, and sanitized signing readiness", () => {
    const preview = parseRemoteBuildPreviewResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      provider: "github",
      target: "ios-device",
      profile: "release",
      signing_mode: "unsigned",
      source_mode: "snapshot",
      preview_sha256: digest,
      consent_token: "c".repeat(32),
      source: { manifest_sha256: digest, file_count: "12", total_bytes: "4096" },
      effects: ["create_private_snapshot", "submit_remote_job"],
      consent_required: true
    }));
    expect(preview).toMatchObject({
      source_mode: "snapshot",
      source: { file_count: "12", total_bytes: "4096" },
      consent_required: true
    });

    expect(parseRemoteBuildSubmissionResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      job: showJob(),
      receipt: {
        kind: "remote_build_submitted",
        durable: true,
        source_mode: "snapshot",
        preview_sha256: digest
      }
    }))).toMatchObject({ receipt: { durable: true, preview_sha256: digest } });

    const readiness = parseSigningReadinessResponse(JSON.stringify({
      protocol_version: 1,
      workspace: "C:\\work\\ferry",
      provider: "github",
      target: "ios-device",
      mode: "github_actions_ios_signing",
      ready: false,
      checks: [
        { code: "github.authentication", required: true, ready: true },
        {
          code: "apple.signing_certificate",
          required: true,
          ready: false,
          reason_code: "credential.not_configured"
        }
      ]
    }));
    expect(readiness).toMatchObject({ ready: false, checks: [{ ready: true }, { ready: false }] });
    expect(JSON.stringify(readiness)).not.toMatch(/token|password|private_key/u);
  });
});

function artifactActionIdentity(): Record<string, unknown> {
  return {
    protocol_version: 1,
    workspace: "C:\\work\\ferry",
    local_job_id: "job-1",
    artifact_id: "artifact-1",
    revision: 4
  };
}

function listJob(): Record<string, unknown> {
  return {
    local_job_id: "job-1",
    revision: 4,
    provider: "github",
    provider_job_id: "101",
    provider_run_id: "201",
    operation_id: "operation-1",
    app_label: "Ferry",
    application_identifier: "com.example.ferry",
    target: "aarch64-apple-ios",
    profile: "release",
    signing_mode: "unsigned-compile-only",
    created_at_ms: 1_700_000_000_000,
    submitted_at_ms: 1_700_000_000_100,
    updated_at_ms: 1_700_000_000_200,
    state: "running",
    last_confirmed_state: "running",
    terminal_outcome: null,
    cleanup_status: "pending",
    cancellation_status: "none"
  };
}

function showJob(): Record<string, unknown> {
  return {
    local_job_id: "job-1",
    revision: 4,
    provider: {
      name: "github",
      config_sha256: digest,
      principal: { kind: "user", id: "1", login: "owner" },
      execution_repository_id: "2"
    },
    provider_job_id: "101",
    provider_run_id: "201",
    operation_id: "operation-1",
    request_sha256: digest,
    semantic_retry_sha256: digest,
    application_identifier: "com.example.ferry",
    source_revision: "b".repeat(40),
    source_manifest_sha256: digest,
    target: "aarch64-apple-ios",
    profile: "release",
    signing_mode: "unsigned-compile-only",
    created_at_ms: 1_700_000_000_000,
    submitted_at_ms: 1_700_000_000_100,
    updated_at_ms: 1_700_000_000_200,
    state: "running",
    last_confirmed_state: "running",
    terminal_outcome: null,
    cleanup_status: "pending",
    cancellation_status: "none",
    retry: { attempt: 0, parent_job_id: null, child_job_ids: [] },
    failure: null,
    artifact_count: 1,
    event_journal_bound: true,
    provider_resume_available: true
  };
}

function jobLogs(): Record<string, unknown> {
  return {
    protocol_version: 1,
    workspace: "C:\\work\\ferry",
    local_job_id: "job-1",
    log_scope: "durable_sanitized_job_events",
    provider_full_logs: true,
    after_sequence: "0",
    phase: null,
    limit: 3,
    returned: 3,
    next_after_sequence: "3",
    has_more: false,
    terminal: true,
    events: [
      {
        record_kind: "sanitized_lifecycle_event",
        sequence: "1",
        occurred_at_ms: 1_700_000_000_000,
        phase: null,
        source: "controller",
        source_sequence: null,
        source_event_sha256: null,
        level: "info",
        code: "job.created",
        message: "Job created"
      },
      {
        record_kind: "sanitized_lifecycle_event",
        sequence: "2",
        occurred_at_ms: 1_700_000_000_100,
        phase: "github_actions",
        source: "worker",
        source_sequence: "1",
        source_event_sha256: digest,
        level: "info",
        code: "worker.log_line",
        message: "Compiling Ferry",
        raw_provider_payload: "must-not-surface"
      },
      {
        record_kind: "sanitized_lifecycle_event",
        sequence: "3",
        occurred_at_ms: 1_700_000_000_200,
        phase: "github_actions",
        source: "worker",
        source_sequence: "2",
        source_event_sha256: "b".repeat(64),
        level: "info",
        code: "worker.logs_complete",
        message: "Sanitized worker-log ingestion complete"
      }
    ]
  };
}

function jobLogsWithEvent(overrides: Record<string, unknown>): Record<string, unknown> {
  const value = jobLogs();
  const events = value.events as Record<string, unknown>[];
  return {
    ...value,
    limit: 1,
    returned: 1,
    next_after_sequence: "2",
    events: [{ ...events[1], ...overrides }]
  };
}
