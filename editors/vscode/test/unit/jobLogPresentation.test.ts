import { describe, expect, it } from "vitest";

import type { JobLogEvent } from "../../src/cli/protocol.js";
import {
  jobLogCoveragePresentation,
  jobLogEmptyText,
  jobLogScopeNotice,
  jobLogTreePresentation,
  renderJobLogEvent
} from "../../src/jobs/logPresentation.js";

const digest = "a".repeat(64);

describe("durable sanitized job-event presentation", () => {
  it("distinguishes legacy, incomplete, and complete sanitized coverage", () => {
    const legacy = {
      log_scope: "durable_sanitized_lifecycle_events" as const,
      provider_full_logs: false
    };
    const incomplete = {
      log_scope: "durable_sanitized_job_events" as const,
      provider_full_logs: false
    };
    const complete = {
      log_scope: "durable_sanitized_job_events" as const,
      provider_full_logs: true
    };

    expect(jobLogCoveragePresentation(legacy)).toMatchObject({
      label: "Sanitized lifecycle events",
      description: "worker-log coverage unavailable",
      icon: "info"
    });
    expect(jobLogCoveragePresentation(incomplete)).toMatchObject({
      label: "Sanitized job events",
      description: "worker-log coverage incomplete",
      icon: "info"
    });
    expect(jobLogCoveragePresentation(complete)).toMatchObject({
      label: "Sanitized job events",
      description: "worker-log coverage complete",
      icon: "verified-filled"
    });
    expect(jobLogEmptyText(legacy)).toContain("sanitized lifecycle events");
    expect(jobLogEmptyText(complete)).toContain("sanitized job events");

    const notices = [
      jobLogScopeNotice(legacy),
      jobLogScopeNotice(incomplete),
      jobLogScopeNotice(complete)
    ];
    expect(new Set(notices).size).toBe(3);
    for (const notice of notices) {
      expect(notice).toContain("sanitized");
      expect(notice).not.toMatch(/\braw\b/iu);
    }
  });

  it("renders lifecycle, worker-line, and completion records with their provenance", () => {
    const lifecycle = event({
      sequence: "1",
      source: "controller",
      code: "job.created",
      message: "Job created"
    });
    const workerLine = event({
      sequence: "2",
      source: "worker",
      source_sequence: "1",
      source_event_sha256: digest,
      phase: "github_actions",
      code: "worker.log_line",
      message: "Compiling Ferry"
    });
    const completion = event({
      sequence: "3",
      source: "worker",
      source_sequence: "2",
      source_event_sha256: "b".repeat(64),
      phase: "github_actions",
      code: "worker.logs_complete",
      message: "Sanitized worker-log ingestion complete"
    });

    expect(renderJobLogEvent(lifecycle)).toContain("[controller] info job.created Job created");
    expect(renderJobLogEvent(workerLine)).toContain(
      "[worker] info [github_actions] worker.log_line Compiling Ferry"
    );
    expect(renderJobLogEvent(completion)).toContain("[worker] info [github_actions] worker.logs_complete");

    const lifecycleTree = jobLogTreePresentation(lifecycle);
    expect(lifecycleTree).toMatchObject({
      label: "job.created",
      icon: "output"
    });
    expect(lifecycleTree.description).toContain("controller | info");
    const workerTree = jobLogTreePresentation(workerLine);
    expect(workerTree.label).toBe("worker.log_line");
    expect(workerTree.description).toContain("worker | info");
    expect(workerTree.tooltip).toContain("Source sequence: 1");
    expect(jobLogTreePresentation(completion)).toMatchObject({
      label: "worker.logs_complete",
      icon: "pass-filled"
    });
  });

  it("flattens line separators in server-provided sanitized text before display", () => {
    const value = event({
      source: "worker",
      source_sequence: "1",
      source_event_sha256: digest,
      phase: "github_actions\r\nforged",
      code: "worker.log_line",
      message: "line one\r\nline two\tline three\u2028line four\u2029line five"
    });
    const rendered = renderJobLogEvent(value);
    expect(rendered).not.toMatch(/[\r\n\t\u2028\u2029]/u);
    expect(rendered).toContain("line one line two line three line four line five");
    expect(jobLogTreePresentation(value).tooltip).not.toMatch(/[\r\t\u2028\u2029]/u);
  });

  it("preserves the complete bounded server message instead of silently truncating it", () => {
    const message = `prefix-${"x".repeat(2_048)}-suffix`;
    const value = event({ message });

    expect(renderJobLogEvent(value)).toContain(message);
    expect(jobLogTreePresentation(value).tooltip).toContain(message);
  });
});

function event(overrides: Partial<JobLogEvent>): JobLogEvent {
  return {
    record_kind: "sanitized_lifecycle_event",
    sequence: "1",
    occurred_at_ms: 1_700_000_000_000,
    source: "controller",
    level: "info",
    code: "job.created",
    ...overrides
  };
}
