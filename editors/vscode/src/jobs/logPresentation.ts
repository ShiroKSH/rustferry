import type { JobLogEvent, JobLogsPageResponse } from "../cli/protocol.js";

type JobLogCoverage = Pick<JobLogsPageResponse, "log_scope" | "provider_full_logs">;

export type JobLogTreePresentation = Readonly<{
  label: string;
  description: string;
  tooltip: string;
  icon: "error" | "output" | "pass-filled" | "warning";
}>;

export type JobLogCoveragePresentation = Readonly<{
  label: string;
  description: string;
  tooltip: string;
  icon: "info" | "verified-filled";
}>;

export function jobLogScopeNotice(coverage: JobLogCoverage): string {
  if (coverage.log_scope === "durable_sanitized_lifecycle_events") {
    return "Durable sanitized lifecycle events only. Sanitized provider worker-log coverage: unavailable.";
  }
  return coverage.provider_full_logs
    ? "Durable sanitized job events. Sanitized provider worker-log coverage: complete."
    : "Durable sanitized job events. Sanitized provider worker-log coverage: incomplete.";
}

export function jobLogEmptyText(coverage: JobLogCoverage): string {
  return coverage.log_scope === "durable_sanitized_lifecycle_events"
    ? "No durable sanitized lifecycle events recorded."
    : "No durable sanitized job events recorded.";
}

export function jobLogCoveragePresentation(
  coverage: JobLogCoverage
): JobLogCoveragePresentation {
  if (coverage.log_scope === "durable_sanitized_lifecycle_events") {
    return {
      label: "Sanitized lifecycle events",
      description: "worker-log coverage unavailable",
      tooltip: jobLogScopeNotice(coverage),
      icon: "info"
    };
  }
  return {
    label: "Sanitized job events",
    description: coverage.provider_full_logs
      ? "worker-log coverage complete"
      : "worker-log coverage incomplete",
    tooltip: jobLogScopeNotice(coverage),
    icon: coverage.provider_full_logs ? "verified-filled" : "info"
  };
}

export function renderJobLogEvent(event: JobLogEvent): string {
  const phase = event.phase === undefined ? "" : ` [${displayText(event.phase)}]`;
  const message = event.message === undefined ? "" : ` ${displayText(event.message)}`;
  return `${formatTimestamp(event.occurred_at_ms)} #${event.sequence} [${event.source}] ${event.level}${phase} ${displayText(event.code)}${message}`;
}

export function jobLogTreePresentation(event: JobLogEvent): JobLogTreePresentation {
  const details = [
    `Sequence: ${event.sequence}`,
    `Source: ${event.source}`,
    event.source_sequence === undefined ? undefined : `Source sequence: ${event.source_sequence}`,
    event.source_event_sha256 === undefined
      ? undefined
      : `Source event SHA-256: ${event.source_event_sha256}`,
    event.phase === undefined ? undefined : `Phase: ${displayText(event.phase)}`,
    `Level: ${event.level}`,
    `Code: ${displayText(event.code)}`,
    event.message === undefined ? undefined : displayText(event.message)
  ].filter((value): value is string => value !== undefined);
  return {
    label: displayText(event.code),
    description: `${event.source} | ${event.level} | ${formatTimestamp(event.occurred_at_ms)}`,
    tooltip: details.join("\n"),
    icon: event.source === "worker" && event.code === "worker.logs_complete"
      ? "pass-filled"
      : logIcon(event.level)
  };
}

function displayText(value: string): string {
  return value.replaceAll(/[\r\n\t\u2028\u2029]+/gu, " ").trim();
}

function formatTimestamp(timestampMs: number): string {
  const date = new Date(timestampMs);
  return Number.isNaN(date.valueOf()) ? String(timestampMs) : date.toISOString();
}

function logIcon(level: JobLogEvent["level"]): JobLogTreePresentation["icon"] {
  if (level === "error") {
    return "error";
  }
  if (level === "warning") {
    return "warning";
  }
  return "output";
}
