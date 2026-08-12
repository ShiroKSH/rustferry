import { StringDecoder } from "node:string_decoder";

import { PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION, PROTOCOL_VERSION } from "../constants.js";

export type BuildPlatform = "android" | "ios-simulator" | "ios-device";
export type BuildProfile = "debug" | "release";
export type Severity = "error" | "warning" | "information" | "hint";

export type ProtocolPosition = Readonly<{
  line: number;
  character: number;
}>;

export type ProtocolRange = Readonly<{
  start: ProtocolPosition;
  end: ProtocolPosition;
}>;

export type ProtocolTextEdit = Readonly<{
  file: string;
  range: ProtocolRange;
  new_text: string;
}>;

export type ProtocolFix = Readonly<{
  title: string;
  kind: string;
  edit?: ProtocolTextEdit;
  text_edit?: ProtocolTextEdit;
}>;

export type ProtocolDiagnostic = Readonly<{
  severity: Severity;
  code: string;
  message: string;
  file: string;
  range: ProtocolRange;
  help?: string;
  documentation?: string;
  fixes: readonly ProtocolFix[];
}>;

export type Handshake = Readonly<{
  protocol_version: number;
  tool: Readonly<{ name: string; version: string }>;
  host: Readonly<{ os: string; arch: string }>;
  supported_protocol_versions: readonly number[];
  supported_platforms: readonly string[];
  supported_commands: readonly string[];
  supported_event_types: readonly string[];
  features: Readonly<{
    android_build: boolean;
    ios_simulator_build: boolean;
    devices: boolean;
    install: boolean;
    run: boolean;
    logs: boolean;
    physical_ios: boolean;
    cancellation: boolean;
  }>;
  build: Readonly<{
    profile: string;
    target: string;
    development: boolean;
    git_commit?: string;
  }>;
  runtime_dependency: Readonly<{
    usable: boolean;
    source: string;
  }>;
  templates: readonly ProtocolTemplate[];
}>;

export type ProtocolProject = Readonly<{
  root: string;
  config_path: string;
  target_directory: string;
  display_name: string;
  crate_name: string;
  identifier: string;
  version: string;
  platforms: readonly string[];
  capabilities: readonly string[];
  artifacts?: readonly ProtocolArtifact[];
}>;

export type ProjectResponse = Readonly<{
  protocol_version: number;
  project: ProtocolProject;
  templates: readonly ProtocolTemplate[];
}>;

export type ProtocolTemplate = Readonly<{
  id: string;
  description: string;
}>;

export type ValidationResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  valid: boolean;
  diagnostics: readonly ProtocolDiagnostic[];
}>;

export type SigningTeam = Readonly<{
  team_id: string;
  identity: string;
  certificate_fingerprint: string;
}>;

export type SigningTeamsResponse = Readonly<{
  protocol_version: number;
  teams: readonly SigningTeam[];
}>;

export type ProtocolDevice = Readonly<{
  id: string;
  name: string;
  platform: string;
  kind: string;
  state: string;
  os_version?: string;
  architecture?: string;
  transport?: string;
  paired?: boolean;
  trusted?: boolean;
  capabilities?: Readonly<{
    build: boolean;
    install: boolean;
    launch: boolean;
    logs: boolean;
  }>;
  supports_build?: boolean;
  supports_install?: boolean;
  supports_launch?: boolean;
  supports_logs?: boolean;
  details?: Readonly<Record<string, unknown>>;
}>;

export type ProtocolArtifact = Readonly<{
  platform: string;
  kind: string;
  path: string;
  package_identifier: string;
  architectures: readonly string[];
  profile: string;
  validation: Readonly<Record<string, unknown>>;
  size_bytes?: number;
  built_at?: string;
}>;

export type DecimalString = string;

export type JobActionEligibility = Readonly<{
  can_cancel: boolean;
  cancel_reason_code?: string;
  can_retry: boolean;
  retry_reason_code?: string;
}>;

export type ArtifactActionEligibility = Readonly<{
  can_verify: boolean;
  verify_reason_code?: string;
  can_reveal: boolean;
  reveal_reason_code?: string;
  can_remove: boolean;
  remove_reason_code?: string;
}>;

export type JobListItem = Readonly<{
  local_job_id: string;
  revision: number;
  provider: string;
  provider_job_id?: DecimalString;
  provider_run_id?: DecimalString;
  operation_id: string;
  app_label: string;
  application_identifier: string;
  target: string;
  profile: string;
  signing_mode: string;
  created_at_ms: number;
  submitted_at_ms?: number;
  updated_at_ms: number;
  state: string;
  last_confirmed_state?: string;
  terminal_outcome?: string;
  cleanup_status: string;
  cancellation_status: string;
}> & JobActionEligibility;

export type JobPrincipal =
  | Readonly<{ kind: "user"; id: DecimalString; login: string }>
  | Readonly<{ kind: "repository_credential" }>;

export type JobDetails = Readonly<{
  local_job_id: string;
  revision: number;
  provider: Readonly<{
    name: string;
    config_sha256: string;
    principal: JobPrincipal;
    execution_repository_id: DecimalString;
  }>;
  provider_job_id?: DecimalString;
  provider_run_id?: DecimalString;
  operation_id: string;
  request_sha256: string;
  semantic_retry_sha256: string;
  application_identifier: string;
  source_revision?: string;
  source_manifest_sha256: string;
  target: string;
  profile: string;
  signing_mode: string;
  created_at_ms: number;
  submitted_at_ms?: number;
  updated_at_ms: number;
  state: string;
  last_confirmed_state?: string;
  terminal_outcome?: string;
  cleanup_status: string;
  cancellation_status: string;
  retry: Readonly<{
    attempt: number;
    parent_job_id?: string;
    child_job_ids: readonly string[];
  }>;
  failure?: Readonly<{
    code: string;
    retryable: boolean;
  }>;
  artifact_count: number;
  event_journal_bound: boolean;
  provider_resume_available: boolean;
}> & JobActionEligibility;

export type JobArtifact = Readonly<{
  artifact_id: string;
  kind: string;
  file_name: string;
  size: number;
  sha256: string;
  media_type?: string;
  download_destination?: string;
  download_parent_identity?: string;
  local_path?: string;
  local_file_identity?: string;
  locally_validated: boolean;
  current_status: string;
}> & ArtifactActionEligibility;

export type JobLogSource = "controller" | "provider" | "worker";

export type JobLogLevel = "info" | "warning" | "error";

export type JobLogScope =
  | "durable_sanitized_lifecycle_events"
  | "durable_sanitized_job_events";

export type JobLogEvent = Readonly<{
  record_kind: "sanitized_lifecycle_event";
  sequence: DecimalString;
  occurred_at_ms: number;
  phase?: string;
  source: JobLogSource;
  source_sequence?: DecimalString;
  source_event_sha256?: string;
  level: JobLogLevel;
  code: string;
  message?: string;
}>;

export type LegacyJobLogEvent = Readonly<{
  record_kind: "sanitized_lifecycle_event";
  sequence: number;
  occurred_at_ms: number;
  phase?: string;
  source: JobLogSource;
  source_sequence?: number;
  source_event_sha256?: string;
  level: JobLogLevel;
  code: string;
  message?: string;
}>;

export type JobsListResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  limit: number;
  returned: number;
  jobs: readonly JobListItem[];
}>;

export type JobShowResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  job: JobDetails;
}>;

export type JobArtifactsResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  revision: number;
  artifacts: readonly JobArtifact[];
}>;

export type JobLogsPageRequest = Readonly<{
  afterSequence?: DecimalString;
  limit?: number;
  refresh?: boolean;
  waitForEvents?: boolean;
  phase?: string;
}>;

export type JobLogsPageResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  log_scope: JobLogScope;
  provider_full_logs: boolean;
  after_sequence: DecimalString;
  phase?: string;
  limit: number;
  returned: number;
  next_after_sequence: DecimalString;
  has_more: boolean;
  terminal: boolean;
  events: readonly JobLogEvent[];
}>;

export type LegacyJobLogsSnapshotResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  log_scope: JobLogScope;
  provider_full_logs: boolean;
  since_ms: number;
  phase?: string;
  returned: number;
  next_sequence: number;
  terminal: boolean;
  events: readonly LegacyJobLogEvent[];
}>;

export type CancelJobResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  parent: JobDetails;
  receipt: Readonly<{
    kind: "cancellation_requested";
    parent_local_job_id: string;
    durable: true;
    revision: number;
  }>;
}>;

export type RetryJobResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  parent: JobDetails;
  child: JobDetails;
  lineage: Readonly<{
    parent_local_job_id: string;
    child_local_job_id: string;
    attempt: number;
  }>;
  receipt: Readonly<{
    kind: "retry_created";
    disposition: "created" | "resumed_existing";
    durable: true;
  }>;
}>;

export type ArtifactIntegrityEvidence = Readonly<{
  size: DecimalString;
  sha256: string;
  filesystem_identity: string;
  container:
    | Readonly<{ kind: "opaque" }>
    | Readonly<{
        kind: "zip";
        entry_count: DecimalString;
        expanded_size: DecimalString;
      }>;
}>;

export type ArtifactProductEvidence =
  | Readonly<{
      status: "verified";
      kind: "unsigned_xcarchive" | "ipa" | "signed_artifact_set";
    }>
  | Readonly<{ status: "not_applicable" }>
  | Readonly<{ status: "evidence_unavailable"; reason_code: string }>;

export type ArtifactVerifyResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  artifact_id: string;
  revision: number;
  outcome: "verified" | "evidence_unavailable";
  evidence_level: "integrity" | "archive_safety" | "product" | "cross_validated";
  integrity: ArtifactIntegrityEvidence;
  product: ArtifactProductEvidence;
  validation_levels: readonly string[];
  signed_cleanup_evidence_bound: boolean;
  status: "verified" | "evidence_unavailable";
}>;

export type ArtifactRevealResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  artifact_id: string;
  revision: number;
  receipt: Readonly<{
    launcher: string;
    environment_policy: "fixed_no_inheritance";
    launch_requested: true;
    exact_path_bound_during_launch: boolean;
    post_launch_revalidation: "passed";
  }>;
  status: "revealed";
}>;

export type ArtifactRemoveResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  artifact_id: string;
  revision: number;
  receipt: Readonly<{
    confirmation_provided: true;
    executed: boolean;
    result_state: "removed" | "already_removed" | "replacement_preserved";
    already_complete: boolean;
    replacement_preserved: boolean;
  }>;
  status: "removed" | "already_removed" | "replacement_preserved";
  replacement_preserved: boolean;
}>;

export type RemoteBuildPreviewRequest = Readonly<{
  profile: BuildProfile;
}>;

export type RemoteBuildPreviewResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  provider: "github";
  target: "ios-device";
  profile: BuildProfile;
  signing_mode: "unsigned";
  source_mode: "snapshot";
  preview_sha256: string;
  consent_token: string;
  source: Readonly<{
    manifest_sha256: string;
    file_count: DecimalString;
    total_bytes: DecimalString;
  }>;
  effects: readonly string[];
  consent_required: true;
}>;

export type RemoteBuildConsent = Readonly<{
  consent_token: string;
  preview_sha256: string;
  approved: true;
}>;

export type RemoteBuildSubmissionResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  job: JobDetails;
  receipt: Readonly<{
    kind: "remote_build_submitted";
    durable: true;
    source_mode: "snapshot";
    preview_sha256: string;
  }>;
}>;

export type SigningReadinessCheck = Readonly<{
  code: string;
  required: boolean;
  ready: boolean;
  reason_code?: string;
}>;

export type SigningReadinessResponse = Readonly<{
  protocol_version: number;
  workspace: string;
  provider: "github";
  target: "ios-device";
  mode: "github_actions_ios_signing";
  ready: boolean;
  checks: readonly SigningReadinessCheck[];
}>;

export function deviceMatchesBuildPlatform(
  device: ProtocolDevice,
  platform: BuildPlatform
): boolean {
  if (platform === "android") {
    return device.kind === "android_physical" || device.kind === "android_emulator";
  }
  return platform === "ios-simulator"
    ? device.kind === "ios_simulator"
    : device.kind === "ios_physical";
}

export function artifactBuildPlatform(
  artifact: ProtocolArtifact
): BuildPlatform | undefined {
  if (artifact.platform === "android") {
    return "android";
  }
  if (artifact.platform === "ios-simulator") {
    return "ios-simulator";
  }
  if (artifact.platform === "ios-device") {
    return "ios-device";
  }
  return undefined;
}

export type DeviceSnapshotResponse = Readonly<{
  protocol_version: number;
  devices: readonly ProtocolDevice[];
  warnings: readonly Readonly<{ code: string; source: string; message: string }>[];
  devicectl: Readonly<{
    available: boolean;
    json_output: boolean;
    install: boolean;
    launch: boolean;
    logs: boolean;
  }>;
}>;

export type CommonEvent = Readonly<{
  protocol_version: number;
  event: string;
  operation_id: string;
  timestamp_ms: number;
  parent_operation_id?: string;
}>;

export type ProtocolEvent = CommonEvent & Readonly<Record<string, unknown>>;

export type LegacyJsonSuccess<T> = Readonly<{
  schema_version: number;
  command: string;
  status: "ok";
  data: T;
  warnings: readonly string[];
}>;

export type LegacyJsonError = Readonly<{
  schema_version: number;
  command: string | null;
  status: "error";
  error: Readonly<{
    code: string;
    message: string;
    help?: string | null;
    details?: readonly string[];
  }>;
}>;

export class ProtocolError extends Error {
  public constructor(message: string, readonly code = "protocol.invalid") {
    super(message);
    this.name = "ProtocolError";
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseJsonObject(source: string, context: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch (error) {
    throw new ProtocolError(`${context} returned invalid JSON: ${errorMessage(error)}`);
  }
  if (!isRecord(value)) {
    throw new ProtocolError(`${context} returned JSON that was not an object.`);
  }
  return value;
}

export function assertProtocolVersion(value: Record<string, unknown>, context: string): void {
  const version = value.protocol_version;
  if (version !== PROTOCOL_VERSION) {
    const installed = typeof version === "number" ? String(version) : "missing";
    throw new ProtocolError(
      `${context} uses IDE protocol ${installed}; this extension requires ${PROTOCOL_MIN_VERSION}–${PROTOCOL_MAX_VERSION}.`,
      "protocol.incompatible"
    );
  }
}

export function parseHandshake(source: string): Handshake {
  const value = parseJsonObject(source, "cargo-ferry handshake");
  assertProtocolVersion(value, "cargo-ferry handshake");
  const tool = requireRecord(value.tool, "handshake.tool");
  const host = requireRecord(value.host, "handshake.host");
  const features = requireRecord(value.features, "handshake.features");
  const build = requireRecord(value.build, "handshake.build");
  const runtime = requireRecord(value.runtime_dependency, "handshake.runtime_dependency");
  return {
    protocol_version: PROTOCOL_VERSION,
    tool: {
      name: requireString(tool.name, "handshake.tool.name"),
      version: requireString(tool.version, "handshake.tool.version")
    },
    host: {
      os: requireString(host.os, "handshake.host.os"),
      arch: requireString(host.arch, "handshake.host.arch")
    },
    supported_protocol_versions: requireNumberArray(value.supported_protocol_versions, "handshake.supported_protocol_versions"),
    supported_platforms: requireStringArray(value.supported_platforms, "handshake.supported_platforms"),
    supported_commands: requireStringArray(value.supported_commands, "handshake.supported_commands"),
    supported_event_types: requireStringArray(value.supported_event_types, "handshake.supported_event_types"),
    features: {
      android_build: requireBoolean(features.android_build, "handshake.features.android_build"),
      ios_simulator_build: requireBoolean(features.ios_simulator_build, "handshake.features.ios_simulator_build"),
      devices: requireBoolean(features.devices, "handshake.features.devices"),
      install: requireBoolean(features.install, "handshake.features.install"),
      run: requireBoolean(features.run, "handshake.features.run"),
      logs: requireBoolean(features.logs, "handshake.features.logs"),
      physical_ios: requireBoolean(features.physical_ios, "handshake.features.physical_ios"),
      cancellation: requireBoolean(features.cancellation, "handshake.features.cancellation")
    },
    build: {
      profile: requireString(build.profile, "handshake.build.profile"),
      target: requireString(build.target, "handshake.build.target"),
      development: requireBoolean(build.development, "handshake.build.development"),
      ...(typeof build.git_commit === "string" ? { git_commit: build.git_commit } : {})
    },
    runtime_dependency: {
      usable: requireBoolean(runtime.usable, "handshake.runtime_dependency.usable"),
      source: requireString(runtime.source, "handshake.runtime_dependency.source")
    },
    templates: requireArray(value.templates, "handshake.templates").map((template, index) => {
      const metadata = requireRecord(template, `handshake.templates[${index}]`);
      return {
        id: requireString(metadata.id, `handshake.templates[${index}].id`),
        description: requireString(metadata.description, `handshake.templates[${index}].description`)
      };
    })
  };
}

export function parseProjectResponse(source: string): ProjectResponse {
  const value = parseJsonObject(source, "cargo-ferry project");
  assertProtocolVersion(value, "cargo-ferry project");
  const project = requireRecord(value.project, "project.project");
  const capabilities = requireStringArray(project.capabilities, "project.capabilities");
  const artifacts = Array.isArray(project.artifacts)
    ? project.artifacts.map((artifact, index) => parseArtifact(requireRecord(artifact, `project.artifacts[${index}]`)))
    : undefined;
  return {
    protocol_version: PROTOCOL_VERSION,
    project: {
      root: requireString(project.root, "project.root"),
      config_path: requireString(project.config_path, "project.config_path"),
      target_directory: requireString(project.target_directory, "project.target_directory"),
      display_name: requireString(project.display_name, "project.display_name"),
      crate_name: requireString(project.crate_name, "project.crate_name"),
      identifier: requireString(project.identifier, "project.identifier"),
      version: requireString(project.version, "project.version"),
      platforms: requireStringArray(project.platforms, "project.platforms"),
      capabilities,
      ...(artifacts === undefined ? {} : { artifacts })
    },
    templates: requireArray(value.templates, "project.templates").map((template, index) => {
      const metadata = requireRecord(template, `project.templates[${index}]`);
      return {
        id: requireString(metadata.id, `project.templates[${index}].id`),
        description: requireString(metadata.description, `project.templates[${index}].description`)
      };
    })
  };
}

export function parseValidationResponse(source: string): ValidationResponse {
  const value = parseJsonObject(source, "cargo-ferry validate");
  assertProtocolVersion(value, "cargo-ferry validate");
  const values = requireArray(value.diagnostics, "validate.diagnostics");
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requireString(value.workspace, "validate.workspace"),
    valid: requireBoolean(value.valid, "validate.valid"),
    diagnostics: values.map((diagnostic, index) => parseDiagnostic(requireRecord(diagnostic, `validate.diagnostics[${index}]`)))
  };
}

export function parseSigningTeamsResponse(source: string): SigningTeamsResponse {
  const value = parseJsonObject(source, "cargo-ferry signing teams");
  assertProtocolVersion(value, "cargo-ferry signing teams");
  return {
    protocol_version: PROTOCOL_VERSION,
    teams: requireArray(value.teams, "signing-teams.teams").map((team, index) => {
      const item = requireRecord(team, `signing-teams.teams[${index}]`);
      return {
        team_id: requireString(item.team_id, `signing-teams.teams[${index}].team_id`),
        identity: requireString(item.identity, `signing-teams.teams[${index}].identity`),
        certificate_fingerprint: requireString(
          item.certificate_fingerprint,
          `signing-teams.teams[${index}].certificate_fingerprint`
        )
      };
    })
  };
}

export function parseDeviceSnapshotResponse(source: string): DeviceSnapshotResponse {
  const value = parseJsonObject(source, "cargo-ferry devices");
  assertProtocolVersion(value, "cargo-ferry devices");
  const devicectl = requireRecord(value.devicectl, "devices.devicectl");
  return {
    protocol_version: PROTOCOL_VERSION,
    devices: requireArray(value.devices, "devices.devices").map((device, index) => parseDevice(requireRecord(device, `devices.devices[${index}]`))),
    warnings: requireArray(value.warnings, "devices.warnings").map((warning, index) => {
      const item = requireRecord(warning, `devices.warnings[${index}]`);
      return {
        code: requireString(item.code, `devices.warnings[${index}].code`),
        source: requireString(item.source, `devices.warnings[${index}].source`),
        message: requireString(item.message, `devices.warnings[${index}].message`)
      };
    }),
    devicectl: {
      available: requireBoolean(devicectl.available, "devices.devicectl.available"),
      json_output: requireBoolean(devicectl.json_output, "devices.devicectl.json_output"),
      install: requireBoolean(devicectl.install, "devices.devicectl.install"),
      launch: requireBoolean(devicectl.launch, "devices.devicectl.launch"),
      logs: requireBoolean(devicectl.logs, "devices.devicectl.logs")
    }
  };
}

export function parseJobsListResponse(source: string): JobsListResponse {
  const value = parseJobResponse(source, "cargo-ferry jobs-list");
  const jobs = requireArray(value.jobs, "jobs-list.jobs").map((job, index) =>
    parseJobListItem(requireRecord(job, `jobs-list.jobs[${index}]`), `jobs-list.jobs[${index}]`)
  );
  const returned = requireNonNegativeInteger(value.returned, "jobs-list.returned");
  const limit = requireBoundedPageLimit(value.limit, "jobs-list.limit");
  if (returned !== jobs.length || returned > limit) {
    throw new ProtocolError(
      "jobs-list.returned must match jobs-list.jobs length without exceeding jobs-list.limit."
    );
  }
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, "jobs-list.workspace"),
    limit,
    returned,
    jobs
  };
}

export function parseJobShowResponse(source: string): JobShowResponse {
  const value = parseJobResponse(source, "cargo-ferry jobs-show");
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, "jobs-show.workspace"),
    job: parseJobDetails(requireRecord(value.job, "jobs-show.job"), "jobs-show.job")
  };
}

export function parseJobArtifactsResponse(source: string): JobArtifactsResponse {
  const value = parseJobResponse(source, "cargo-ferry jobs-artifacts");
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, "jobs-artifacts.workspace"),
    local_job_id: requireSafeIdentifier(value.local_job_id, "jobs-artifacts.local_job_id"),
    revision: requireNonNegativeInteger(value.revision, "jobs-artifacts.revision"),
    artifacts: requireArray(value.artifacts, "jobs-artifacts.artifacts").map((artifact, index) =>
      parseJobArtifact(
        requireRecord(artifact, `jobs-artifacts.artifacts[${index}]`),
        `jobs-artifacts.artifacts[${index}]`
      )
    )
  };
}

export function parseLegacyJobLogsSnapshotResponse(
  source: string
): LegacyJobLogsSnapshotResponse {
  const value = parseJobResponse(source, "cargo-ferry jobs-logs");
  const events = requireArray(value.events, "jobs-logs.events").map((event, index) =>
    parseLegacyJobLogEvent(
      requireRecord(event, `jobs-logs.events[${index}]`),
      `jobs-logs.events[${index}]`
    )
  );
  const returned = requireNonNegativeInteger(value.returned, "jobs-logs.returned");
  if (returned !== events.length || returned > 65_536) {
    throw new ProtocolError(
      "jobs-logs.returned must match its bounded legacy snapshot event count."
    );
  }
  const logScope = parseJobLogScope(value.log_scope);
  const providerFullLogs = requireBoolean(value.provider_full_logs, "jobs-logs.provider_full_logs");
  if (logScope === "durable_sanitized_lifecycle_events" && providerFullLogs) {
    throw new ProtocolError(
      "jobs-logs.provider_full_logs must be false for durable_sanitized_lifecycle_events."
    );
  }
  const phase = optionalBoundedString(value.phase, "jobs-logs.phase");
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, "jobs-logs.workspace"),
    local_job_id: requireSafeIdentifier(value.local_job_id, "jobs-logs.local_job_id"),
    log_scope: logScope,
    provider_full_logs: providerFullLogs,
    since_ms: requireNonNegativeInteger(value.since_ms, "jobs-logs.since_ms"),
    ...(phase === undefined ? {} : { phase }),
    returned,
    next_sequence: requireNonNegativeInteger(value.next_sequence, "jobs-logs.next_sequence"),
    terminal: requireBoolean(value.terminal, "jobs-logs.terminal"),
    events
  };
}

export function parseJobLogsPageResponse(source: string): JobLogsPageResponse {
  const value = parseJobResponse(source, "cargo-ferry jobs-logs-page");
  const events = requireArray(value.events, "jobs-logs-page.events").map((event, index) =>
    parseJobLogEvent(
      requireRecord(event, `jobs-logs-page.events[${index}]`),
      `jobs-logs-page.events[${index}]`
    )
  );
  const limit = requireBoundedPageLimit(value.limit, "jobs-logs-page.limit");
  const returned = requireNonNegativeInteger(value.returned, "jobs-logs-page.returned");
  if (returned !== events.length) {
    throw new ProtocolError("jobs-logs-page.returned does not match jobs-logs-page.events length.");
  }
  if (returned > limit) {
    throw new ProtocolError("jobs-logs-page.returned exceeds jobs-logs-page.limit.");
  }
  const logScope = parseJobLogScope(value.log_scope);
  const providerFullLogs = requireBoolean(
    value.provider_full_logs,
    "jobs-logs-page.provider_full_logs"
  );
  const phase = optionalBoundedString(value.phase, "jobs-logs-page.phase");
  if (logScope === "durable_sanitized_lifecycle_events" && providerFullLogs) {
    throw new ProtocolError(
      "jobs-logs-page.provider_full_logs must be false for durable_sanitized_lifecycle_events."
    );
  }
  const afterSequence = requireDecimalString(
    value.after_sequence,
    "jobs-logs-page.after_sequence"
  );
  const nextAfterSequence = requireDecimalString(
    value.next_after_sequence,
    "jobs-logs-page.next_after_sequence"
  );
  let previous = afterSequence;
  for (const event of events) {
    if (compareDecimalStrings(event.sequence, previous) <= 0) {
      throw new ProtocolError(
        "jobs-logs-page event sequences must strictly advance after the cursor."
      );
    }
    previous = event.sequence;
  }
  if (nextAfterSequence !== previous) {
    throw new ProtocolError(
      "jobs-logs-page.next_after_sequence must equal the last returned sequence or the request cursor."
    );
  }
  const hasMore = requireBoolean(value.has_more, "jobs-logs-page.has_more");
  if (hasMore && returned === 0) {
    throw new ProtocolError("jobs-logs-page.has_more requires a cursor-advancing event.");
  }
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, "jobs-logs-page.workspace"),
    local_job_id: requireSafeIdentifier(value.local_job_id, "jobs-logs-page.local_job_id"),
    log_scope: logScope,
    provider_full_logs: providerFullLogs,
    after_sequence: afterSequence,
    ...(phase === undefined ? {} : { phase }),
    limit,
    returned,
    next_after_sequence: nextAfterSequence,
    has_more: hasMore,
    terminal: requireBoolean(value.terminal, "jobs-logs-page.terminal"),
    events
  };
}

export function parseCancelJobResponse(source: string): CancelJobResponse {
  const command = "jobs-cancel";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const parent = parseJobDetails(requireRecord(value.parent, `${command}.parent`), `${command}.parent`);
  const receipt = requireRecord(value.receipt, `${command}.receipt`);
  const parentLocalJobId = requireSafeIdentifier(
    receipt.parent_local_job_id,
    `${command}.receipt.parent_local_job_id`
  );
  const revision = requireNonNegativeInteger(receipt.revision, `${command}.receipt.revision`);
  if (parentLocalJobId !== parent.local_job_id || revision !== parent.revision) {
    throw new ProtocolError(`${command}.receipt does not bind the returned parent revision.`);
  }
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, `${command}.workspace`),
    parent,
    receipt: {
      kind: requireLiteral(receipt.kind, "cancellation_requested", `${command}.receipt.kind`),
      parent_local_job_id: parentLocalJobId,
      durable: requireLiteral(receipt.durable, true, `${command}.receipt.durable`),
      revision
    }
  };
}

export function parseRetryJobResponse(source: string): RetryJobResponse {
  const command = "jobs-retry";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const parent = parseJobDetails(requireRecord(value.parent, `${command}.parent`), `${command}.parent`);
  const child = parseJobDetails(requireRecord(value.child, `${command}.child`), `${command}.child`);
  const lineage = requireRecord(value.lineage, `${command}.lineage`);
  const receipt = requireRecord(value.receipt, `${command}.receipt`);
  const parentLocalJobId = requireSafeIdentifier(
    lineage.parent_local_job_id,
    `${command}.lineage.parent_local_job_id`
  );
  const childLocalJobId = requireSafeIdentifier(
    lineage.child_local_job_id,
    `${command}.lineage.child_local_job_id`
  );
  const attempt = requirePositiveInteger(lineage.attempt, `${command}.lineage.attempt`);
  if (
    parent.local_job_id === child.local_job_id
    || parentLocalJobId !== parent.local_job_id
    || childLocalJobId !== child.local_job_id
    || child.retry.parent_job_id !== parent.local_job_id
    || child.retry.attempt !== attempt
    || child.retry.attempt !== parent.retry.attempt + 1
    || child.semantic_retry_sha256 !== parent.semantic_retry_sha256
    || child.source_manifest_sha256 !== parent.source_manifest_sha256
    || !parent.retry.child_job_ids.includes(child.local_job_id)
  ) {
    throw new ProtocolError(`${command} returned inconsistent parent/child lineage.`);
  }
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, `${command}.workspace`),
    parent,
    child,
    lineage: {
      parent_local_job_id: parentLocalJobId,
      child_local_job_id: childLocalJobId,
      attempt
    },
    receipt: {
      kind: requireLiteral(receipt.kind, "retry_created", `${command}.receipt.kind`),
      disposition: requireEnum(
        receipt.disposition,
        ["created", "resumed_existing"] as const,
        `${command}.receipt.disposition`
      ),
      durable: requireLiteral(receipt.durable, true, `${command}.receipt.durable`)
    }
  };
}

export function parseArtifactVerifyResponse(source: string): ArtifactVerifyResponse {
  const command = "jobs-artifact-verify";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const outcome = requireEnum(
    value.outcome,
    ["verified", "evidence_unavailable"] as const,
    `${command}.outcome`
  );
  const product = parseArtifactProductEvidence(
    requireRecord(value.product, `${command}.product`),
    `${command}.product`
  );
  if (
    (outcome === "verified" && product.status === "evidence_unavailable")
    || (outcome === "evidence_unavailable" && product.status !== "evidence_unavailable")
  ) {
    throw new ProtocolError(`${command}.outcome conflicts with its product evidence status.`);
  }
  return {
    ...parseArtifactActionIdentity(value, command),
    outcome,
    evidence_level: requireEnum(
      value.evidence_level,
      ["integrity", "archive_safety", "product", "cross_validated"] as const,
      `${command}.evidence_level`
    ),
    integrity: parseArtifactIntegrityEvidence(
      requireRecord(value.integrity, `${command}.integrity`),
      `${command}.integrity`
    ),
    product,
    validation_levels: requireArray(value.validation_levels, `${command}.validation_levels`).map(
      (level, index) => requireBoundedString(level, `${command}.validation_levels[${index}]`)
    ),
    signed_cleanup_evidence_bound: requireBoolean(
      value.signed_cleanup_evidence_bound,
      `${command}.signed_cleanup_evidence_bound`
    ),
    status: outcome
  };
}

export function parseArtifactRevealResponse(source: string): ArtifactRevealResponse {
  const command = "jobs-artifact-reveal";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const receipt = requireRecord(value.receipt, `${command}.receipt`);
  if (
    value.path !== undefined
    || value.local_path !== undefined
    || receipt.path !== undefined
    || receipt.local_path !== undefined
  ) {
    throw new ProtocolError(`${command} must return a launch receipt, not a path for the extension to launch.`);
  }
  return {
    ...parseArtifactActionIdentity(value, command),
    receipt: {
      launcher: requireBoundedString(receipt.launcher, `${command}.receipt.launcher`),
      environment_policy: requireLiteral(
        receipt.environment_policy,
        "fixed_no_inheritance",
        `${command}.receipt.environment_policy`
      ),
      launch_requested: requireLiteral(
        receipt.launch_requested,
        true,
        `${command}.receipt.launch_requested`
      ),
      exact_path_bound_during_launch: requireBoolean(
        receipt.exact_path_bound_during_launch,
        `${command}.receipt.exact_path_bound_during_launch`
      ),
      post_launch_revalidation: requireLiteral(
        receipt.post_launch_revalidation,
        "passed",
        `${command}.receipt.post_launch_revalidation`
      )
    },
    status: "revealed"
  };
}

export function parseArtifactRemoveResponse(source: string): ArtifactRemoveResponse {
  const command = "jobs-artifact-remove";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const receipt = requireRecord(value.receipt, `${command}.receipt`);
  const resultState = requireEnum(
    receipt.result_state,
    ["removed", "already_removed", "replacement_preserved"] as const,
    `${command}.receipt.result_state`
  );
  const executed = requireBoolean(receipt.executed, `${command}.receipt.executed`);
  const alreadyComplete = requireBoolean(
    receipt.already_complete,
    `${command}.receipt.already_complete`
  );
  const replacementPreserved = requireBoolean(
    receipt.replacement_preserved,
    `${command}.receipt.replacement_preserved`
  );
  if (
    (resultState === "removed" && (!executed || alreadyComplete || replacementPreserved))
    || (resultState === "already_removed" && (executed || !alreadyComplete || replacementPreserved))
    || (resultState === "replacement_preserved" && (executed || alreadyComplete || !replacementPreserved))
  ) {
    throw new ProtocolError(`${command}.receipt contains an inconsistent removal result.`);
  }
  return {
    ...parseArtifactActionIdentity(value, command),
    receipt: {
      confirmation_provided: requireLiteral(
        receipt.confirmation_provided,
        true,
        `${command}.receipt.confirmation_provided`
      ),
      executed,
      result_state: resultState,
      already_complete: alreadyComplete,
      replacement_preserved: replacementPreserved
    },
    status: resultState,
    replacement_preserved: replacementPreserved
  };
}

export function parseRemoteBuildPreviewResponse(source: string): RemoteBuildPreviewResponse {
  const command = "remote-build-preview";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const sourceIdentity = requireRecord(value.source, `${command}.source`);
  const effects = requireArray(value.effects, `${command}.effects`).map((effect, index) =>
    requireBoundedString(effect, `${command}.effects[${index}]`)
  );
  if (effects.length === 0 || effects.length > 64) {
    throw new ProtocolError(`${command}.effects must contain 1-64 bounded entries.`);
  }
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, `${command}.workspace`),
    provider: requireLiteral(value.provider, "github", `${command}.provider`),
    target: requireLiteral(value.target, "ios-device", `${command}.target`),
    profile: parseBuildProfile(value.profile, `${command}.profile`),
    signing_mode: requireLiteral(value.signing_mode, "unsigned", `${command}.signing_mode`),
    source_mode: requireLiteral(value.source_mode, "snapshot", `${command}.source_mode`),
    preview_sha256: requireSha256(value.preview_sha256, `${command}.preview_sha256`),
    consent_token: requireConsentToken(value.consent_token, `${command}.consent_token`),
    source: {
      manifest_sha256: requireSha256(
        sourceIdentity.manifest_sha256,
        `${command}.source.manifest_sha256`
      ),
      file_count: requireDecimalString(
        sourceIdentity.file_count,
        `${command}.source.file_count`
      ),
      total_bytes: requireDecimalString(
        sourceIdentity.total_bytes,
        `${command}.source.total_bytes`
      )
    },
    effects,
    consent_required: requireLiteral(
      value.consent_required,
      true,
      `${command}.consent_required`
    )
  };
}

export function parseRemoteBuildSubmissionResponse(
  source: string
): RemoteBuildSubmissionResponse {
  const command = "remote-build-submit";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const receipt = requireRecord(value.receipt, `${command}.receipt`);
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, `${command}.workspace`),
    job: parseJobDetails(requireRecord(value.job, `${command}.job`), `${command}.job`),
    receipt: {
      kind: requireLiteral(receipt.kind, "remote_build_submitted", `${command}.receipt.kind`),
      durable: requireLiteral(receipt.durable, true, `${command}.receipt.durable`),
      source_mode: requireLiteral(receipt.source_mode, "snapshot", `${command}.receipt.source_mode`),
      preview_sha256: requireSha256(
        receipt.preview_sha256,
        `${command}.receipt.preview_sha256`
      )
    }
  };
}

export function parseSigningReadinessResponse(source: string): SigningReadinessResponse {
  const command = "signing-readiness";
  const value = parseJobResponse(source, `cargo-ferry ${command}`);
  const checks = requireArray(value.checks, `${command}.checks`).map((entry, index) => {
    const check = requireRecord(entry, `${command}.checks[${index}]`);
    const ready = requireBoolean(check.ready, `${command}.checks[${index}].ready`);
    const reasonCode = parseEligibilityReason(
      ready,
      check.reason_code,
      `${command}.checks[${index}].reason_code`
    );
    return {
      code: requireReasonCode(check.code, `${command}.checks[${index}].code`),
      required: requireBoolean(check.required, `${command}.checks[${index}].required`),
      ready,
      ...reasonCode
    };
  });
  if (checks.length === 0 || checks.length > 64) {
    throw new ProtocolError(`${command}.checks must contain 1-64 entries.`);
  }
  const ready = requireBoolean(value.ready, `${command}.ready`);
  const computedReady = checks.every((check) => !check.required || check.ready);
  if (ready !== computedReady) {
    throw new ProtocolError(`${command}.ready does not match its required checks.`);
  }
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, `${command}.workspace`),
    provider: requireLiteral(value.provider, "github", `${command}.provider`),
    target: requireLiteral(value.target, "ios-device", `${command}.target`),
    mode: requireLiteral(
      value.mode,
      "github_actions_ios_signing",
      `${command}.mode`
    ),
    ready,
    checks
  };
}

function parseArtifactActionIdentity(
  value: Record<string, unknown>,
  command: string
): Readonly<{
  protocol_version: number;
  workspace: string;
  local_job_id: string;
  artifact_id: string;
  revision: number;
}> {
  return {
    protocol_version: PROTOCOL_VERSION,
    workspace: requirePathString(value.workspace, `${command}.workspace`),
    local_job_id: requireSafeIdentifier(value.local_job_id, `${command}.local_job_id`),
    artifact_id: requireOpaqueIdentifier(value.artifact_id, `${command}.artifact_id`),
    revision: requireNonNegativeInteger(value.revision, `${command}.revision`)
  };
}

function parseArtifactIntegrityEvidence(
  value: Record<string, unknown>,
  name: string
): ArtifactIntegrityEvidence {
  const container = requireRecord(value.container, `${name}.container`);
  const kind = requireEnum(container.kind, ["opaque", "zip"] as const, `${name}.container.kind`);
  return {
    size: requireDecimalString(value.size, `${name}.size`),
    sha256: requireSha256(value.sha256, `${name}.sha256`),
    filesystem_identity: requireBoundedString(
      value.filesystem_identity,
      `${name}.filesystem_identity`
    ),
    container: kind === "opaque"
      ? { kind }
      : {
          kind,
          entry_count: requireDecimalString(container.entry_count, `${name}.container.entry_count`),
          expanded_size: requireDecimalString(
            container.expanded_size,
            `${name}.container.expanded_size`
          )
        }
  };
}

function parseArtifactProductEvidence(
  value: Record<string, unknown>,
  name: string
): ArtifactProductEvidence {
  const status = requireEnum(
    value.status,
    ["verified", "not_applicable", "evidence_unavailable"] as const,
    `${name}.status`
  );
  if (status === "verified") {
    return {
      status,
      kind: requireEnum(
        value.kind,
        ["unsigned_xcarchive", "ipa", "signed_artifact_set"] as const,
        `${name}.kind`
      )
    };
  }
  if (status === "evidence_unavailable") {
    return {
      status,
      reason_code: requireReasonCode(value.reason_code, `${name}.reason_code`)
    };
  }
  if (value.kind !== undefined || value.reason_code !== undefined) {
    throw new ProtocolError(`${name} not_applicable evidence cannot carry a kind or reason.`);
  }
  return { status };
}

function parseJobResponse(source: string, context: string): Record<string, unknown> {
  const value = parseJsonObject(source, context);
  assertProtocolVersion(value, context);
  return value;
}

function parseJobListItem(value: Record<string, unknown>, name: string): JobListItem {
  const providerJobId = optionalDecimalString(value.provider_job_id, `${name}.provider_job_id`);
  const providerRunId = optionalDecimalString(value.provider_run_id, `${name}.provider_run_id`);
  const submittedAtMs = optionalNonNegativeInteger(value.submitted_at_ms, `${name}.submitted_at_ms`);
  const lastConfirmedState = optionalBoundedString(
    value.last_confirmed_state,
    `${name}.last_confirmed_state`
  );
  const terminalOutcome = optionalBoundedString(
    value.terminal_outcome,
    `${name}.terminal_outcome`
  );
  return {
    local_job_id: requireSafeIdentifier(value.local_job_id, `${name}.local_job_id`),
    revision: requireNonNegativeInteger(value.revision, `${name}.revision`),
    provider: requireBoundedString(value.provider, `${name}.provider`),
    ...(providerJobId === undefined ? {} : { provider_job_id: providerJobId }),
    ...(providerRunId === undefined ? {} : { provider_run_id: providerRunId }),
    operation_id: requireBoundedString(value.operation_id, `${name}.operation_id`),
    app_label: requireBoundedString(value.app_label, `${name}.app_label`),
    application_identifier: requireBoundedString(
      value.application_identifier,
      `${name}.application_identifier`
    ),
    target: requireBoundedString(value.target, `${name}.target`),
    profile: requireBoundedString(value.profile, `${name}.profile`),
    signing_mode: requireBoundedString(value.signing_mode, `${name}.signing_mode`),
    created_at_ms: requireNonNegativeInteger(value.created_at_ms, `${name}.created_at_ms`),
    ...(submittedAtMs === undefined ? {} : { submitted_at_ms: submittedAtMs }),
    updated_at_ms: requireNonNegativeInteger(value.updated_at_ms, `${name}.updated_at_ms`),
    state: requireBoundedString(value.state, `${name}.state`),
    ...(lastConfirmedState === undefined ? {} : { last_confirmed_state: lastConfirmedState }),
    ...(terminalOutcome === undefined ? {} : { terminal_outcome: terminalOutcome }),
    cleanup_status: requireBoundedString(value.cleanup_status, `${name}.cleanup_status`),
    cancellation_status: requireBoundedString(value.cancellation_status, `${name}.cancellation_status`),
    ...parseJobActionEligibility(value, name)
  };
}

function parseJobDetails(value: Record<string, unknown>, name: string): JobDetails {
  const provider = requireRecord(value.provider, `${name}.provider`);
  const retry = requireRecord(value.retry, `${name}.retry`);
  const failure = value.failure === null || value.failure === undefined
    ? undefined
    : requireRecord(value.failure, `${name}.failure`);
  const providerJobId = optionalDecimalString(value.provider_job_id, `${name}.provider_job_id`);
  const providerRunId = optionalDecimalString(value.provider_run_id, `${name}.provider_run_id`);
  const sourceRevision = optionalBoundedString(value.source_revision, `${name}.source_revision`);
  const submittedAtMs = optionalNonNegativeInteger(value.submitted_at_ms, `${name}.submitted_at_ms`);
  const lastConfirmedState = optionalBoundedString(
    value.last_confirmed_state,
    `${name}.last_confirmed_state`
  );
  const terminalOutcome = optionalBoundedString(
    value.terminal_outcome,
    `${name}.terminal_outcome`
  );
  const parentJobId = optionalSafeIdentifier(retry.parent_job_id, `${name}.retry.parent_job_id`);
  return {
    local_job_id: requireSafeIdentifier(value.local_job_id, `${name}.local_job_id`),
    revision: requireNonNegativeInteger(value.revision, `${name}.revision`),
    provider: {
      name: requireBoundedString(provider.name, `${name}.provider.name`),
      config_sha256: requireSha256(provider.config_sha256, `${name}.provider.config_sha256`),
      principal: parseJobPrincipal(
        requireRecord(provider.principal, `${name}.provider.principal`),
        `${name}.provider.principal`
      ),
      execution_repository_id: requireDecimalString(
        provider.execution_repository_id,
        `${name}.provider.execution_repository_id`
      )
    },
    ...(providerJobId === undefined ? {} : { provider_job_id: providerJobId }),
    ...(providerRunId === undefined ? {} : { provider_run_id: providerRunId }),
    operation_id: requireBoundedString(value.operation_id, `${name}.operation_id`),
    request_sha256: requireSha256(value.request_sha256, `${name}.request_sha256`),
    semantic_retry_sha256: requireSha256(value.semantic_retry_sha256, `${name}.semantic_retry_sha256`),
    application_identifier: requireBoundedString(
      value.application_identifier,
      `${name}.application_identifier`
    ),
    ...(sourceRevision === undefined ? {} : { source_revision: sourceRevision }),
    source_manifest_sha256: requireSha256(
      value.source_manifest_sha256,
      `${name}.source_manifest_sha256`
    ),
    target: requireBoundedString(value.target, `${name}.target`),
    profile: requireBoundedString(value.profile, `${name}.profile`),
    signing_mode: requireBoundedString(value.signing_mode, `${name}.signing_mode`),
    created_at_ms: requireNonNegativeInteger(value.created_at_ms, `${name}.created_at_ms`),
    ...(submittedAtMs === undefined ? {} : { submitted_at_ms: submittedAtMs }),
    updated_at_ms: requireNonNegativeInteger(value.updated_at_ms, `${name}.updated_at_ms`),
    state: requireBoundedString(value.state, `${name}.state`),
    ...(lastConfirmedState === undefined ? {} : { last_confirmed_state: lastConfirmedState }),
    ...(terminalOutcome === undefined ? {} : { terminal_outcome: terminalOutcome }),
    cleanup_status: requireBoundedString(value.cleanup_status, `${name}.cleanup_status`),
    cancellation_status: requireBoundedString(value.cancellation_status, `${name}.cancellation_status`),
    retry: {
      attempt: requireNonNegativeInteger(retry.attempt, `${name}.retry.attempt`),
      ...(parentJobId === undefined ? {} : { parent_job_id: parentJobId }),
      child_job_ids: requireArray(retry.child_job_ids, `${name}.retry.child_job_ids`).map((identifier, index) =>
        requireSafeIdentifier(identifier, `${name}.retry.child_job_ids[${index}]`)
      )
    },
    ...(failure === undefined
      ? {}
      : {
          failure: {
            code: requireBoundedString(failure.code, `${name}.failure.code`),
            retryable: requireBoolean(failure.retryable, `${name}.failure.retryable`)
          }
        }),
    artifact_count: requireNonNegativeInteger(value.artifact_count, `${name}.artifact_count`),
    event_journal_bound: requireBoolean(value.event_journal_bound, `${name}.event_journal_bound`),
    provider_resume_available: requireBoolean(
      value.provider_resume_available,
      `${name}.provider_resume_available`
    ),
    ...parseJobActionEligibility(value, name)
  };
}

function parseJobPrincipal(value: Record<string, unknown>, name: string): JobPrincipal {
  const kind = requireString(value.kind, `${name}.kind`);
  if (kind === "repository_credential") {
    return { kind };
  }
  if (kind === "user") {
    return {
      kind,
      id: requireDecimalString(value.id, `${name}.id`),
      login: requireBoundedString(value.login, `${name}.login`)
    };
  }
  throw new ProtocolError(`${name}.kind has unknown value ${kind}.`);
}

function parseJobArtifact(value: Record<string, unknown>, name: string): JobArtifact {
  const mediaType = optionalBoundedString(value.media_type, `${name}.media_type`);
  const downloadDestination = optionalPathString(
    value.download_destination,
    `${name}.download_destination`
  );
  const downloadParentIdentity = optionalBoundedString(
    value.download_parent_identity,
    `${name}.download_parent_identity`
  );
  const localPath = optionalPathString(value.local_path, `${name}.local_path`);
  const localFileIdentity = optionalBoundedString(
    value.local_file_identity,
    `${name}.local_file_identity`
  );
  return {
    artifact_id: requireOpaqueIdentifier(value.artifact_id, `${name}.artifact_id`),
    kind: requireBoundedString(value.kind, `${name}.kind`),
    file_name: requireBoundedString(value.file_name, `${name}.file_name`),
    size: requireNonNegativeInteger(value.size, `${name}.size`),
    sha256: requireSha256(value.sha256, `${name}.sha256`),
    ...(mediaType === undefined ? {} : { media_type: mediaType }),
    ...(downloadDestination === undefined ? {} : { download_destination: downloadDestination }),
    ...(downloadParentIdentity === undefined
      ? {}
      : { download_parent_identity: downloadParentIdentity }),
    ...(localPath === undefined ? {} : { local_path: localPath }),
    ...(localFileIdentity === undefined ? {} : { local_file_identity: localFileIdentity }),
    locally_validated: requireBoolean(value.locally_validated, `${name}.locally_validated`),
    current_status: requireBoundedString(value.current_status, `${name}.current_status`),
    ...parseArtifactActionEligibility(value, name)
  };
}

function parseJobLogEvent(value: Record<string, unknown>, name: string): JobLogEvent {
  const source = parseJobLogSource(value.source, `${name}.source`);
  const sourceIdentity = parseJobLogSourceIdentity(value, name);
  const phase = optionalBoundedString(value.phase, `${name}.phase`);
  const message = optionalBoundedString(value.message, `${name}.message`, 16_384);
  if (source === "worker" && sourceIdentity.source_sequence === undefined) {
    throw new ProtocolError(
      `${name} worker events require a positive source_sequence and source_event_sha256.`
    );
  }
  return {
    record_kind: requireLiteral(
      value.record_kind,
      "sanitized_lifecycle_event",
      `${name}.record_kind`
    ),
    sequence: requirePositiveDecimalString(value.sequence, `${name}.sequence`),
    occurred_at_ms: requireNonNegativeInteger(value.occurred_at_ms, `${name}.occurred_at_ms`),
    ...(phase === undefined ? {} : { phase }),
    source,
    ...sourceIdentity,
    level: parseJobLogLevel(value.level, `${name}.level`),
    code: requireBoundedString(value.code, `${name}.code`),
    ...(message === undefined ? {} : { message })
  };
}

function parseLegacyJobLogEvent(
  value: Record<string, unknown>,
  name: string
): LegacyJobLogEvent {
  const source = parseJobLogSource(value.source, `${name}.source`);
  const sourceSequence = value.source_sequence === undefined || value.source_sequence === null
    ? undefined
    : requirePositiveInteger(value.source_sequence, `${name}.source_sequence`);
  const sourceEventSha256 = value.source_event_sha256 === undefined
    || value.source_event_sha256 === null
    ? undefined
    : requireSha256(value.source_event_sha256, `${name}.source_event_sha256`);
  if (
    (sourceSequence === undefined) !== (sourceEventSha256 === undefined)
    || (source === "worker" && sourceSequence === undefined)
  ) {
    throw new ProtocolError(`${name} has an incomplete legacy source identity.`);
  }
  const phase = optionalBoundedString(value.phase, `${name}.phase`);
  const message = optionalBoundedString(value.message, `${name}.message`, 16_384);
  return {
    record_kind: requireLiteral(
      value.record_kind,
      "sanitized_lifecycle_event",
      `${name}.record_kind`
    ),
    sequence: requirePositiveInteger(value.sequence, `${name}.sequence`),
    occurred_at_ms: requireNonNegativeInteger(value.occurred_at_ms, `${name}.occurred_at_ms`),
    ...(phase === undefined ? {} : { phase }),
    source,
    ...(sourceSequence === undefined || sourceEventSha256 === undefined
      ? {}
      : { source_sequence: sourceSequence, source_event_sha256: sourceEventSha256 }),
    level: parseJobLogLevel(value.level, `${name}.level`),
    code: requireBoundedString(value.code, `${name}.code`),
    ...(message === undefined ? {} : { message })
  };
}

function parseJobLogScope(value: unknown): JobLogScope {
  if (
    value === "durable_sanitized_lifecycle_events"
    || value === "durable_sanitized_job_events"
  ) {
    return value;
  }
  throw new ProtocolError("jobs-logs.log_scope has an unknown value.");
}

function parseJobLogSource(value: unknown, name: string): JobLogSource {
  if (value === "controller" || value === "provider" || value === "worker") {
    return value;
  }
  throw new ProtocolError(`${name} has an unknown value.`);
}

function parseJobLogLevel(value: unknown, name: string): JobLogLevel {
  if (value === "info" || value === "warning" || value === "error") {
    return value;
  }
  throw new ProtocolError(`${name} has an unknown value.`);
}

function parseJobLogSourceIdentity(
  value: Record<string, unknown>,
  name: string
): Readonly<{ source_sequence?: DecimalString; source_event_sha256?: string }> {
  const sourceSequence = value.source_sequence === undefined || value.source_sequence === null
    ? undefined
    : requirePositiveDecimalString(value.source_sequence, `${name}.source_sequence`);
  const sourceEventSha256 = value.source_event_sha256 === undefined || value.source_event_sha256 === null
    ? undefined
    : requireSha256(value.source_event_sha256, `${name}.source_event_sha256`);
  if (sourceSequence === undefined && sourceEventSha256 === undefined) {
    return {};
  }
  if (sourceSequence === undefined || sourceEventSha256 === undefined) {
    throw new ProtocolError(
      `${name}.source_sequence and ${name}.source_event_sha256 must be present together.`
    );
  }
  return { source_sequence: sourceSequence, source_event_sha256: sourceEventSha256 };
}

function parseJobActionEligibility(
  value: Record<string, unknown>,
  name: string
): JobActionEligibility {
  const fields = ["can_cancel", "cancel_reason_code", "can_retry", "retry_reason_code"] as const;
  const present = fields.filter((field) => Object.hasOwn(value, field));
  if (present.length === 0) {
    return {
      can_cancel: false,
      cancel_reason_code: "server_action_eligibility_unavailable",
      can_retry: false,
      retry_reason_code: "server_action_eligibility_unavailable"
    };
  }
  if (value.can_cancel === undefined || value.can_retry === undefined) {
    throw new ProtocolError(`${name} contains a partial job action eligibility contract.`);
  }
  const canCancel = requireBoolean(value.can_cancel, `${name}.can_cancel`);
  const canRetry = requireBoolean(value.can_retry, `${name}.can_retry`);
  return {
    can_cancel: canCancel,
    ...parseEligibilityReason(canCancel, value.cancel_reason_code, `${name}.cancel_reason_code`, "cancel_reason_code"),
    can_retry: canRetry,
    ...parseEligibilityReason(canRetry, value.retry_reason_code, `${name}.retry_reason_code`, "retry_reason_code")
  };
}

function parseArtifactActionEligibility(
  value: Record<string, unknown>,
  name: string
): ArtifactActionEligibility {
  const fields = [
    "can_verify",
    "verify_reason_code",
    "can_reveal",
    "reveal_reason_code",
    "can_remove",
    "remove_reason_code"
  ] as const;
  const present = fields.filter((field) => Object.hasOwn(value, field));
  if (present.length === 0) {
    return {
      can_verify: false,
      verify_reason_code: "server_action_eligibility_unavailable",
      can_reveal: false,
      reveal_reason_code: "server_action_eligibility_unavailable",
      can_remove: false,
      remove_reason_code: "server_action_eligibility_unavailable"
    };
  }
  if (
    value.can_verify === undefined
    || value.can_reveal === undefined
    || value.can_remove === undefined
  ) {
    throw new ProtocolError(`${name} contains a partial artifact action eligibility contract.`);
  }
  const canVerify = requireBoolean(value.can_verify, `${name}.can_verify`);
  const canReveal = requireBoolean(value.can_reveal, `${name}.can_reveal`);
  const canRemove = requireBoolean(value.can_remove, `${name}.can_remove`);
  return {
    can_verify: canVerify,
    ...parseEligibilityReason(canVerify, value.verify_reason_code, `${name}.verify_reason_code`, "verify_reason_code"),
    can_reveal: canReveal,
    ...parseEligibilityReason(canReveal, value.reveal_reason_code, `${name}.reveal_reason_code`, "reveal_reason_code"),
    can_remove: canRemove,
    ...parseEligibilityReason(canRemove, value.remove_reason_code, `${name}.remove_reason_code`, "remove_reason_code")
  };
}

function parseEligibilityReason<Key extends string = "reason_code">(
  allowed: boolean,
  value: unknown,
  name: string,
  key = "reason_code" as Key
): Readonly<Partial<Record<Key, string>>> {
  if (allowed) {
    if (value !== undefined) {
      throw new ProtocolError(`${name} must be absent when the action is allowed.`);
    }
    return {} as Readonly<Partial<Record<Key, string>>>;
  }
  return { [key]: requireReasonCode(value, name) } as Readonly<Record<Key, string>>;
}

export function parseProtocolEvent(source: string): ProtocolEvent {
  const value = parseJsonObject(source, "cargo-ferry stream");
  assertProtocolVersion(value, "cargo-ferry stream");
  requireString(value.event, "event.event");
  requireString(value.operation_id, "event.operation_id");
  requireNumber(value.timestamp_ms, "event.timestamp_ms");
  if (value.parent_operation_id !== undefined) {
    requireString(value.parent_operation_id, "event.parent_operation_id");
  }
  return value as ProtocolEvent;
}

export class NdjsonDecoder {
  readonly #decoder = new StringDecoder("utf8");
  readonly #maxLineBytes: number;
  #pending = "";
  #finished = false;

  public constructor(maxLineBytes: number) {
    if (!Number.isSafeInteger(maxLineBytes) || maxLineBytes <= 0) {
      throw new RangeError("maxLineBytes must be a positive safe integer");
    }
    this.#maxLineBytes = maxLineBytes;
  }

  public push(chunk: Uint8Array): readonly ProtocolEvent[] {
    if (this.#finished) {
      throw new ProtocolError("Cannot append data after the NDJSON stream finished.");
    }
    this.#pending += this.#decoder.write(Buffer.from(chunk));
    const events: ProtocolEvent[] = [];
    let newline = this.#pending.indexOf("\n");
    while (newline >= 0) {
      const raw = this.#pending.slice(0, newline);
      this.#pending = this.#pending.slice(newline + 1);
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      this.#assertBounded(line);
      if (line.trim().length > 0) {
        events.push(parseProtocolEvent(line));
      }
      newline = this.#pending.indexOf("\n");
    }
    this.#assertBounded(this.#pending);
    return events;
  }

  public finish(): readonly ProtocolEvent[] {
    if (this.#finished) {
      return [];
    }
    this.#finished = true;
    this.#pending += this.#decoder.end();
    this.#assertBounded(this.#pending);
    if (this.#pending.trim().length > 0) {
      throw new ProtocolError("cargo-ferry ended with a truncated NDJSON event.", "protocol.truncated");
    }
    this.#pending = "";
    return [];
  }

  #assertBounded(line: string): void {
    if (Buffer.byteLength(line, "utf8") > this.#maxLineBytes) {
      throw new ProtocolError(
        `cargo-ferry emitted an IDE protocol line larger than ${this.#maxLineBytes} bytes.`,
        "protocol.line_too_large"
      );
    }
  }
}

export function eventDiagnostic(event: ProtocolEvent): ProtocolDiagnostic | undefined {
  if (event.event !== "diagnostic") {
    return undefined;
  }
  return parseDiagnostic(requireRecord(event.diagnostic, "diagnostic event payload"));
}

export function eventArtifact(event: ProtocolEvent): ProtocolArtifact | undefined {
  if (event.event !== "artifact") {
    return undefined;
  }
  return parseArtifact(requireRecord(event.artifact, "artifact event payload"));
}

export function eventDevice(event: ProtocolEvent): ProtocolDevice | undefined {
  if (event.event !== "device") {
    return undefined;
  }
  const value = isRecord(event.device) ? event.device : event;
  return parseDevice(value);
}

function parseDevice(value: Record<string, unknown>): ProtocolDevice {
  return {
    id: requireString(value.id, "device.id"),
    name: requireString(value.name, "device.name"),
    platform: requireString(value.platform, "device.platform"),
    kind: requireString(value.kind, "device.kind"),
    state: requireString(value.state, "device.state"),
    ...(typeof value.os_version === "string" ? { os_version: value.os_version } : {}),
    ...(typeof value.architecture === "string" ? { architecture: value.architecture } : {}),
    ...(typeof value.transport === "string" ? { transport: value.transport } : {}),
    ...(typeof value.paired === "boolean" ? { paired: value.paired } : {}),
    ...(typeof value.trusted === "boolean" ? { trusted: value.trusted } : {}),
    ...(isRecord(value.capabilities) ? {
      capabilities: {
        build: requireBoolean(value.capabilities.build, "device.capabilities.build"),
        install: requireBoolean(value.capabilities.install, "device.capabilities.install"),
        launch: requireBoolean(value.capabilities.launch, "device.capabilities.launch"),
        logs: requireBoolean(value.capabilities.logs, "device.capabilities.logs")
      }
    } : {}),
    ...(typeof value.supports_build === "boolean" ? { supports_build: value.supports_build } : {}),
    ...(typeof value.supports_install === "boolean" ? { supports_install: value.supports_install } : {}),
    ...(typeof value.supports_launch === "boolean" ? { supports_launch: value.supports_launch } : {}),
    ...(typeof value.supports_logs === "boolean" ? { supports_logs: value.supports_logs } : {}),
    ...(isRecord(value.details) ? { details: value.details } : {})
  };
}

function parseDiagnostic(value: Record<string, unknown>): ProtocolDiagnostic {
  const range = parseRange(requireRecord(value.range, "diagnostic.range"));
  const fixes = value.fixes === undefined
    ? []
    : requireArray(value.fixes, "diagnostic.fixes").map((fix, index) => parseFix(requireRecord(fix, `diagnostic.fixes[${index}]`)));
  const severity = requireString(value.severity, "diagnostic.severity");
  if (!(["error", "warning", "information", "hint"] as const).includes(severity as Severity)) {
    throw new ProtocolError(`diagnostic.severity has unknown value ${severity}.`);
  }
  return {
    severity: severity as Severity,
    code: requireString(value.code, "diagnostic.code"),
    message: requireString(value.message, "diagnostic.message"),
    file: requireString(value.file, "diagnostic.file"),
    range,
    fixes,
    ...(typeof value.help === "string" ? { help: value.help } : {}),
    ...(typeof value.documentation === "string" ? { documentation: value.documentation } : {})
  };
}

function parseFix(value: Record<string, unknown>): ProtocolFix {
  const parseOptionalEdit = (candidate: unknown, name: string): ProtocolTextEdit | undefined => {
    if (candidate === undefined) {
      return undefined;
    }
    const edit = requireRecord(candidate, name);
    return {
      file: requireString(edit.file, `${name}.file`),
      range: parseRange(requireRecord(edit.range, `${name}.range`)),
      new_text: requireString(edit.new_text, `${name}.new_text`)
    };
  };
  const edit = parseOptionalEdit(value.edit, "fix.edit");
  const textEdit = parseOptionalEdit(value.text_edit, "fix.text_edit");
  return {
    title: requireString(value.title, "fix.title"),
    kind: requireString(value.kind, "fix.kind"),
    ...(edit === undefined ? {} : { edit }),
    ...(textEdit === undefined ? {} : { text_edit: textEdit })
  };
}

function parseArtifact(value: Record<string, unknown>): ProtocolArtifact {
  return {
    platform: requireString(value.platform, "artifact.platform"),
    kind: requireString(value.kind, "artifact.kind"),
    path: requireString(value.path, "artifact.path"),
    package_identifier: requireString(value.package_identifier, "artifact.package_identifier"),
    architectures: requireStringArray(value.architectures, "artifact.architectures"),
    profile: requireString(value.profile, "artifact.profile"),
    validation: requireRecord(value.validation, "artifact.validation"),
    ...(typeof value.size_bytes === "number" ? { size_bytes: value.size_bytes } : {}),
    ...(typeof value.built_at === "string" ? { built_at: value.built_at } : {})
  };
}

function parseRange(value: Record<string, unknown>): ProtocolRange {
  return {
    start: parsePosition(requireRecord(value.start, "range.start")),
    end: parsePosition(requireRecord(value.end, "range.end"))
  };
}

function parsePosition(value: Record<string, unknown>): ProtocolPosition {
  const line = requireNumber(value.line, "position.line");
  const character = requireNumber(value.character, "position.character");
  if (!Number.isSafeInteger(line) || line < 0 || !Number.isSafeInteger(character) || character < 0) {
    throw new ProtocolError("Protocol positions must be non-negative integers.");
  }
  return { line, character };
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new ProtocolError(`${name} must be an object.`);
  }
  return value;
}

function requireArray(value: unknown, name: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${name} must be an array.`);
  }
  return value;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string") {
    throw new ProtocolError(`${name} must be a string.`);
  }
  return value;
}

function requireBoolean(value: unknown, name: string): boolean {
  if (typeof value !== "boolean") {
    throw new ProtocolError(`${name} must be a boolean.`);
  }
  return value;
}

function requireNumber(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ProtocolError(`${name} must be a finite number.`);
  }
  return value;
}

function requireNonNegativeInteger(value: unknown, name: string): number {
  const number = requireNumber(value, name);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new ProtocolError(`${name} must be a non-negative safe integer.`);
  }
  return number;
}

function optionalNonNegativeInteger(value: unknown, name: string): number | undefined {
  return value === undefined || value === null
    ? undefined
    : requireNonNegativeInteger(value, name);
}

function requirePositiveInteger(value: unknown, name: string): number {
  const number = requireNonNegativeInteger(value, name);
  if (number === 0) {
    throw new ProtocolError(`${name} must be a positive safe integer.`);
  }
  return number;
}

function requireBoundedPageLimit(value: unknown, name: string): number {
  const limit = requirePositiveInteger(value, name);
  if (limit > 1_000) {
    throw new ProtocolError(`${name} must not exceed 1000.`);
  }
  return limit;
}

export function requireDecimalString(value: unknown, name: string): DecimalString {
  const text = requireString(value, name);
  if (
    text.length > 20
    || !/^(?:0|[1-9][0-9]*)$/u.test(text)
    || BigInt(text) > 18_446_744_073_709_551_615n
  ) {
    throw new ProtocolError(`${name} must be a canonical unsigned 64-bit decimal string.`);
  }
  return text;
}

function optionalDecimalString(value: unknown, name: string): DecimalString | undefined {
  return value === undefined || value === null
    ? undefined
    : requireDecimalString(value, name);
}

function requirePositiveDecimalString(value: unknown, name: string): DecimalString {
  const text = requireDecimalString(value, name);
  if (text === "0") {
    throw new ProtocolError(`${name} must be a positive decimal string.`);
  }
  return text;
}

function compareDecimalStrings(left: DecimalString, right: DecimalString): number {
  const leftValue = BigInt(left);
  const rightValue = BigInt(right);
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0;
}

function requireLiteral<T extends string | number | boolean>(
  value: unknown,
  expected: T,
  name: string
): T {
  if (value !== expected) {
    throw new ProtocolError(`${name} must be ${String(expected)}.`);
  }
  return expected;
}

function requireEnum<const T extends readonly string[]>(
  value: unknown,
  expected: T,
  name: string
): T[number] {
  if (typeof value !== "string" || !expected.includes(value)) {
    throw new ProtocolError(`${name} has an unknown value.`);
  }
  return value;
}

function requireBoundedString(value: unknown, name: string, maxBytes = 4_096): string {
  const text = requireString(value, name);
  if (text.length === 0 || Buffer.byteLength(text, "utf8") > maxBytes || hasTerminalControl(text)) {
    throw new ProtocolError(`${name} must be non-empty, bounded UTF-8 text without terminal controls.`);
  }
  return text;
}

function optionalBoundedString(
  value: unknown,
  name: string,
  maxBytes = 4_096
): string | undefined {
  return value === undefined || value === null
    ? undefined
    : requireBoundedString(value, name, maxBytes);
}

function hasTerminalControl(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if ((code < 32 && !matchesWhitespaceControl(code)) || code === 127) {
      return true;
    }
  }
  return false;
}

function matchesWhitespaceControl(codePoint: number): boolean {
  return codePoint === 9 || codePoint === 10 || codePoint === 13;
}

function requirePathString(value: unknown, name: string): string {
  const path = requireBoundedString(value, name, 32_768);
  if (/[\r\n\t]/u.test(path)) {
    throw new ProtocolError(`${name} must not contain whitespace controls.`);
  }
  return path;
}

function optionalPathString(value: unknown, name: string): string | undefined {
  return value === undefined || value === null
    ? undefined
    : requirePathString(value, name);
}

function requireSha256(value: unknown, name: string): string {
  const hash = requireString(value, name);
  if (!/^[0-9a-f]{64}$/u.test(hash)) {
    throw new ProtocolError(`${name} must be a lowercase SHA-256 digest.`);
  }
  return hash;
}

function requireSafeIdentifier(value: unknown, name: string): string {
  const identifier = requireString(value, name);
  const windowsReserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/iu;
  if (
    identifier.length === 0
    || Buffer.byteLength(identifier, "utf8") > 160
    || !/^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/u.test(identifier)
    || windowsReserved.test(identifier)
  ) {
    throw new ProtocolError(`${name} must be a safe lowercase identifier.`);
  }
  return identifier;
}

function optionalSafeIdentifier(value: unknown, name: string): string | undefined {
  return value === undefined || value === null
    ? undefined
    : requireSafeIdentifier(value, name);
}

function requireOpaqueIdentifier(value: unknown, name: string): string {
  const identifier = requireString(value, name);
  if (
    identifier.length === 0
    || Buffer.byteLength(identifier, "utf8") > 160
    || !/^[A-Za-z0-9_.:-]+$/u.test(identifier)
  ) {
    throw new ProtocolError(`${name} must be a bounded ASCII identifier.`);
  }
  return identifier;
}

function requireReasonCode(value: unknown, name: string): string {
  const code = requireString(value, name);
  if (!/^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/u.test(code) || code.length > 128) {
    throw new ProtocolError(`${name} must be a bounded lowercase reason code.`);
  }
  return code;
}

function requireConsentToken(value: unknown, name: string): string {
  const token = requireString(value, name);
  if (!/^[A-Za-z0-9_-]{32,512}$/u.test(token)) {
    throw new ProtocolError(`${name} must be a bounded opaque URL-safe token.`);
  }
  return token;
}

function parseBuildProfile(value: unknown, name: string): BuildProfile {
  return requireEnum(value, ["debug", "release"] as const, name);
}

function requireStringArray(value: unknown, name: string): readonly string[] {
  return requireArray(value, name).map((item, index) => requireString(item, `${name}[${index}]`));
}

function requireNumberArray(value: unknown, name: string): readonly number[] {
  return requireArray(value, name).map((item, index) => requireNumber(item, `${name}[${index}]`));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
