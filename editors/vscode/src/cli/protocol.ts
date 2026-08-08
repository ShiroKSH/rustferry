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

function requireStringArray(value: unknown, name: string): readonly string[] {
  return requireArray(value, name).map((item, index) => requireString(item, `${name}[${index}]`));
}

function requireNumberArray(value: unknown, name: string): readonly number[] {
  return requireArray(value, name).map((item, index) => requireNumber(item, `${name}[${index}]`));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
