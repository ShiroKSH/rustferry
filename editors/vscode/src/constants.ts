export const EXTENSION_ID = "shiroksh.rustferry-vscode";
export const PROTOCOL_VERSION = 1;
export const PROTOCOL_MIN_VERSION = 1;
export const PROTOCOL_MAX_VERSION = 1;
export const PROJECT_MANIFEST = "ferry.toml";
export const OUTPUT_CHANNEL = "RustFerry";
export const LOGS_CHANNEL = "RustFerry Logs";
export const JOB_LOGS_CHANNEL = "RustFerry Job Logs";
export const DOCUMENTATION_URL = "https://shiroksh.github.io/rustferry/";
export const INSTALLATION_URL = "https://shiroksh.github.io/rustferry/installation.html";
export const ANDROID_SETUP_URL = "https://shiroksh.github.io/rustferry/android/setup.html";
export const IOS_SETUP_URL = "https://shiroksh.github.io/rustferry/ios/setup.html";
export const IOS_SIGNING_URL = "https://shiroksh.github.io/rustferry/ios/physical-device.html";

export const jobIdeCommands = {
  list: "jobs-list",
  show: "jobs-show",
  logs: "jobs-logs",
  logsPage: "jobs-logs-page",
  artifacts: "jobs-artifacts",
  // Mutation IDs are dormant gates: no action is visible or invoked until the CLI advertises
  // that exact endpoint, after it has its own workspace/ownership revalidation contract.
  cancel: "jobs-cancel",
  retry: "jobs-retry",
  artifactVerify: "jobs-artifact-verify",
  artifactReveal: "jobs-artifact-reveal",
  artifactRemove: "jobs-artifact-remove"
} as const;

export type JobIdeCommand = typeof jobIdeCommands[keyof typeof jobIdeCommands];

export const remoteIdeCommands = {
  buildPreview: "remote-build-preview",
  buildSubmit: "remote-build-submit",
  signingReadiness: "signing-readiness"
} as const;

export type RemoteIdeCommand = typeof remoteIdeCommands[keyof typeof remoteIdeCommands];

export const commands = {
  createProject: "rustferry.createProject",
  refresh: "rustferry.refresh",
  selectProject: "rustferry.selectProject",
  selectTarget: "rustferry.selectTarget",
  check: "rustferry.check",
  doctor: "rustferry.doctor",
  buildAndroid: "rustferry.buildAndroid",
  buildIosSimulator: "rustferry.buildIosSimulator",
  buildPhysicalIos: "rustferry.buildPhysicalIos",
  buildSelected: "rustferry.buildSelected",
  clean: "rustferry.clean",
  addCapability: "rustferry.addCapability",
  removeCapability: "rustferry.removeCapability",
  openConfig: "rustferry.openConfig",
  openApp: "rustferry.openApp",
  openDocumentation: "rustferry.openDocumentation",
  refreshDevices: "rustferry.refreshDevices",
  selectDevice: "rustferry.selectDevice",
  selectDevelopmentTeam: "rustferry.selectDevelopmentTeam",
  runIosDoctor: "rustferry.runIosDoctor",
  openIosSigningGuide: "rustferry.openIosSigningGuide",
  install: "rustferry.install",
  run: "rustferry.run",
  logs: "rustferry.logs",
  stopLogs: "rustferry.stopLogs",
  revealArtifact: "rustferry.revealArtifact",
  copyArtifactPath: "rustferry.copyArtifactPath",
  inspectArtifact: "rustferry.inspectArtifact",
  deleteArtifact: "rustferry.deleteArtifact",
  applyValidatedFix: "rustferry.applyValidatedFix",
  trustWorkspace: "rustferry.trustWorkspace",
  selectCli: "rustferry.selectCli",
  refreshJobs: "rustferry.jobs.refresh",
  showJob: "rustferry.jobs.show",
  showJobLogs: "rustferry.jobs.logs",
  loadMoreJobLogs: "rustferry.jobs.logs.loadMore",
  followJobLogs: "rustferry.jobs.logs.follow",
  cancelJob: "rustferry.jobs.cancel",
  retryJob: "rustferry.jobs.retry",
  verifyJobArtifact: "rustferry.jobs.artifact.verify",
  revealJobArtifact: "rustferry.jobs.artifact.reveal",
  removeJobArtifact: "rustferry.jobs.artifact.remove",
  remoteSnapshotBuild: "rustferry.jobs.remoteSnapshotBuild",
  signingReadiness: "rustferry.jobs.signingReadiness"
} as const;
