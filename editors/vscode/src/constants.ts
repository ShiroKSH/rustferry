export const EXTENSION_ID = "shiroksh.rustferry-vscode";
export const PROTOCOL_VERSION = 1;
export const PROTOCOL_MIN_VERSION = 1;
export const PROTOCOL_MAX_VERSION = 1;
export const PROJECT_MANIFEST = "ferry.toml";
export const OUTPUT_CHANNEL = "RustFerry";
export const LOGS_CHANNEL = "RustFerry Logs";
export const DOCUMENTATION_URL = "https://shiroksh.github.io/rustferry/";
export const INSTALLATION_URL = "https://shiroksh.github.io/rustferry/installation.html";
export const ANDROID_SETUP_URL = "https://shiroksh.github.io/rustferry/android/setup.html";
export const IOS_SETUP_URL = "https://shiroksh.github.io/rustferry/ios/setup.html";
export const IOS_SIGNING_URL = "https://shiroksh.github.io/rustferry/ios/physical-device.html";

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
  selectCli: "rustferry.selectCli"
} as const;
