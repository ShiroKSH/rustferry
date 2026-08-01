# VS Code devices

The Devices view normalizes Android physical devices/emulators, iOS Simulators, and paired physical Apple devices returned by `cargo-ferry`. Refresh is explicit; state such as offline, unauthorized, shutdown, unavailable, unpaired, or disconnected remains visible.

Select a target first, then choose a compatible device by its stable ADB serial, Simulator UDID, or CoreDevice identifier. The selection is stored per project. Switching platform clears an incompatible selection, and refreshed inventory restores a selection only when the exact ID remains compatible.

Install, Run, and Logs prompt for a device if none is selected. Each device record carries separate build, install, launch, and application-log capabilities; unsupported or stale device state fails closed in the CLI even when the extension-level feature exists. Multi-root workspaces retain separate project, target, device, and artifact state.

For a physical iPhone, select **iOS Device**, choose the paired device by its exact CoreDevice identifier, then run **RustFerry: Select Development Team**. The extension queries `cargo ferry ide signing-teams`, shows the Team ID, identity label, and public certificate fingerprint, and stores only the selected Team ID in the global `rustferry.ios.developmentTeam` setting. It does not collect credentials, private keys, or profile contents.

**Build for Physical iPhone**, Install, and Run pass that Team to the same official Xcode/`devicectl` pipeline used by the CLI. Install and Run create and independently validate a fresh development-signed artifact before using the selected device. The editor uses automatic signing without provisioning mutation; manual profile selection and opt-in `-allowProvisioningUpdates` remain explicit CLI/protocol controls. Standalone physical-iPhone Logs is unavailable because the current CoreDevice path does not provide the same application-only boundary as Android and Simulator logging.

In a trusted file-backed remote workspace, discovery runs remotely. Only SDK tools and connections visible to that remote extension host can appear. The current validation environment had no Android emulator/device, iOS Simulator runtime/device, Apple Development identity, Team, provisioning profile, or attached iPhone. The editor flow is implemented and host-tested, but physical signing and all mobile runtime operations remain unobserved. See the general [device discovery](../deployment/devices.md) contract.
