# VS Code tasks

RustFerry contributes a `rustferry` task provider. In a trusted, executable project it generates Check, Doctor, Android Build, iOS Simulator Build, selected-target Build, and Clean tasks. Install, Run, and Logs appear only when the negotiated CLI protocol advertises those features.

Generated tasks use the human CLI, not the editor JSON protocol, and run in a dedicated terminal with the project directory as `cwd`. **Build Selected Target** is assigned to VS Code's standard Build task group; it is not marked as the default task.

A checked-in task may use the same definition:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "type": "rustferry",
      "action": "build",
      "platform": "android",
      "profile": "release",
      "project": "${workspaceFolder}"
    }
  ]
}
```

Supported actions are `check`, `doctor`, `build`, `install`, `run`, `logs`, and `clean`. Platforms are `android`, `ios-simulator`, and `ios-device`; profiles are `debug` and `release`. The physical-iPhone build task appears only when the protocol advertises physical iOS support and passes the configured non-secret Team ID when one is selected. Deployment tasks may include an exact stable `device` ID. Physical-iPhone install and run require both that ID and a Team; standalone physical-iPhone logs remain unavailable.

Task argument construction uses process executable/argument arrays. It does not build a shell command string. Tasks are absent in untrusted workspaces and unresolved when the project or CLI cannot execute.
