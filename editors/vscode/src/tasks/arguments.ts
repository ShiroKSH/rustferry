import type { BuildPlatform, BuildProfile } from "../cli/protocol.js";

export type TaskCommandAction = "check" | "doctor" | "build" | "install" | "run" | "logs" | "clean";

export type TaskCommandDefinition = Readonly<{
  action: TaskCommandAction;
  platform?: BuildPlatform;
  profile?: BuildProfile;
  device?: string;
  team?: string;
}>;

export type TaskCommandProject = Readonly<{
  root: Readonly<{ fsPath: string }>;
  selectedPlatform: BuildPlatform;
  selectedProfile: BuildProfile;
}>;

export function commandArguments(
  project: TaskCommandProject,
  definition: TaskCommandDefinition
): readonly string[] {
  switch (definition.action) {
    case "check":
      return ["check", "--project-dir", project.root.fsPath];
    case "doctor":
      return ["doctor", "--all"];
    case "clean":
      return ["clean", "generated", "--project-dir", project.root.fsPath];
    case "build": {
      const platform = definition.platform ?? project.selectedPlatform;
      const profile = definition.profile ?? project.selectedProfile;
      const platformArgs = platform === "android"
        ? ["android"]
        : platform === "ios-simulator"
          ? ["ios", "--simulator"]
          : ["ios", "--device", ...(definition.team === undefined ? [] : ["--team", definition.team])];
      return [
        "build",
        ...platformArgs,
        "--project-dir",
        project.root.fsPath,
        ...(profile === "release" ? ["--release"] : [])
      ];
    }
    case "install":
    case "run":
    case "logs": {
      const target = definition.platform ?? project.selectedPlatform;
      const platformArgs = target === "android"
        ? ["android", ...(definition.device === undefined ? [] : ["--device", definition.device])]
        : target === "ios-simulator"
          ? ["ios", "--simulator", ...(definition.device === undefined ? [] : [definition.device])]
          : [
              "ios",
              "--device",
              definition.device ?? "auto",
              ...(definition.action === "logs" || definition.team === undefined
                ? []
                : ["--team", definition.team])
            ];
      return [
        definition.action,
        ...platformArgs,
        "--project-dir",
        project.root.fsPath
      ];
    }
  }
}
