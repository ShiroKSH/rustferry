import { describe, expect, it } from "vitest";

import { commandArguments } from "../../src/tasks/arguments.js";

const androidProject = {
  root: { fsPath: "/tmp/RustFerry App" },
  selectedPlatform: "android" as const,
  selectedProfile: "debug" as const
};

describe("task argument arrays", () => {
  it("uses the Android device flag only for Android", () => {
    expect(commandArguments(androidProject, {
      action: "install",
      platform: "android",
      device: "emulator-5554"
    })).toEqual([
      "install", "android", "--device", "emulator-5554", "--project-dir", "/tmp/RustFerry App"
    ]);
  });

  it("passes a Simulator UDID as the optional simulator selector", () => {
    expect(commandArguments(androidProject, {
      action: "run",
      platform: "ios-simulator",
      device: "SIM-UDID"
    })).toEqual([
      "run", "ios", "--simulator", "SIM-UDID", "--project-dir", "/tmp/RustFerry App"
    ]);
    expect(commandArguments(androidProject, {
      action: "logs",
      platform: "ios-simulator"
    })).toEqual([
      "logs", "ios", "--simulator", "--project-dir", "/tmp/RustFerry App"
    ]);
  });

  it("uses official physical-iPhone flags with an explicit Development Team", () => {
    expect(commandArguments(androidProject, {
      action: "build",
      platform: "ios-device",
      team: "ABCDE12345"
    })).toEqual([
      "build", "ios", "--device", "--team", "ABCDE12345", "--project-dir", "/tmp/RustFerry App"
    ]);
    expect(commandArguments(androidProject, {
      action: "run",
      platform: "ios-device",
      device: "PHONE-UDID",
      team: "ABCDE12345"
    })).toEqual([
      "run", "ios", "--device", "PHONE-UDID", "--team", "ABCDE12345", "--project-dir", "/tmp/RustFerry App"
    ]);
  });
});
