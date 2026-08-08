import { readFile } from "node:fs/promises";
import * as path from "node:path";

import { describe, expect, it } from "vitest";

import {
  artifactBuildPlatform,
  deviceMatchesBuildPlatform,
  eventArtifact,
  eventDiagnostic,
  NdjsonDecoder,
  parseProtocolEvent,
  ProtocolError
} from "../../src/cli/protocol.js";

const fixtures = path.resolve(process.cwd(), "../../crates/cargo-ferry/tests/fixtures/ide-protocol-v1");

describe("IDE protocol v1", () => {
  it("keeps physical devices visible without routing them through Simulator operations", () => {
    const simulator = { id: "sim", name: "Simulator", platform: "ios", kind: "ios_simulator", state: "booted" };
    const physical = { id: "phone", name: "iPhone", platform: "ios", kind: "ios_physical", state: "online" };
    expect(deviceMatchesBuildPlatform(simulator, "ios-simulator")).toBe(true);
    expect(deviceMatchesBuildPlatform(physical, "ios-simulator")).toBe(false);
    expect(deviceMatchesBuildPlatform(physical, "ios-device")).toBe(true);
    expect(artifactBuildPlatform({
      platform: "ios-simulator",
      kind: "app",
      path: "/tmp/App.app",
      package_identifier: "com.example.app",
      architectures: ["arm64"],
      profile: "debug",
      validation: {}
    })).toBe("ios-simulator");
    expect(artifactBuildPlatform({
      platform: "ios-device",
      kind: "app",
      path: "/tmp/Physical.app",
      package_identifier: "com.example.app",
      architectures: ["arm64"],
      profile: "debug",
      validation: { team_id: "ABCDE12345" }
    })).toBe("ios-device");
  });

  it("parses the canonical Rust artifact fixture across UTF-8 chunk boundaries", async () => {
    const source = await readFile(path.join(fixtures, "event-from-rust.json"));
    const emoji = Buffer.from("🚢");
    const split = source.indexOf(emoji) + 2;
    const decoder = new NdjsonDecoder(1_048_576);
    expect(decoder.push(source.subarray(0, split))).toEqual([]);
    const events = decoder.push(Buffer.concat([source.subarray(split), Buffer.from("\n")]));
    decoder.finish();
    expect(events).toHaveLength(1);
    expect(eventArtifact(events[0]!)).toMatchObject({
      kind: "apk",
      platform: "android",
      package_identifier: "com.example.ferry",
      architectures: ["arm64-v8a"]
    });
  });

  it("parses the canonical TypeScript diagnostic fixture with Unicode and a Windows path", async () => {
    const source = await readFile(path.join(fixtures, "event-from-typescript.json"), "utf8");
    const event = parseProtocolEvent(source);
    const diagnostic = eventDiagnostic(event);
    expect(event.parent_operation_id).toBe("wizard:parent");
    expect(diagnostic?.file).toBe("C:\\Users\\Zoë Doe\\RustFerry Приложение\\ferry.toml");
    expect(diagnostic?.message).toContain("Zoë 🚢");
    expect(event.future_optional).toEqual({ accepted: true });
  });

  it("consumes the canonical cancellation stream", async () => {
    const source = await readFile(path.join(fixtures, "cancellation.ndjson"));
    const decoder = new NdjsonDecoder(1_048_576);
    const events = decoder.push(source);
    decoder.finish();
    expect(events.map((event) => event.event)).toEqual(["operation_started", "operation_cancelled"]);
    expect(new Set(events.map((event) => event.operation_id))).toEqual(new Set(["vscode:cancel-1"]));
  });

  it("ignores unknown event-specific fields and unknown event names", () => {
    const event = parseProtocolEvent(JSON.stringify({
      protocol_version: 1,
      operation_id: "test:future",
      timestamp_ms: 1,
      event: "future_event",
      future: { nested: true }
    }));
    expect(event.event).toBe("future_event");
    expect(event.future).toEqual({ nested: true });
  });

  it("rejects incompatible versions and missing common fields", () => {
    expect(() => parseProtocolEvent(JSON.stringify({
      protocol_version: 2,
      operation_id: "test:version",
      timestamp_ms: 1,
      event: "operation_started"
    }))).toThrow(/requires 1–1/u);
    expect(() => parseProtocolEvent(JSON.stringify({
      protocol_version: 1,
      timestamp_ms: 1,
      event: "operation_started"
    }))).toThrow(/operation_id/u);
  });

  it("rejects truncated and oversized stream records", () => {
    const truncated = new NdjsonDecoder(1_024);
    truncated.push(Buffer.from('{"protocol_version":1'));
    expect(() => truncated.finish()).toThrow(ProtocolError);

    const bounded = new NdjsonDecoder(64);
    expect(() => bounded.push(Buffer.from("x".repeat(65)))).toThrow(/larger than 64 bytes/u);
  });
});
