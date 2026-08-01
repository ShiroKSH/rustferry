import { describe, expect, it } from "vitest";

import type { CliClient } from "../../src/cli/client.js";
import type { ProtocolDiagnostic, ProtocolEvent } from "../../src/cli/protocol.js";
import { runCheckAndPublish } from "../../src/commands/checkOperation.js";

describe("Check operation diagnostics", () => {
  it("publishes exact rustc ranges even when Check fails", async () => {
    const diagnostic: ProtocolDiagnostic = {
      severity: "error",
      code: "rustc.E0308",
      message: "mismatched types",
      file: "/workspace/src/app.rs",
      range: {
        start: { line: 6, character: 4 },
        end: { line: 6, character: 7 }
      },
      help: "use the expected type",
      documentation: "https://doc.rust-lang.org/error_codes/E0308.html",
      fixes: []
    };
    const events: ProtocolEvent[] = [
      event("operation_started", { command: "check", workspace: "/workspace" }),
      event("phase_started", { phase: "rust_check" }),
      event("diagnostic", { diagnostic }),
      event("phase_finished", { phase: "rust_check", success: false, duration_ms: 1 }),
      event("operation_finished", { success: false, duration_ms: 1 })
    ];
    const client = {
      check: async (
        workspace: string,
        onEvent: (value: ProtocolEvent) => void | Promise<void>,
        signal?: AbortSignal
      ): Promise<string> => {
        expect(workspace).toBe("/workspace");
        expect(signal?.aborted).toBe(false);
        for (const protocolEvent of events) {
          await onEvent(protocolEvent);
        }
        throw new Error("fake Cargo check failed");
      }
    } as Pick<CliClient, "check">;
    const reported: ProtocolEvent[] = [];
    let published: readonly ProtocolDiagnostic[] | undefined;

    await expect(runCheckAndPublish(
      client,
      "/workspace",
      new AbortController().signal,
      (protocolEvent) => {
        reported.push(protocolEvent);
      },
      (diagnostics) => {
        published = diagnostics;
      }
    )).rejects.toThrow("fake Cargo check failed");

    expect(reported).toEqual(events);
    expect(published).toEqual([diagnostic]);
  });
});

function event(name: string, fields: Readonly<Record<string, unknown>>): ProtocolEvent {
  return {
    protocol_version: 1,
    operation_id: "check-operation",
    timestamp_ms: 1,
    event: name,
    ...fields
  };
}
