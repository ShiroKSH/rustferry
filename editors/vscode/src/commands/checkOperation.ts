import type { CliClient } from "../cli/client.js";
import { eventDiagnostic, type ProtocolDiagnostic, type ProtocolEvent } from "../cli/protocol.js";

type CheckClient = Pick<CliClient, "check">;

export async function runCheckAndPublish(
  client: CheckClient,
  workspace: string,
  signal: AbortSignal,
  report: (event: ProtocolEvent) => void | Promise<void>,
  publish: (diagnostics: readonly ProtocolDiagnostic[]) => void
): Promise<void> {
  const diagnostics: ProtocolDiagnostic[] = [];
  try {
    await client.check(
      workspace,
      async (event) => {
        await report(event);
        const diagnostic = eventDiagnostic(event);
        if (diagnostic !== undefined) {
          diagnostics.push(diagnostic);
        }
      },
      signal
    );
  } finally {
    publish(diagnostics);
  }
}
