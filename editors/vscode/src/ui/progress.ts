import * as vscode from "vscode";

import type { ProtocolEvent } from "../cli/protocol.js";

export type ProgressOperation<T> = (
  signal: AbortSignal,
  event: (event: ProtocolEvent) => void | Promise<void>
) => Promise<T>;

export async function withCancellableProgress<T>(
  title: string,
  operation: ProgressOperation<T>
): Promise<T> {
  return await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title,
      cancellable: true
    },
    async (progress, token) => {
      const controller = new AbortController();
      const cancellation = token.onCancellationRequested(() => controller.abort());
      let lastPercent = 0;
      try {
        return await operation(controller.signal, (event) => {
          if (event.event === "progress") {
            const current = numberField(event, "current");
            const total = numberField(event, "total");
            const nextPercent = current !== undefined && total !== undefined && total > 0
              ? Math.min(100, Math.max(0, (current / total) * 100))
              : lastPercent;
            progress.report({
              message: stringField(event, "message"),
              increment: Math.max(0, nextPercent - lastPercent)
            });
            lastPercent = nextPercent;
          } else if (event.event === "phase_started") {
            progress.report({ message: stringField(event, "phase") });
          }
        });
      } finally {
        cancellation.dispose();
      }
    }
  );
}

function stringField(event: ProtocolEvent, field: string): string {
  return typeof event[field] === "string" ? event[field] : "Working…";
}

function numberField(event: ProtocolEvent, field: string): number | undefined {
  return typeof event[field] === "number" ? event[field] : undefined;
}
