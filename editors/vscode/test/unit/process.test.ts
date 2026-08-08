import { describe, expect, it } from "vitest";

import { ProcessExecutionError, ProcessRunner } from "../../src/cli/process.js";
import { ProtocolError } from "../../src/cli/protocol.js";

describe("bounded process input", () => {
  it("writes editor source through stdin without adding it to argv", async () => {
    const runner = new ProcessRunner();
    const source = "[app]\nname = \"Unsaved Ferry\"\n";
    const script = [
      "let input = '';",
      "process.stdin.setEncoding('utf8');",
      "process.stdin.on('data', chunk => input += chunk);",
      "process.stdin.on('end', () => process.stdout.write(JSON.stringify({ input, args: process.argv.slice(1) })));"
    ].join(" ");
    const result = await runner.runBuffered({
      executable: process.execPath,
      args: ["-e", script, "visible-argument"],
      cwd: process.cwd(),
      stdin: source
    });

    expect(JSON.parse(result.stdout)).toEqual({ input: source, args: ["visible-argument"] });
    runner.dispose();
  });

  it("rejects more than one MiB before spawning a process", async () => {
    const runner = new ProcessRunner();
    const failure = runner.runBuffered({
      executable: "/definitely/not/a/real/executable",
      args: [],
      cwd: process.cwd(),
      stdin: "x".repeat(1024 * 1024 + 1)
    });

    await expect(failure).rejects.toBeInstanceOf(ProtocolError);
    await expect(failure).rejects.toMatchObject({ code: "protocol.input_too_large" });
    runner.dispose();
  });
});

describe("bounded NDJSON delivery", () => {
  it("fails closed when an async event consumer cannot keep up", async () => {
    const runner = new ProcessRunner();
    const line = `${JSON.stringify({
      protocol_version: 1,
      operation_id: "queue-test",
      timestamp_ms: 1,
      event: "progress",
      phase: "test",
      message: "queued"
    })}\n`;
    const script = `const line = ${JSON.stringify(line)}; for (let index = 0; index < 2048; index += 1) process.stdout.write(line);`;

    const failure = runner.runNdjson(
      {
        executable: process.execPath,
        args: ["-e", script],
        cwd: process.cwd(),
        timeoutMs: 2_000
      },
      4_096,
      async () => await new Promise<void>(() => undefined)
    );
    await expect(failure).rejects.toMatchObject({ code: "protocol.event_queue_full" });
    runner.dispose();
  }, 5_000);
});

describe.runIf(process.platform !== "win32")("process-tree termination", () => {
  it("kills a descendant that keeps inherited output pipes open after its parent exits", async () => {
    const runner = new ProcessRunner();
    const script = [
      "const { spawn } = require('node:child_process');",
      "const child = spawn(process.execPath, ['-e', 'process.on(\\\"SIGINT\\\", () => {}); setInterval(() => {}, 1000)'], { stdio: ['ignore', 'inherit', 'inherit'] });",
      "require('node:fs').writeSync(2, `DESCENDANT:${child.pid}\\n`);",
      "process.exit(0);"
    ].join(" ");

    let failure: unknown;
    try {
      await runner.runBuffered({
        executable: process.execPath,
        args: ["-e", script],
        cwd: process.cwd(),
        timeoutMs: 100
      });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(ProcessExecutionError);
    const stderr = (failure as ProcessExecutionError).stderr;
    const pid = Number.parseInt(/DESCENDANT:(\d+)/u.exec(stderr)?.[1] ?? "", 10);
    expect(pid).toBeGreaterThan(0);
    await expectProcessExit(pid, 3_000);
  }, 5_000);
});

async function expectProcessExit(pid: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") {
        return;
      }
      throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`descendant process ${pid} survived process-tree termination`);
}
