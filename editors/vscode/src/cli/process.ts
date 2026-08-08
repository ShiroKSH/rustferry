import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

import { NdjsonDecoder, ProtocolError, type ProtocolEvent } from "./protocol.js";

const DEFAULT_STDOUT_LIMIT = 8 * 1024 * 1024;
const DEFAULT_STDERR_LIMIT = 2 * 1024 * 1024;
const DEFAULT_STDIN_LIMIT = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_PENDING_PROTOCOL_EVENTS = 1_024;

type TerminationState = {
  terminate?: NodeJS.Timeout;
  kill?: NodeJS.Timeout;
};

const activeTerminations = new WeakMap<ChildProcessWithoutNullStreams, TerminationState>();
const closedProcesses = new WeakSet<ChildProcessWithoutNullStreams>();

export type ProcessRequest = Readonly<{
  executable: string;
  args: readonly string[];
  cwd: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxStdoutBytes?: number;
  maxStderrBytes?: number;
  stdin?: string;
}>;

export type ProcessResult = Readonly<{
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}>;

export class ProcessCancelledError extends Error {
  public constructor(message = "RustFerry operation cancelled.") {
    super(message);
    this.name = "ProcessCancelledError";
  }
}

export class ProcessExecutionError extends Error {
  public constructor(
    message: string,
    readonly code: number | null,
    readonly stderr: string
  ) {
    super(message);
    this.name = "ProcessExecutionError";
  }
}

export class ProcessRunner {
  readonly #active = new Set<ChildProcessWithoutNullStreams>();
  #disposed = false;

  public async runBuffered(request: ProcessRequest): Promise<ProcessResult> {
    return await this.#run(request, undefined, undefined);
  }

  public async runNdjson(
    request: ProcessRequest,
    maxLineBytes: number,
    onEvent: (event: ProtocolEvent) => void | Promise<void>
  ): Promise<ProcessResult> {
    return await this.#run(request, new NdjsonDecoder(maxLineBytes), onEvent);
  }

  public dispose(): void {
    this.#disposed = true;
    for (const child of this.#active) {
      terminateProcessTree(child);
    }
    this.#active.clear();
  }

  async #run(
    request: ProcessRequest,
    decoder: NdjsonDecoder | undefined,
    onEvent: ((event: ProtocolEvent) => void | Promise<void>) | undefined
  ): Promise<ProcessResult> {
    if (this.#disposed) {
      throw new Error("ProcessRunner is disposed.");
    }
    if (request.signal?.aborted === true) {
      throw new ProcessCancelledError();
    }
    if (Buffer.byteLength(request.stdin ?? "", "utf8") > DEFAULT_STDIN_LIMIT) {
      throw new ProtocolError(
        `cargo-ferry stdin exceeded the ${DEFAULT_STDIN_LIMIT}-byte request limit.`,
        "protocol.input_too_large"
      );
    }

    const child = spawn(request.executable, [...request.args], {
      cwd: request.cwd,
      detached: process.platform !== "win32",
      env: { ...process.env, CARGO_TERM_COLOR: "never", NO_COLOR: "1" },
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
    this.#active.add(child);
    child.once("close", () => closedProcesses.add(child));

    return await new Promise<ProcessResult>((resolve, reject) => {
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let cancelled = false;
      let settled = false;
      let chain = Promise.resolve();
      let pendingProtocolEvents = 0;
      const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
      const timeout = timeoutMs > 0
        ? setTimeout(() => fail(new ProcessExecutionError(`RustFerry command timed out after ${timeoutMs} ms.`, null, boundedText(stderr))), timeoutMs)
        : undefined;
      timeout?.unref();

      const cleanup = (): void => {
        if (timeout !== undefined) {
          clearTimeout(timeout);
        }
        request.signal?.removeEventListener("abort", onAbort);
        this.#active.delete(child);
      };
      const fail = (error: unknown): void => {
        if (settled) {
          return;
        }
        settled = true;
        terminateProcessTree(child);
        cleanup();
        reject(error instanceof Error ? error : new Error(String(error)));
      };
      const onAbort = (): void => {
        cancelled = true;
        terminateProcessTree(child);
      };
      request.signal?.addEventListener("abort", onAbort, { once: true });

      child.stdout.on("data", (chunk: Buffer) => {
        if (settled) {
          return;
        }
        stdoutBytes += chunk.byteLength;
        if (decoder === undefined) {
          if (stdoutBytes > (request.maxStdoutBytes ?? DEFAULT_STDOUT_LIMIT)) {
            fail(new ProtocolError("cargo-ferry stdout exceeded the bounded response limit.", "protocol.output_too_large"));
            return;
          }
          stdout.push(chunk);
          return;
        }
        try {
          const events = decoder.push(chunk);
          for (const event of events) {
            if (pendingProtocolEvents >= MAX_PENDING_PROTOCOL_EVENTS) {
              fail(new ProtocolError(
                `cargo-ferry queued more than ${MAX_PENDING_PROTOCOL_EVENTS} IDE protocol events while the extension was processing earlier events.`,
                "protocol.event_queue_full"
              ));
              return;
            }
            pendingProtocolEvents += 1;
            chain = chain.then(async () => {
              try {
                await onEvent?.(event);
              } finally {
                pendingProtocolEvents -= 1;
              }
            });
            void chain.catch(fail);
          }
        } catch (error) {
          fail(error);
        }
      });

      child.stderr.on("data", (chunk: Buffer) => {
        if (settled) {
          return;
        }
        stderrBytes += chunk.byteLength;
        if (stderrBytes > (request.maxStderrBytes ?? DEFAULT_STDERR_LIMIT)) {
          fail(new ProtocolError("cargo-ferry stderr exceeded the bounded bootstrap-error limit.", "protocol.stderr_too_large"));
          return;
        }
        stderr.push(chunk);
      });

      child.once("error", (error) => {
        fail(new ProcessExecutionError(`Could not start ${request.executable}: ${error.message}`, null, boundedText(stderr)));
      });
      child.stdin.once("error", (error) => {
        if (!settled && !closedProcesses.has(child)) {
          fail(new ProcessExecutionError(
            `Could not write bounded input to ${request.executable}: ${error.message}`,
            null,
            boundedText(stderr)
          ));
        }
      });
      child.once("close", (code, closeSignal) => {
        if (settled) {
          return;
        }
        chain = chain.then(() => {
          decoder?.finish();
        });
        void chain.then(
          () => {
            if (settled) {
              return;
            }
            settled = true;
            cleanup();
            if (cancelled || request.signal?.aborted === true) {
              reject(new ProcessCancelledError());
              return;
            }
            resolve({
              code,
              signal: closeSignal,
              stdout: Buffer.concat(stdout).toString("utf8"),
              stderr: boundedText(stderr)
            });
          },
          fail
        );
      });
      child.stdin.end(request.stdin ?? "", "utf8");
    });
  }
}

function boundedText(chunks: readonly Buffer[]): string {
  return Buffer.concat(chunks).toString("utf8");
}

function terminateProcessTree(child: ChildProcessWithoutNullStreams): void {
  const pid = child.pid;
  if (
    pid === undefined
    || closedProcesses.has(child)
    || activeTerminations.has(child)
  ) {
    return;
  }
  const state: TerminationState = {};
  activeTerminations.set(child, state);
  const clearEscalation = (): void => {
    if (state.terminate !== undefined) {
      clearTimeout(state.terminate);
    }
    if (state.kill !== undefined) {
      clearTimeout(state.kill);
    }
    activeTerminations.delete(child);
  };
  child.once("close", clearEscalation);
  if (process.platform === "win32") {
    const killer = spawn("taskkill.exe", ["/pid", String(pid), "/t", "/f"], {
      shell: false,
      stdio: "ignore",
      windowsHide: true
    });
    killer.unref();
    return;
  }
  signalGroup(pid, "SIGINT");
  state.terminate = setTimeout(() => {
    if (!closedProcesses.has(child)) {
      signalGroup(pid, "SIGTERM");
    }
  }, 1_500);
  state.kill = setTimeout(() => {
    if (!closedProcesses.has(child)) {
      signalGroup(pid, "SIGKILL");
    }
  }, 4_000);
  state.terminate.unref();
  state.kill.unref();
}

function signalGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") {
      try {
        process.kill(pid, signal);
      } catch {
        // The process exited between checks.
      }
    }
  }
}
