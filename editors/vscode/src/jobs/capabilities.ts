import {
  jobIdeCommands,
  remoteIdeCommands,
  type JobIdeCommand,
  type RemoteIdeCommand
} from "../constants.js";

const jobCommands: readonly JobIdeCommand[] = [
  jobIdeCommands.show,
  jobIdeCommands.logsPage,
  jobIdeCommands.cancel,
  jobIdeCommands.retry
];

const artifactCommands: readonly JobIdeCommand[] = [
  jobIdeCommands.artifactVerify,
  jobIdeCommands.artifactReveal,
  jobIdeCommands.artifactRemove
];

export type JobRecordEligibility = Readonly<{
  can_cancel: boolean;
  cancel_reason_code?: string;
  can_retry: boolean;
  retry_reason_code?: string;
}>;

export type ArtifactRecordEligibility = Readonly<{
  can_verify: boolean;
  verify_reason_code?: string;
  can_reveal: boolean;
  reveal_reason_code?: string;
  can_remove: boolean;
  remove_reason_code?: string;
}>;

export function advertisesJobCommand(
  supportedCommands: readonly string[],
  command: JobIdeCommand
): boolean {
  return supportedCommands.includes(command);
}

export function advertisesRemoteCommand(
  supportedCommands: readonly string[],
  command: RemoteIdeCommand
): boolean {
  return supportedCommands.includes(command);
}

export function jobProjectContextValue(supportedCommands: readonly string[]): string {
  const supported = new Set(supportedCommands);
  return [
    "rustferry.jobProject",
    ...Object.values(remoteIdeCommands).filter((command) => supported.has(command))
  ].join(".");
}

export function jobContextValue(
  supportedCommands: readonly string[],
  eligibility: JobRecordEligibility
): string {
  return contextValue(
    "rustferry.job",
    jobCommands.filter((command) => jobCommandAllowed(command, eligibility)),
    supportedCommands
  );
}

export function jobArtifactContextValue(
  supportedCommands: readonly string[],
  eligibility: ArtifactRecordEligibility
): string {
  return contextValue(
    "rustferry.jobArtifact",
    artifactCommands.filter((command) => artifactCommandAllowed(command, eligibility)),
    supportedCommands
  );
}

function jobCommandAllowed(command: JobIdeCommand, eligibility: JobRecordEligibility): boolean {
  if (command === jobIdeCommands.cancel) {
    return eligibility.can_cancel;
  }
  if (command === jobIdeCommands.retry) {
    return eligibility.can_retry;
  }
  return true;
}

function artifactCommandAllowed(
  command: JobIdeCommand,
  eligibility: ArtifactRecordEligibility
): boolean {
  if (command === jobIdeCommands.artifactVerify) {
    return eligibility.can_verify;
  }
  if (command === jobIdeCommands.artifactReveal) {
    return eligibility.can_reveal;
  }
  if (command === jobIdeCommands.artifactRemove) {
    return eligibility.can_remove;
  }
  return true;
}

function contextValue(
  base: string,
  commands: readonly JobIdeCommand[],
  supportedCommands: readonly string[]
): string {
  const advertised = new Set(supportedCommands);
  return [base, ...commands.filter((command) => advertised.has(command))].join(".");
}
