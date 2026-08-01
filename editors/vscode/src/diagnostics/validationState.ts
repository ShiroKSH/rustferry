export type ValidationTextState = Readonly<{
  uri: string;
  version: number;
  sha256: string;
  dirty: boolean;
}>;

export function isCurrentValidationText(
  expected: ValidationTextState,
  current: ValidationTextState
): boolean {
  return expected.uri === current.uri
    && expected.version === current.version
    && expected.sha256 === current.sha256
    && expected.dirty === current.dirty;
}

export function canIssueDiskBackedFix(
  document: ValidationTextState,
  diskSha256: string
): boolean {
  return !document.dirty && document.sha256 === diskSha256;
}
