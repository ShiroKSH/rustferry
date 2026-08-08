import { createHash } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import * as path from "node:path";

import type { ProtocolRange } from "../cli/protocol.js";

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function rangeWithinLines(range: ProtocolRange, lines: readonly string[]): boolean {
  const { start, end } = range;
  if (
    !Number.isSafeInteger(start.line)
    || !Number.isSafeInteger(start.character)
    || !Number.isSafeInteger(end.line)
    || !Number.isSafeInteger(end.character)
    || start.line < 0
    || start.character < 0
    || end.line < 0
    || end.character < 0
    || start.line >= lines.length
    || end.line >= lines.length
    || start.character > (lines[start.line]?.length ?? -1)
    || end.character > (lines[end.line]?.length ?? -1)
  ) {
    return false;
  }
  return end.line > start.line || (end.line === start.line && end.character >= start.character);
}

export async function validateSafeFilePath(
  root: string,
  candidate: string,
  expectedRealPath: string
): Promise<void> {
  const absoluteRoot = path.resolve(root);
  const absoluteCandidate = path.resolve(candidate);
  const lexicalRelative = path.relative(absoluteRoot, absoluteCandidate);
  if (
    lexicalRelative.length === 0
    || lexicalRelative.startsWith("..")
    || path.isAbsolute(lexicalRelative)
  ) {
    throw new Error("Quick fix target is outside its project root.");
  }

  const [canonicalRoot, canonicalCandidate] = await Promise.all([
    realpath(absoluteRoot),
    realpath(absoluteCandidate)
  ]);
  const canonicalRelative = path.relative(canonicalRoot, canonicalCandidate);
  if (
    canonicalRelative.length === 0
    || canonicalRelative.startsWith("..")
    || path.isAbsolute(canonicalRelative)
    || canonicalCandidate !== expectedRealPath
  ) {
    throw new Error("Quick fix target changed or escaped its project root.");
  }

  let cursor = absoluteRoot;
  const parts = lexicalRelative.split(path.sep).filter(Boolean);
  for (const part of ["", ...parts]) {
    if (part.length > 0) {
      cursor = path.join(cursor, part);
    }
    const metadata = await lstat(cursor);
    if (metadata.isSymbolicLink()) {
      throw new Error("Quick fixes are disabled across symbolic-link boundaries.");
    }
    if (cursor === absoluteCandidate && !metadata.isFile()) {
      throw new Error("Quick fix target is not a regular file.");
    }
  }
}
