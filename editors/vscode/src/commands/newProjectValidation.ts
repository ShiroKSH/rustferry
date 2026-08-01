import { createHash } from "node:crypto";

const WINDOWS_RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/u;
const RUST_KEYWORDS = new Set([
  "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn",
  "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
  "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
  "where", "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final",
  "macro", "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "gen"
]);

export function validateProjectName(value: string): string | undefined {
  if (value.length === 0) {
    return "Project name cannot be empty.";
  }
  if (value.trim() !== value) {
    return "Leading or trailing whitespace is not allowed.";
  }
  if (value === "." || value === "..") {
    return "A project name cannot be . or ...";
  }
  if (value.includes("/") || value.includes("\\")) {
    return "Path separators are not allowed.";
  }
  if (hasControlCharacter(value)) {
    return "Control characters are not allowed.";
  }
  if (/[<>:"|?*]/u.test(value) || value.endsWith(".")) {
    return "The name contains characters unsafe on supported file systems.";
  }
  const windowsStem = value.split(".", 1)[0]?.toUpperCase() ?? value.toUpperCase();
  if (WINDOWS_RESERVED.test(windowsStem)) {
    return "This project name is reserved by Windows.";
  }
  return undefined;
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) {
      return true;
    }
  }
  return false;
}

export function validateIdentifier(value: string): string | undefined {
  if (Buffer.byteLength(value, "utf8") > 255) {
    return "Application identifier must be 255 bytes or fewer.";
  }
  if (!/^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*){2,}$/u.test(value)) {
    return "Use at least three lowercase reverse-DNS segments, such as com.example.weather.";
  }
  return undefined;
}

export function deriveDefaultIdentifier(value: string): string {
  let crateName = "";
  let separator = false;
  for (const character of value) {
    if (/^[A-Za-z0-9]$/u.test(character)) {
      if (separator && crateName.length > 0) {
        crateName += "-";
      }
      separator = false;
      crateName += character.toLowerCase();
    } else {
      separator = true;
    }
  }
  crateName = crateName.replace(/-+$/u, "");
  if (crateName.length === 0) {
    crateName = `app-${createHash("sha256").update(value, "utf8").digest("hex").slice(0, 8)}`;
  }
  if (/^[0-9]/u.test(crateName)) {
    crateName = `app-${crateName}`;
  }
  if (RUST_KEYWORDS.has(crateName)) {
    crateName = `app-${crateName}`;
  }
  return `org.rustferry.${crateName.replaceAll(/[^a-z0-9]/gu, "")}`;
}
