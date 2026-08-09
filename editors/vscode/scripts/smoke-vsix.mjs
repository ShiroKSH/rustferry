import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import * as path from "node:path";

import { strFromU8, unzipSync } from "fflate";

const MAX_VSIX_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 16 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024;
const ALLOWED_ENTRIES = new Set([
  "[Content_Types].xml",
  "extension.vsixmanifest",
  "extension/changelog.md",
  "extension/LICENSE.txt",
  "extension/SUPPORT.md",
  "extension/dist/extension.js",
  "extension/media/ferry.svg",
  "extension/media/rustferry-icon.png",
  "extension/media/walkthrough/build.md",
  "extension/media/walkthrough/device.md",
  "extension/media/walkthrough/docs.md",
  "extension/media/walkthrough/doctor.md",
  "extension/media/walkthrough/edit.md",
  "extension/media/walkthrough/locate.md",
  "extension/media/walkthrough/project.md",
  "extension/media/walkthrough/target.md",
  "extension/package.json",
  "extension/readme.md",
  "extension/snippets/rust.json"
]);
const FORBIDDEN_CONTENT = [
  /\/Users\/[A-Za-z0-9._-]+\//u,
  /\/home\/[A-Za-z0-9._-]+\//u,
  /[A-Z]:\\Users\\[^\\]+\\/u,
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/u,
  /\bgh[oprsu]_[A-Za-z0-9]{20,}\b/u,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bAKIA[0-9A-Z]{16}\b/u
];

const candidate = path.resolve(process.argv[2] ?? "dist/rustferry-vscode.vsix");
const metadata = await stat(candidate);
if (!metadata.isFile() || metadata.size > MAX_VSIX_BYTES) {
  throw new Error(`VSIX must be a regular file no larger than ${MAX_VSIX_BYTES} bytes`);
}
const bytes = await readFile(candidate);
const declaredNames = new Set();
let uncompressedBytes = 0;
const archive = unzipSync(new Uint8Array(bytes), {
  filter: (entry) => {
    if (declaredNames.has(entry.name)) {
      throw new Error(`VSIX contains duplicate entry: ${entry.name}`);
    }
    declaredNames.add(entry.name);
    if (
      entry.name.includes("/node_modules/")
      || entry.name.includes("/src/")
      || entry.name.includes("/test/")
      || entry.name.endsWith("package-lock.json")
      || entry.name.endsWith(".map")
    ) {
      throw new Error(`VSIX contains development file: ${entry.name}`);
    }
    if (!ALLOWED_ENTRIES.has(entry.name)) {
      throw new Error(`VSIX contains entry outside the allowlist: ${entry.name}`);
    }
    if (entry.originalSize > MAX_ENTRY_BYTES) {
      throw new Error(`VSIX entry exceeds ${MAX_ENTRY_BYTES}-byte bound: ${entry.name}`);
    }
    uncompressedBytes += entry.originalSize;
    if (uncompressedBytes > MAX_UNCOMPRESSED_BYTES) {
      throw new Error(`VSIX exceeds ${MAX_UNCOMPRESSED_BYTES}-byte uncompressed-size bound`);
    }
    return true;
  }
});
const names = Object.keys(archive).sort();
const missing = [...ALLOWED_ENTRIES].filter((name) => !(name in archive));
if (missing.length > 0) {
  throw new Error(`VSIX is missing allowlisted entries: ${missing.join(", ")}`);
}

const manifest = JSON.parse(strFromU8(archive["extension/package.json"]));
if (manifest.main !== "./dist/extension.js") {
  throw new Error("VSIX manifest points at an unexpected extension entry point");
}
if (manifest.icon !== "media/rustferry-icon.png") {
  throw new Error("VSIX manifest points at an unexpected extension icon");
}
for (const name of names) {
  const entry = archive[name];
  const content = Buffer.from(entry).toString("latin1");
  for (const pattern of FORBIDDEN_CONTENT) {
    if (pattern.test(content)) {
      throw new Error(
        `VSIX entry ${name} contains forbidden developer-path or secret material matching ${String(pattern)}`
      );
    }
  }
}
const digest = createHash("sha256").update(bytes).digest("hex");
process.stdout.write(`${candidate}\nsize=${bytes.byteLength}\nsha256=${digest}\nentries=${names.length}\n`);
