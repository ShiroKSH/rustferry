# Source bundles

RustFerry snapshot transport selects project source and local Cargo packages without copying the
repository, credentials, generated output, or signing material. It creates a deterministic ZIP and
a separate versioned descriptor that binds the ZIP size and SHA-256 to the canonical source
manifest.

Inspect the exact selection before creating anything:

```console
cargo ferry remote bundle inspect --project ./weather
```

The report lists every portable path, byte size, executable bit, file SHA-256, resolved local path
dependency, excluded sensitive path, and the empty selected-symlink set (any encountered symlink is
rejected). Sensitive directories are listed at the skipped root and are not traversed. Cargo
metadata is read with `--locked`; only the selected package's resolved local dependency closure is
included, including when the selected package is the workspace root, and unrelated workspace
members are excluded. Local path dependencies must remain inside the selected workspace. Built-in
sensitive exclusions cannot be negated. A root or project `.ferryignore` may add literal relative
path exclusions using the restricted syntax described by command errors.

On Windows and other hosts without Unix mode bits, tracked `100755` modes are imported from the Git
index when available. Use repeatable `--executable <workspace-relative-path>` arguments for selected
untracked files or an index-less workspace; invalid or unselected paths are rejected.

Create new files without overwriting an existing path:

```console
cargo ferry remote bundle create \
  --project ./weather \
  --output ../exports/weather-source.zip \
  --descriptor ../exports/weather-source.json
```

The example assumes `../exports` already exists outside the Cargo workspace. Omitting
`--descriptor` uses `<output>.manifest.json`. Global `--dry-run` performs source planning
and destination checks but does not create either file. Both destinations must be outside the
selected Cargo workspace so temporary or previously generated bundles cannot alter their own source
manifest.

Archive and descriptor publication is independently no-clobber, not a two-file transaction. If
the archive is published but descriptor publication fails, the error reports both paths and leaves
the verified archive in place. RustFerry does not delete a path after it can no longer prove that
the path still names the operation-owned file.

Verify a received bundle independently:

```console
cargo ferry remote bundle verify \
  --archive ./weather-source.zip \
  --descriptor ./weather-source.json
```

Verification treats both files as untrusted. Descriptor reads are bounded and identity-stable. ZIP
size, SHA-256, entry order, path portability, file count, per-file and total sizes, compression
ratio, executable bits, and every content digest must match before success. Extraction uses a fresh
temporary directory and rejects traversal, symlinks, hard links, case/Unicode collisions, extra or
missing entries, archive expansion abuse, and destination replacement.

The commands are the transport foundation for SSH and future managed builders. The current GitHub
provider still uses an exact committed Git revision; these commands do not silently upload a dirty
working tree or enable GitHub snapshot submission.
