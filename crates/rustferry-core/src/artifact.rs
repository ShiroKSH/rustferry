use std::fs::{self, File};
use std::io::Read as _;

use camino::{Utf8Path, Utf8PathBuf};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const DIGEST_DOMAIN: &[u8] = b"rustferry-artifact-digest-v1\0";

/// Artifact family included in the integrity-digest domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactDigestKind {
    /// Android application package.
    AndroidApk,
    /// Ad-hoc-signed iOS Simulator application bundle.
    IosSimulatorApp,
    /// Development-signed physical iOS application bundle.
    IosPhysicalApp,
}

impl ArtifactDigestKind {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::AndroidApk => b"android-apk",
            Self::IosSimulatorApp => b"ios-simulator-app",
            Self::IosPhysicalApp => b"ios-physical-app",
        }
    }
}

/// Deterministic SHA-256 identity of one artifact file or directory tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactDigest {
    /// Lowercase hexadecimal SHA-256 digest.
    pub sha256: String,
    /// Number of regular files, directories, and symbolic links represented.
    pub entries: u64,
    /// Total bytes across regular files.
    pub bytes: u64,
}

/// Failure while producing a deterministic artifact digest.
#[derive(Debug, Error)]
pub enum ArtifactDigestError {
    /// Artifact filesystem access failed.
    #[error("could not {operation} `{path}`: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Affected artifact path.
        path: Utf8PathBuf,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
    /// Artifact shape cannot be safely represented by the digest.
    #[error("invalid artifact `{path}`: {message}")]
    Invalid {
        /// Rejected artifact path.
        path: Utf8PathBuf,
        /// Exact failed invariant.
        message: String,
    },
}

/// Hash a complete APK or Apple application tree with stable path ordering and framing.
///
/// The root and every traversed entry are inspected without following a root symlink. Internal
/// bundle symlinks are represented by their target text and must resolve within the bundle.
///
/// # Errors
///
/// Returns an error for missing paths, unsafe symlinks, unsupported filesystem entries,
/// non-UTF-8 paths, concurrent truncation, or filesystem I/O failures.
pub fn digest_artifact(
    path: &Utf8Path,
    kind: ArtifactDigestKind,
) -> Result<ArtifactDigest, ArtifactDigestError> {
    let original_metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect artifact root", path, source))?;
    if original_metadata.file_type().is_symlink() {
        return Err(invalid(path, "artifact root must not be a symbolic link"));
    }
    let canonical = path
        .canonicalize_utf8()
        .map_err(|source| io_error("resolve artifact root", path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| io_error("inspect canonical artifact root", &canonical, source))?;

    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(kind.label());
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    if metadata.is_file() {
        hash_file(
            &canonical,
            Utf8Path::new("artifact"),
            &mut hasher,
            &mut entries,
            &mut bytes,
        )?;
    } else if metadata.is_dir() {
        hash_record(
            &mut hasher,
            b'R',
            Utf8Path::new("artifact"),
            &permission_mode(&metadata).to_be_bytes(),
        );
        hash_directory(
            &canonical,
            &canonical,
            &mut hasher,
            &mut entries,
            &mut bytes,
        )?;
    } else {
        return Err(invalid(
            &canonical,
            "artifact root is not a regular file or directory",
        ));
    }

    Ok(ArtifactDigest {
        sha256: hex::encode(hasher.finalize()),
        entries,
        bytes,
    })
}

fn hash_directory(
    root: &Utf8Path,
    directory: &Utf8Path,
    hasher: &mut Sha256,
    entries: &mut u64,
    bytes: &mut u64,
) -> Result<(), ArtifactDigestError> {
    let mut children = fs::read_dir(directory)
        .map_err(|source| io_error("read artifact directory", directory, source))?
        .map(|entry| {
            entry
                .map_err(|source| io_error("read artifact entry", directory, source))
                .and_then(|entry| {
                    Utf8PathBuf::from_path_buf(entry.path()).map_err(|path| {
                        invalid(
                            directory,
                            &format!("artifact entry is not UTF-8: {}", path.display()),
                        )
                    })
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();

    for child in children {
        let relative = child
            .strip_prefix(root)
            .map_err(|_| invalid(&child, "artifact entry escaped its canonical root"))?;
        let metadata = fs::symlink_metadata(&child)
            .map_err(|source| io_error("inspect artifact entry", &child, source))?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&child)
                .map_err(|source| io_error("read artifact symlink", &child, source))?;
            let target = Utf8PathBuf::from_path_buf(target).map_err(|target| {
                invalid(
                    &child,
                    &format!("artifact symlink target is not UTF-8: {}", target.display()),
                )
            })?;
            let resolved = child
                .parent()
                .unwrap_or(root)
                .join(&target)
                .canonicalize_utf8()
                .map_err(|source| io_error("resolve artifact symlink", &child, source))?;
            if !resolved.starts_with(root) {
                return Err(invalid(&child, "artifact symlink escapes its bundle root"));
            }
            hash_record(hasher, b'L', relative, target.as_str().as_bytes());
            *entries = entries.saturating_add(1);
        } else if metadata.is_dir() {
            hash_record(
                hasher,
                b'D',
                relative,
                &permission_mode(&metadata).to_be_bytes(),
            );
            *entries = entries.saturating_add(1);
            hash_directory(root, &child, hasher, entries, bytes)?;
        } else if metadata.is_file() {
            hash_file(&child, relative, hasher, entries, bytes)?;
        } else {
            return Err(invalid(
                &child,
                "artifact contains a non-file, non-directory filesystem entry",
            ));
        }
    }
    Ok(())
}

fn hash_file(
    path: &Utf8Path,
    relative: &Utf8Path,
    hasher: &mut Sha256,
    entries: &mut u64,
    bytes: &mut u64,
) -> Result<(), ArtifactDigestError> {
    let mut file = File::open(path)
        .map_err(|source| io_error("open artifact file for hashing", path, source))?;
    let initial_metadata = file
        .metadata()
        .map_err(|source| io_error("inspect opened artifact file", path, source))?;
    let length = initial_metadata.len();
    let mode = permission_mode(&initial_metadata);
    let mut attributes = [0_u8; 12];
    attributes[..4].copy_from_slice(&mode.to_be_bytes());
    attributes[4..].copy_from_slice(&length.to_be_bytes());
    hash_record(hasher, b'F', relative, &attributes);

    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| io_error("hash artifact file", path, source))?;
        if read == 0 {
            break;
        }
        observed = observed.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        hasher.update(&buffer[..read]);
    }
    let final_metadata = file
        .metadata()
        .map_err(|source| io_error("reinspect opened artifact file", path, source))?;
    if observed != length
        || final_metadata.len() != length
        || permission_mode(&final_metadata) != mode
    {
        return Err(invalid(
            path,
            "artifact file changed length or permissions while it was hashed",
        ));
    }
    *entries = entries.saturating_add(1);
    *bytes = bytes.saturating_add(length);
    Ok(())
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.mode() & 0o7777
}

#[cfg(not(unix))]
const fn permission_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn hash_record(hasher: &mut Sha256, kind: u8, path: &Utf8Path, value: &[u8]) {
    hasher.update([kind]);
    hasher.update(
        u64::try_from(path.as_str().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(path.as_str().as_bytes());
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn io_error(
    operation: &'static str,
    path: &Utf8Path,
    source: std::io::Error,
) -> ArtifactDigestError {
    ArtifactDigestError::Io {
        operation,
        path: path.to_owned(),
        source,
    }
}

fn invalid(path: &Utf8Path, message: &str) -> ArtifactDigestError {
    ArtifactDigestError::Invalid {
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_changes_with_file_and_tree_content() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let root =
            Utf8PathBuf::from_path_buf(directory.path().join("Example.app")).expect("UTF-8 path");
        fs::create_dir_all(root.join("Resources")).expect("create bundle");
        fs::write(root.join("Info.plist"), b"plist").expect("write plist");
        fs::write(root.join("Resources/icon.png"), b"icon-a").expect("write icon");
        let original =
            digest_artifact(&root, ArtifactDigestKind::IosSimulatorApp).expect("initial digest");
        let repeated =
            digest_artifact(&root, ArtifactDigestKind::IosSimulatorApp).expect("repeated digest");
        assert_eq!(original, repeated);

        fs::write(root.join("Resources/icon.png"), b"icon-b").expect("replace icon");
        let changed =
            digest_artifact(&root, ArtifactDigestKind::IosSimulatorApp).expect("changed digest");
        assert_ne!(original, changed);
    }

    #[cfg(unix)]
    #[test]
    fn digest_rejects_a_symlinked_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let actual =
            Utf8PathBuf::from_path_buf(directory.path().join("actual.apk")).expect("UTF-8 path");
        let linked =
            Utf8PathBuf::from_path_buf(directory.path().join("linked.apk")).expect("UTF-8 path");
        fs::write(&actual, b"PK\x03\x04payload").expect("write APK");
        symlink(&actual, &linked).expect("create symlink");

        assert!(matches!(
            digest_artifact(&linked, ArtifactDigestKind::AndroidApk),
            Err(ArtifactDigestError::Invalid { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn digest_changes_with_executable_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        let root =
            Utf8PathBuf::from_path_buf(directory.path().join("Example.app")).expect("UTF-8 path");
        fs::create_dir_all(&root).expect("create bundle");
        let executable = root.join("Example");
        fs::write(&executable, b"Mach-O").expect("write executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o644))
            .expect("set non-executable mode");
        let original =
            digest_artifact(&root, ArtifactDigestKind::IosSimulatorApp).expect("initial digest");

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("set executable mode");
        let executable_digest =
            digest_artifact(&root, ArtifactDigestKind::IosSimulatorApp).expect("changed digest");
        assert_ne!(original, executable_digest);
    }
}
