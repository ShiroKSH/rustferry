//! Sealed unsigned-archive handoff between compile and protected signing jobs.

use std::{collections::BTreeSet, fs};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_remote::{
    SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION, SealedUnsignedArchive, SourceArchiveLimits,
    SourceBundleRequest, SourceLimits, UnsignedXcarchiveExpectation, UnsignedXcarchiveInspection,
    create_source_bundle_archive, inspect_unsigned_xcarchive, plan_source_bundle,
    validate_source_manifest, verify_and_extract_source_bundle,
};
use same_file::Handle;

/// Validate the public descriptor without touching archive bytes.
///
/// # Errors
///
/// Rejects unsupported schema, invalid content manifests, and malformed
/// transport descriptors.
pub fn validate_sealed_unsigned_archive(
    descriptor: &SealedUnsignedArchive,
) -> Result<(), SealedArchiveError> {
    if descriptor.schema_version != SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION
        || descriptor.contents.project_path != "."
        || descriptor.transport.size == 0
        || !is_sha256(&descriptor.transport.sha256)
    {
        return Err(SealedArchiveError::InvalidDescriptor);
    }
    validate_source_manifest(&descriptor.contents, sealed_limits().source)
        .map_err(|_| SealedArchiveError::InvalidDescriptor)
}

/// Evidence produced on either side of the compile/signing trust boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedArchiveEvidence {
    /// Verified descriptor.
    pub descriptor: SealedUnsignedArchive,
    /// Independently inspected unsigned archive structure and Mach-O graph.
    pub inspection: UnsignedXcarchiveInspection,
}

/// Typed sealed-handoff failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealedArchiveError {
    /// Input/output paths or descriptor were malformed.
    InvalidDescriptor,
    /// Archive tree contained unsupported objects or selection omissions.
    UnsafeArchiveTree,
    /// Source transport planning or sealing failed.
    SealFailed,
    /// Transport integrity or extraction failed.
    UnsealFailed,
    /// Unsigned archive validation failed.
    InspectionFailed,
    /// Archive root identity changed while sealing.
    ArchiveRootChanged,
    /// Portable filesystem I/O failure.
    Io {
        /// Fixed operation label.
        operation: &'static str,
        /// Portable error category.
        kind: std::io::ErrorKind,
    },
}

impl std::fmt::Display for SealedArchiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDescriptor => formatter.write_str("sealed archive descriptor is invalid"),
            Self::UnsafeArchiveTree => {
                formatter.write_str("unsigned archive contains an unsafe or omitted object")
            }
            Self::SealFailed => formatter.write_str("unsigned archive sealing failed"),
            Self::UnsealFailed => formatter.write_str("sealed archive verification failed"),
            Self::InspectionFailed => {
                formatter.write_str("unsigned physical-iPhone archive inspection failed")
            }
            Self::ArchiveRootChanged => {
                formatter.write_str("unsigned archive root changed during sealing")
            }
            Self::Io { operation, kind } => write!(formatter, "{operation} failed: {kind}"),
        }
    }
}

impl std::error::Error for SealedArchiveError {}

/// Inspect, deterministically ZIP, and hash one unsigned physical-device archive.
///
/// The complete filesystem file set must equal the source transport plan, so
/// source-oriented exclusions cannot silently omit generated archive content.
/// Existing output is never replaced.
///
/// # Errors
///
/// Returns a typed error for unsafe objects, selection drift, path races,
/// structural mismatch, or transport publication failure.
pub fn seal_unsigned_xcarchive(
    archive_path: &Utf8Path,
    output_zip: &Utf8Path,
    expectation: UnsignedXcarchiveExpectation,
) -> Result<SealedArchiveEvidence, SealedArchiveError> {
    validate_archive_paths(archive_path, output_zip)?;
    let root_handle = Handle::from_path(archive_path)
        .map_err(|source| io_error("bind unsigned archive root", source))?;
    let before = collect_all_files(archive_path)?;
    let inspection = inspect_unsigned_xcarchive(archive_path, &expectation)
        .map_err(|_| SealedArchiveError::InspectionFailed)?;
    let plan = plan_source_bundle(
        &SourceBundleRequest::new(archive_path, archive_path).with_limits(sealed_limits().source),
    )
    .map_err(|_| SealedArchiveError::SealFailed)?;
    let selected = plan
        .manifest()
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    if before != selected {
        return Err(SealedArchiveError::UnsafeArchiveTree);
    }
    let transport = create_source_bundle_archive(&plan, output_zip, sealed_limits())
        .map_err(|_| SealedArchiveError::SealFailed)?;
    let rebound = Handle::from_path(archive_path)
        .map_err(|source| io_error("rebind unsigned archive root", source))?;
    if root_handle != rebound || collect_all_files(archive_path)? != selected {
        return Err(SealedArchiveError::ArchiveRootChanged);
    }
    inspect_unsigned_xcarchive(archive_path, &expectation)
        .map_err(|_| SealedArchiveError::InspectionFailed)?;
    let descriptor = SealedUnsignedArchive {
        schema_version: SEALED_UNSIGNED_ARCHIVE_SCHEMA_VERSION,
        transport,
        contents: plan.manifest().clone(),
        expectation,
    };
    validate_sealed_unsigned_archive(&descriptor)?;
    Ok(SealedArchiveEvidence {
        descriptor,
        inspection,
    })
}

/// Verify, safely extract, and independently re-inspect a sealed archive.
///
/// The destination must not exist. Extraction is delegated to the
/// capability-anchored source transport and exact manifest verifier.
///
/// # Errors
///
/// Returns a typed error for descriptor, ZIP, hash, extraction, or unsigned
/// physical-device archive mismatch.
pub fn unseal_unsigned_xcarchive(
    transport_zip: &Utf8Path,
    descriptor: &SealedUnsignedArchive,
    destination: &Utf8Path,
) -> Result<SealedArchiveEvidence, SealedArchiveError> {
    validate_sealed_unsigned_archive(descriptor)?;
    if destination.exists() || !has_extension(transport_zip, "zip") {
        return Err(SealedArchiveError::InvalidDescriptor);
    }
    verify_and_extract_source_bundle(
        transport_zip,
        &descriptor.transport,
        &descriptor.contents,
        destination,
        sealed_limits(),
    )
    .map_err(|_| SealedArchiveError::UnsealFailed)?;
    let actual_files = collect_all_files(destination)?;
    let expected_files = descriptor
        .contents
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    if actual_files != expected_files {
        return Err(SealedArchiveError::UnsafeArchiveTree);
    }
    let inspection = inspect_unsigned_xcarchive(destination, &descriptor.expectation)
        .map_err(|_| SealedArchiveError::InspectionFailed)?;
    Ok(SealedArchiveEvidence {
        descriptor: descriptor.clone(),
        inspection,
    })
}

/// Fixed resource limits for a generated Xcode archive handoff.
pub const fn sealed_limits() -> SourceArchiveLimits {
    SourceArchiveLimits {
        source: SourceLimits {
            max_file_count: 50_000,
            max_file_size: 512 * 1024 * 1024,
            max_total_size: 2 * 1024 * 1024 * 1024,
            max_depth: 128,
            max_ignore_file_size: 64 * 1024,
            max_ignore_rules: 1,
        },
        max_archive_size: 2 * 1024 * 1024 * 1024,
        max_compression_ratio: 100,
    }
}

fn validate_archive_paths(
    archive_path: &Utf8Path,
    output_zip: &Utf8Path,
) -> Result<(), SealedArchiveError> {
    if !archive_path.is_absolute()
        || !archive_path.is_dir()
        || !has_extension(archive_path, "xcarchive")
        || !output_zip.is_absolute()
        || !has_extension(output_zip, "zip")
        || output_zip.starts_with(archive_path)
        || output_zip.exists()
    {
        return Err(SealedArchiveError::InvalidDescriptor);
    }
    Ok(())
}

fn collect_all_files(root: &Utf8Path) -> Result<BTreeSet<String>, SealedArchiveError> {
    let mut files = BTreeSet::new();
    let mut pending = vec![Utf8PathBuf::new()];
    while let Some(relative_directory) = pending.pop() {
        let absolute_directory = root.join(&relative_directory);
        let mut entries = fs::read_dir(&absolute_directory)
            .map_err(|source| io_error("read unsigned archive tree", source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| io_error("read unsigned archive entry", source))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| SealedArchiveError::UnsafeArchiveTree)?;
            let relative = relative_directory.join(name);
            if relative.components().count() > sealed_limits().source.max_depth {
                return Err(SealedArchiveError::UnsafeArchiveTree);
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|source| io_error("inspect unsigned archive entry", source))?;
            if metadata.file_type().is_dir() {
                pending.push(relative);
            } else if metadata.file_type().is_file() {
                if !files.insert(relative.to_string())
                    || files.len() > sealed_limits().source.max_file_count
                {
                    return Err(SealedArchiveError::UnsafeArchiveTree);
                }
            } else {
                return Err(SealedArchiveError::UnsafeArchiveTree);
            }
        }
    }
    if files.is_empty() {
        return Err(SealedArchiveError::UnsafeArchiveTree);
    }
    Ok(files)
}

fn has_extension(path: &Utf8Path, expected: &str) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case(expected))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[allow(clippy::needless_pass_by_value)] // Owned signature is a direct `map_err` adapter.
fn io_error(operation: &'static str, source: std::io::Error) -> SealedArchiveError {
    SealedArchiveError::Io {
        operation,
        kind: source.kind(),
    }
}

#[cfg(test)]
mod tests {
    use camino::Utf8Path;

    use super::{is_sha256, sealed_limits};

    #[test]
    fn descriptor_digest_requires_lowercase_sha256() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"A".repeat(64)));
        assert!(!is_sha256(&"g".repeat(64)));
    }

    #[test]
    fn sealed_limits_exceed_source_defaults_but_remain_bounded() {
        let limits = sealed_limits();
        assert!(limits.max_archive_size <= 2 * 1024 * 1024 * 1024);
        assert!(limits.source.max_file_count <= 50_000);
        assert!(Utf8Path::new("App.xcarchive").extension() == Some("xcarchive"));
    }
}
