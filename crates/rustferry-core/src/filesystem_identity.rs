//! Stable, handle-bound filesystem identities for durable directory references.

use std::{error::Error, fmt, path::Path, str::FromStr};

const IDENTITY_PREFIX: &str = "rustferry-directory-v1:";
const WINDOWS_PLATFORM: &str = "windows:";
const UNIX_PLATFORM: &str = "unix:";
const WINDOWS_VOLUME_HEX_LEN: usize = 16;
const WINDOWS_FILE_ID_HEX_LEN: usize = 32;
const UNIX_COMPONENT_HEX_LEN: usize = 16;

/// Filesystem operation that failed while capturing a directory identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectoryIdentityOperation {
    /// Open the directory without following its final path component.
    OpenDirectory,
    /// Read directory attributes from the retained handle.
    QueryAttributes,
    /// Read filesystem metadata from the retained descriptor.
    QueryMetadata,
}

/// Stable reason a directory filesystem identity operation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectoryIdentityErrorKind {
    /// The path is relative, empty, or cannot be passed to the operating system safely.
    InvalidPath,
    /// The retained filesystem object is not a directory.
    NotDirectory,
    /// The retained filesystem object is a symbolic link or Windows reparse point.
    ReparsePoint,
    /// The filesystem did not provide the required persistent identity fields.
    IdentityUnavailable,
    /// A filesystem operation failed.
    OperatingSystem(DirectoryIdentityOperation),
    /// A persisted identity string is not in the stable canonical format.
    InvalidEncoding,
    /// The reopened directory does not have the expected identity.
    IdentityMismatch,
    /// The target platform has no supported handle-bound directory identity implementation.
    UnsupportedPlatform,
}

/// Sanitized failure from directory identity capture, parsing, or verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryIdentityError {
    kind: DirectoryIdentityErrorKind,
    os_code: Option<i32>,
}

impl DirectoryIdentityError {
    const fn new(kind: DirectoryIdentityErrorKind, os_code: Option<i32>) -> Self {
        Self { kind, os_code }
    }

    /// Return the stable failure classification.
    pub const fn kind(&self) -> DirectoryIdentityErrorKind {
        self.kind
    }

    /// Return the platform error code without any path or user-controlled text.
    pub const fn os_code(&self) -> Option<i32> {
        self.os_code
    }
}

impl fmt::Display for DirectoryIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            DirectoryIdentityErrorKind::InvalidPath => {
                formatter.write_str("directory identity requires a valid absolute path")
            }
            DirectoryIdentityErrorKind::NotDirectory => {
                formatter.write_str("directory identity target is not a directory")
            }
            DirectoryIdentityErrorKind::ReparsePoint => {
                formatter.write_str("directory identity target is a symbolic link or reparse point")
            }
            DirectoryIdentityErrorKind::IdentityUnavailable => {
                formatter.write_str("filesystem did not provide a persistent directory identity")
            }
            DirectoryIdentityErrorKind::OperatingSystem(operation) => {
                write!(
                    formatter,
                    "directory identity operation {operation:?} failed"
                )
            }
            DirectoryIdentityErrorKind::InvalidEncoding => {
                formatter.write_str("persisted directory identity has an invalid encoding")
            }
            DirectoryIdentityErrorKind::IdentityMismatch => {
                formatter.write_str("directory identity does not match the persisted value")
            }
            DirectoryIdentityErrorKind::UnsupportedPlatform => {
                formatter.write_str("directory identity is unsupported on this platform")
            }
        }
    }
}

impl Error for DirectoryIdentityError {}

/// Opaque, versioned identity of one directory filesystem object.
///
/// The serialized value contains only filesystem identity fields, never the source path. Callers
/// should persist and compare the complete string rather than interpreting its components.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DirectoryFilesystemIdentity(String);

impl DirectoryFilesystemIdentity {
    /// Capture the exact directory object currently named by an absolute path.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the path is not absolute, the final object is not a plain
    /// directory, or the operating system cannot supply a handle-bound persistent identity.
    pub fn capture(path: &Path) -> Result<Self, DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        platform::capture(path)
    }

    /// Return the stable ASCII representation for durable storage.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(windows)]
    fn from_windows(volume: u64, file_id: [u8; 16]) -> Self {
        Self(format!(
            "{IDENTITY_PREFIX}{WINDOWS_PLATFORM}{volume:016x}:{}",
            hex::encode(file_id)
        ))
    }

    #[cfg(unix)]
    fn from_unix(device: u64, inode: u64) -> Self {
        Self(format!(
            "{IDENTITY_PREFIX}{UNIX_PLATFORM}{device:016x}:{inode:016x}"
        ))
    }
}

impl AsRef<str> for DirectoryFilesystemIdentity {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DirectoryFilesystemIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DirectoryFilesystemIdentity {
    type Err = DirectoryIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(encoded) = value.strip_prefix(IDENTITY_PREFIX) else {
            return Err(invalid_encoding());
        };
        let valid = if let Some(encoded) = encoded.strip_prefix(WINDOWS_PLATFORM) {
            valid_pair(encoded, WINDOWS_VOLUME_HEX_LEN, WINDOWS_FILE_ID_HEX_LEN)
        } else if let Some(encoded) = encoded.strip_prefix(UNIX_PLATFORM) {
            valid_pair(encoded, UNIX_COMPONENT_HEX_LEN, UNIX_COMPONENT_HEX_LEN)
        } else {
            false
        };
        if !valid {
            return Err(invalid_encoding());
        }
        Ok(Self(value.to_owned()))
    }
}

/// Reopen an absolute path without following its final component and require exact identity.
///
/// # Errors
///
/// Returns a typed capture error, or [`DirectoryIdentityErrorKind::IdentityMismatch`] when the
/// reopened filesystem object differs from `expected`.
pub fn verify_directory_identity(
    path: &Path,
    expected: &DirectoryFilesystemIdentity,
) -> Result<(), DirectoryIdentityError> {
    let actual = DirectoryFilesystemIdentity::capture(path)?;
    if actual != *expected {
        return Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::IdentityMismatch,
            None,
        ));
    }
    Ok(())
}

fn invalid_encoding() -> DirectoryIdentityError {
    DirectoryIdentityError::new(DirectoryIdentityErrorKind::InvalidEncoding, None)
}

fn valid_pair(value: &str, first_len: usize, second_len: usize) -> bool {
    let Some((first, second)) = value.split_once(':') else {
        return false;
    };
    first.len() == first_len
        && second.len() == second_len
        && valid_lower_hex(first)
        && valid_lower_hex(second)
}

fn valid_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod platform {
    use std::{
        fs::File,
        mem::size_of,
        os::windows::{ffi::OsStrExt as _, io::FromRawHandle as _},
        path::Path,
        ptr,
    };

    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandleEx,
            OPEN_EXISTING,
        },
    };

    use super::{
        DirectoryFilesystemIdentity, DirectoryIdentityError, DirectoryIdentityErrorKind,
        DirectoryIdentityOperation,
    };

    pub(super) fn capture(
        path: &Path,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        let path = wide_path(path)?;
        // SAFETY: `path` is NUL-terminated and all optional pointer parameters are null. The
        // flags open the final path component itself and permit directory handles.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::OpenDirectory,
            )));
        }
        // SAFETY: successful `CreateFileW` transferred one owned real handle.
        let directory = unsafe { File::from_raw_handle(handle) };

        let attributes = query_attributes(&directory)?;
        if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::ReparsePoint,
                None,
            ));
        }
        if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::NotDirectory,
                None,
            ));
        }

        let identity = query_identity(&directory)?;
        Ok(DirectoryFilesystemIdentity::from_windows(
            identity.VolumeSerialNumber,
            identity.FileId.Identifier,
        ))
    }

    fn query_attributes(file: &File) -> Result<FILE_ATTRIBUTE_TAG_INFO, DirectoryIdentityError> {
        let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
        let size =
            structure_size::<FILE_ATTRIBUTE_TAG_INFO>(DirectoryIdentityOperation::QueryAttributes)?;
        // SAFETY: the retained file owns a live handle and `attributes` is writable storage of the
        // exact class-specific structure for the supplied size.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileAttributeTagInfo,
                (&raw mut attributes).cast(),
                size,
            )
        };
        if succeeded == 0 {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::QueryAttributes,
            )));
        }
        Ok(attributes)
    }

    fn query_identity(file: &File) -> Result<FILE_ID_INFO, DirectoryIdentityError> {
        let mut identity = FILE_ID_INFO::default();
        let size = u32::try_from(size_of::<FILE_ID_INFO>()).map_err(|_| {
            DirectoryIdentityError::new(DirectoryIdentityErrorKind::IdentityUnavailable, None)
        })?;
        // SAFETY: the retained file owns a live handle and `identity` is writable storage of the
        // exact class-specific structure for the supplied size.
        let succeeded = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&raw mut identity).cast(),
                size,
            )
        };
        if succeeded == 0 {
            return Err(last_error(DirectoryIdentityErrorKind::IdentityUnavailable));
        }
        Ok(identity)
    }

    fn structure_size<T>(
        operation: DirectoryIdentityOperation,
    ) -> Result<u32, DirectoryIdentityError> {
        u32::try_from(size_of::<T>()).map_err(|_| {
            DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::OperatingSystem(operation),
                None,
            )
        })
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, DirectoryIdentityError> {
        const BACKSLASH: u16 = b'\\' as u16;
        const FORWARD_SLASH: u16 = b'/' as u16;
        const VERBATIM_PREFIX: &[u16] = &[BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH];
        const VERBATIM_UNC_PREFIX: &[u16] = &[
            BACKSLASH,
            BACKSLASH,
            b'?' as u16,
            BACKSLASH,
            b'U' as u16,
            b'N' as u16,
            b'C' as u16,
            BACKSLASH,
        ];

        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.is_empty() || !path.is_absolute() || encoded.contains(&0) {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        if encoded.starts_with(VERBATIM_PREFIX) {
            encoded.push(0);
            return Ok(encoded);
        }
        for unit in &mut encoded {
            if *unit == FORWARD_SLASH {
                *unit = BACKSLASH;
            }
        }
        let mut wide = if encoded.starts_with(&[BACKSLASH, BACKSLASH]) {
            let mut wide = Vec::with_capacity(VERBATIM_UNC_PREFIX.len() + encoded.len() - 2 + 1);
            wide.extend_from_slice(VERBATIM_UNC_PREFIX);
            wide.extend_from_slice(&encoded[2..]);
            wide
        } else {
            let mut wide = Vec::with_capacity(VERBATIM_PREFIX.len() + encoded.len() + 1);
            wide.extend_from_slice(VERBATIM_PREFIX);
            wide.extend_from_slice(&encoded);
            wide
        };
        wide.push(0);
        Ok(wide)
    }

    fn last_error(kind: DirectoryIdentityErrorKind) -> DirectoryIdentityError {
        DirectoryIdentityError::new(kind, std::io::Error::last_os_error().raw_os_error())
    }

    use std::os::windows::io::AsRawHandle as _;
}

#[cfg(unix)]
mod platform {
    use std::{
        fs::OpenOptions,
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
        path::Path,
    };

    use super::{
        DirectoryFilesystemIdentity, DirectoryIdentityError, DirectoryIdentityErrorKind,
        DirectoryIdentityOperation,
    };

    pub(super) fn capture(
        path: &Path,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(open_error)?;
        let metadata = directory.metadata().map_err(|error| {
            DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::OperatingSystem(
                    DirectoryIdentityOperation::QueryMetadata,
                ),
                error.raw_os_error(),
            )
        })?;
        if !metadata.is_dir() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::NotDirectory,
                None,
            ));
        }
        Ok(DirectoryFilesystemIdentity::from_unix(
            metadata.dev(),
            metadata.ino(),
        ))
    }

    fn open_error(error: std::io::Error) -> DirectoryIdentityError {
        let os_code = error.raw_os_error();
        let kind = match os_code {
            Some(libc::ELOOP) => DirectoryIdentityErrorKind::ReparsePoint,
            Some(libc::ENOTDIR) => DirectoryIdentityErrorKind::NotDirectory,
            _ => DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::OpenDirectory,
            ),
        };
        DirectoryIdentityError::new(kind, os_code)
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::path::Path;

    use super::{DirectoryFilesystemIdentity, DirectoryIdentityError, DirectoryIdentityErrorKind};

    pub(super) fn capture(
        _path: &Path,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_across_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DirectoryFilesystemIdentity::capture(temporary.path()).unwrap();
        let second = DirectoryFilesystemIdentity::capture(temporary.path()).unwrap();

        assert_eq!(first, second);
        assert!(first.as_str().is_ascii());
        assert!(
            !first
                .as_str()
                .contains(&temporary.path().to_string_lossy()[..])
        );
        let restored = first
            .to_string()
            .parse::<DirectoryFilesystemIdentity>()
            .unwrap();
        assert_eq!(restored, first);
        verify_directory_identity(temporary.path(), &restored).unwrap();
    }

    #[test]
    fn replacement_directory_has_a_different_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        let original = DirectoryFilesystemIdentity::capture(&project).unwrap();

        std::fs::rename(&project, &displaced).unwrap();
        std::fs::create_dir(&project).unwrap();
        let replacement = DirectoryFilesystemIdentity::capture(&project).unwrap();

        assert_ne!(original, replacement);
        assert_eq!(
            verify_directory_identity(&project, &original)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
    }

    #[test]
    fn relative_and_regular_file_paths_are_rejected() {
        assert_eq!(
            DirectoryFilesystemIdentity::capture(Path::new("relative"))
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::InvalidPath
        );

        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            DirectoryFilesystemIdentity::capture(file.path())
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::NotDirectory
        );
    }

    #[test]
    fn persisted_format_is_strict_and_canonical() {
        let valid_windows =
            "rustferry-directory-v1:windows:0000000000000001:00112233445566778899aabbccddeeff";
        let valid_unix = "rustferry-directory-v1:unix:0000000000000001:0000000000000002";
        assert_eq!(
            valid_windows
                .parse::<DirectoryFilesystemIdentity>()
                .unwrap()
                .as_str(),
            valid_windows
        );
        assert!(valid_unix.parse::<DirectoryFilesystemIdentity>().is_ok());

        for invalid in [
            "",
            "rustferry-directory-v2:unix:0000000000000001:0000000000000002",
            "rustferry-directory-v1:other:0000000000000001:0000000000000002",
            "rustferry-directory-v1:unix:1:2",
            "rustferry-directory-v1:unix:000000000000000G:0000000000000002",
            "rustferry-directory-v1:windows:0000000000000001:00112233445566778899AABBCCDDEEFF",
            "rustferry-directory-v1:unix:0000000000000001:0000000000000002:extra",
        ] {
            let error = invalid.parse::<DirectoryFilesystemIdentity>().unwrap_err();
            assert_eq!(error.kind(), DirectoryIdentityErrorKind::InvalidEncoding);
        }
    }

    #[cfg(unix)]
    #[test]
    fn final_symbolic_link_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let link = temporary.path().join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        assert!(DirectoryFilesystemIdentity::capture(&link).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn final_directory_reparse_point_is_rejected_when_supported() {
        use std::os::windows::fs::symlink_dir;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        let link = temporary.path().join("link");
        std::fs::create_dir(&target).unwrap();
        if let Err(error) = symlink_dir(&target, &link) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("could not create test directory symlink: {error}");
        }

        assert_eq!(
            DirectoryFilesystemIdentity::capture(&link)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
    }

    #[cfg(windows)]
    #[test]
    fn long_absolute_directory_path_is_supported() {
        use std::os::windows::ffi::OsStrExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let mut directory = temporary.path().to_owned();
        let mut segment = 0_u32;
        while directory.as_os_str().encode_wide().count() <= 300 {
            directory.push(format!("long-project-directory-segment-{segment:02}"));
            std::fs::create_dir(&directory).unwrap();
            segment += 1;
        }

        let identity = DirectoryFilesystemIdentity::capture(&directory).unwrap();
        verify_directory_identity(&directory, &identity).unwrap();
    }
}
