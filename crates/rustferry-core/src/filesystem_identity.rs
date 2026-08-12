//! Stable, handle-bound filesystem identities for durable filesystem references.

use std::{error::Error, fmt, path::Path, str::FromStr};

const DIRECTORY_IDENTITY_PREFIX: &str = "rustferry-directory-v1:";
const REGULAR_FILE_IDENTITY_PREFIX: &str = "rustferry-regular-file-v1:";
const WINDOWS_PLATFORM: &str = "windows:";
const UNIX_PLATFORM: &str = "unix:";
const WINDOWS_VOLUME_HEX_LEN: usize = 16;
const WINDOWS_FILE_ID_HEX_LEN: usize = 32;
const UNIX_COMPONENT_HEX_LEN: usize = 16;

/// Filesystem operation that failed while capturing an object identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectoryIdentityOperation {
    /// Open the directory without following its final path component.
    OpenDirectory,
    /// Open a regular file without following its final path component.
    OpenRegularFile,
    /// Read directory attributes from the retained handle.
    QueryAttributes,
    /// Read regular-file attributes and link count from the retained handle.
    QueryLinkCount,
    /// Read filesystem metadata from the retained descriptor.
    QueryMetadata,
    /// Duplicate a retained filesystem handle or descriptor.
    CloneHandle,
    /// Flush retained directory metadata through the exact handle.
    FlushDirectory,
    /// Remove a retained regular file through its exact handle.
    RemoveRegularFile,
}

/// Stable reason a filesystem identity operation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectoryIdentityErrorKind {
    /// The path is relative, empty, or cannot be passed to the operating system safely.
    InvalidPath,
    /// The retained filesystem object is not a directory.
    NotDirectory,
    /// The retained filesystem object is not a regular file.
    NotRegularFile,
    /// The retained filesystem object is a symbolic link or Windows reparse point.
    ReparsePoint,
    /// A regular file has a filesystem link count other than exactly one.
    MultipleLinks,
    /// The filesystem did not provide the required persistent identity fields.
    IdentityUnavailable,
    /// A filesystem operation failed.
    OperatingSystem(DirectoryIdentityOperation),
    /// A persisted identity string is not in the stable canonical format.
    InvalidEncoding,
    /// The reopened filesystem object does not have the expected identity.
    IdentityMismatch,
    /// The target platform has no supported handle-bound filesystem identity implementation.
    UnsupportedPlatform,
}

/// Sanitized failure from filesystem identity capture, parsing, or verification.
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
                formatter.write_str("filesystem identity requires a valid absolute path")
            }
            DirectoryIdentityErrorKind::NotDirectory => {
                formatter.write_str("directory identity target is not a directory")
            }
            DirectoryIdentityErrorKind::NotRegularFile => {
                formatter.write_str("file identity target is not a regular file")
            }
            DirectoryIdentityErrorKind::ReparsePoint => formatter
                .write_str("filesystem identity target is a symbolic link or reparse point"),
            DirectoryIdentityErrorKind::MultipleLinks => {
                formatter.write_str("file identity target does not have exactly one link")
            }
            DirectoryIdentityErrorKind::IdentityUnavailable => {
                formatter.write_str("filesystem did not provide a persistent object identity")
            }
            DirectoryIdentityErrorKind::OperatingSystem(operation) => {
                write!(
                    formatter,
                    "filesystem identity operation {operation:?} failed"
                )
            }
            DirectoryIdentityErrorKind::InvalidEncoding => {
                formatter.write_str("persisted filesystem identity has an invalid encoding")
            }
            DirectoryIdentityErrorKind::IdentityMismatch => {
                formatter.write_str("filesystem identity does not match the persisted value")
            }
            DirectoryIdentityErrorKind::UnsupportedPlatform => {
                formatter.write_str("filesystem identity is unsupported on this platform")
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
            "{DIRECTORY_IDENTITY_PREFIX}{WINDOWS_PLATFORM}{volume:016x}:{}",
            hex::encode(file_id)
        ))
    }

    #[cfg(unix)]
    fn from_unix(device: u64, inode: u64) -> Self {
        Self(format!(
            "{DIRECTORY_IDENTITY_PREFIX}{UNIX_PLATFORM}{device:016x}:{inode:016x}"
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
        if !valid_identity_encoding(value, DIRECTORY_IDENTITY_PREFIX) {
            return Err(invalid_encoding());
        }
        Ok(Self(value.to_owned()))
    }
}

/// Retained, policy-neutral handle and identity for one exact directory.
///
/// The final path component is opened without following a symbolic link or Windows reparse point.
/// On Windows the retained handle shares reads and writes but omits delete sharing, preventing the
/// named directory from being renamed, deleted, or replaced while this value or one of its cloned
/// handles remains alive. Unix descriptors do not prevent namespace rename or replacement, so
/// callers must use [`Self::verify_path`] immediately before and after sensitive pathname work.
pub struct RetainedDirectoryIdentity {
    file: std::fs::File,
    identity: DirectoryFilesystemIdentity,
}

impl RetainedDirectoryIdentity {
    /// Open and retain the exact plain directory currently named by an absolute path.
    ///
    /// The returned file is opened for directory reads and can be safely duplicated for capability
    /// consumers. Metadata synchronization acquires a separate handle bound to this exact retained
    /// directory, so read-only installation directories can still be retained and verified.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the path is not absolute, the final component is a symbolic link,
    /// reparse point, or non-directory, the platform cannot derive a persistent identity, or the
    /// pathname changes during initial binding.
    pub fn open(path: &Path) -> Result<Self, DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        let (file, identity) = platform::open_retained_directory(path)?;
        Ok(Self { file, identity })
    }

    /// Return the canonical identity captured from the retained handle.
    pub fn identity(&self) -> &DirectoryFilesystemIdentity {
        &self.identity
    }

    /// Borrow the exact retained directory file for capability-based consumers.
    pub fn as_file(&self) -> &std::fs::File {
        &self.file
    }

    /// Duplicate the exact retained directory handle or descriptor.
    ///
    /// On Windows the duplicate preserves the original no-delete-sharing lifetime. On Unix it
    /// retains the same directory object but still does not prevent namespace rename.
    ///
    /// # Errors
    ///
    /// Returns a typed operating-system error when the handle cannot be duplicated.
    pub fn try_clone_file(&self) -> Result<std::fs::File, DirectoryIdentityError> {
        self.file.try_clone().map_err(|error| {
            DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::OperatingSystem(
                    DirectoryIdentityOperation::CloneHandle,
                ),
                error.raw_os_error(),
            )
        })
    }

    /// Require the current absolute pathname to identify the same retained directory object.
    ///
    /// Windows no-delete sharing keeps a successfully rebound pathname stable while the retained
    /// handle lives. Unix verification is an instantaneous identity check only; another process can
    /// rename or replace the path immediately after this method returns.
    ///
    /// # Errors
    ///
    /// Returns a typed open/validation error, or [`DirectoryIdentityErrorKind::IdentityMismatch`]
    /// when the path no longer names this retained object.
    pub fn verify_path(&self, path: &Path) -> Result<(), DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        platform::verify_retained_directory_path(&self.file, &self.identity, path)
    }

    /// Synchronize metadata for the retained Windows directory and verify its current pathname.
    ///
    /// This policy-neutral operation requires no owner or DACL shape. It verifies the retained
    /// handle and current absolute pathname before and after a synchronous Windows metadata flush.
    /// While the retained no-delete-sharing handle keeps that binding stable, the operation opens
    /// a write-capable handle to the same verified directory and flushes only that handle. Retain
    /// this value before creating or publishing a child, then call this method on the unchanged
    /// parent path to establish the parent namespace durability barrier.
    ///
    /// A successful return means Windows reported completion of the flush request. Physical
    /// hardware can still fail to honor cache-flush commands.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when `path` is not absolute, no longer binds the retained directory,
    /// the handle lacks directory-write access, or Windows does not report successful synchronous
    /// completion. A rejected or unsupported flush is never converted into success.
    #[cfg(windows)]
    pub fn sync_metadata(&self, path: &Path) -> Result<(), DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        platform::sync_retained_directory_metadata(&self.file, &self.identity, path)
    }
}

impl fmt::Debug for RetainedDirectoryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedDirectoryIdentity")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

/// Opaque, versioned identity of one single-link regular file.
///
/// The serialized value contains only filesystem identity fields, never the source path. Its
/// distinct prefix prevents a persisted directory identity from being accepted as a file identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RegularFileFilesystemIdentity(String);

impl RegularFileFilesystemIdentity {
    /// Capture the exact single-link regular file currently named by an absolute path.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the path is not absolute, the final object is not a plain
    /// single-link regular file, or the operating system cannot supply a persistent identity.
    pub fn capture(path: &Path) -> Result<Self, DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        platform::capture_regular_file(path)
    }

    /// Return the stable ASCII representation for durable storage.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(windows)]
    fn from_windows(volume: u64, file_id: [u8; 16]) -> Self {
        Self(format!(
            "{REGULAR_FILE_IDENTITY_PREFIX}{WINDOWS_PLATFORM}{volume:016x}:{}",
            hex::encode(file_id)
        ))
    }

    #[cfg(unix)]
    fn from_unix(device: u64, inode: u64) -> Self {
        Self(format!(
            "{REGULAR_FILE_IDENTITY_PREFIX}{UNIX_PLATFORM}{device:016x}:{inode:016x}"
        ))
    }
}

impl AsRef<str> for RegularFileFilesystemIdentity {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RegularFileFilesystemIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RegularFileFilesystemIdentity {
    type Err = DirectoryIdentityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if !valid_identity_encoding(value, REGULAR_FILE_IDENTITY_PREFIX) {
            return Err(invalid_encoding());
        }
        Ok(Self(value.to_owned()))
    }
}

/// Retained identity guard for one exact single-link regular file.
///
/// On Windows the retained handle denies write and delete sharing, so the named file cannot be
/// modified, renamed, or replaced while the guard is live. On Unix the descriptor retains the
/// exact object but cannot prevent namespace rebinding; callers must use [`Self::verify_path`]
/// immediately before and after sensitive pathname work and must not claim moment-wide binding.
#[derive(Debug)]
pub struct RetainedRegularFileIdentity {
    file: std::fs::File,
    identity: RegularFileFilesystemIdentity,
}

impl RetainedRegularFileIdentity {
    /// Open and retain the exact plain single-link regular file currently named by an absolute path.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the path is not absolute, the final object is a symbolic link or
    /// reparse point, the file has multiple links, or a stable filesystem identity is unavailable.
    pub fn open(path: &Path) -> Result<Self, DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        let (file, identity) = platform::open_retained_regular_file(path)?;
        Ok(Self { file, identity })
    }

    /// Return the identity captured from the retained handle.
    pub fn identity(&self) -> &RegularFileFilesystemIdentity {
        &self.identity
    }

    /// Require the path to still name the exact retained file.
    ///
    /// # Errors
    ///
    /// Returns a typed capture error, or [`DirectoryIdentityErrorKind::IdentityMismatch`] when the
    /// path no longer names the retained exact file.
    pub fn verify_path(&self, path: &Path) -> Result<(), DirectoryIdentityError> {
        if !path.is_absolute() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::InvalidPath,
                None,
            ));
        }
        platform::verify_retained_regular_file_path(&self.file, &self.identity, path)
    }
}

/// Retained Windows handle for policy-neutral removal of one exact regular file.
///
/// Unlike the private-file APIs in [`crate::windows_private_directory`], opening this handle does
/// not require a protected DACL or a particular owner. The handle denies write and delete sharing,
/// rejects reparse points and multiple links, and remains the sole authority used by [`Self::remove`].
#[cfg(windows)]
#[derive(Debug)]
pub struct ExactRegularFileRemoval {
    file: std::fs::File,
    identity: RegularFileFilesystemIdentity,
}

#[cfg(windows)]
impl ExactRegularFileRemoval {
    /// Return the identity captured from the retained handle.
    ///
    /// Callers with a persisted expected identity must compare it before removing the file.
    pub fn identity(&self) -> &RegularFileFilesystemIdentity {
        &self.identity
    }

    /// Revalidate and remove the exact retained single-link regular file.
    ///
    /// This operation never reopens or deletes a pathname. On any error, callers must treat
    /// cleanup as uncertain; the exact handle is consumed and dropped without deleting a path
    /// that may now name a replacement.
    ///
    /// # Errors
    ///
    /// Returns a typed validation or operating-system error when the retained object no longer
    /// satisfies the identity, type, or single-link invariant, or handle-bound removal fails.
    pub fn remove(self) -> Result<(), DirectoryIdentityError> {
        platform::remove_exact_regular_file(self)
    }
}

/// Capture a single-link regular-file identity from an already-retained file object.
///
/// This function performs no pathname lookup and imposes no owner or DACL policy. It validates
/// the retained object type, rejects Windows reparse points and non-single-link files, and derives
/// the canonical identity from that same file handle or descriptor.
///
/// # Errors
///
/// Returns a typed validation or operating-system error when the retained object is not a plain
/// single-link regular file or the platform cannot supply its persistent identity.
pub fn regular_file_identity_from_file(
    file: &std::fs::File,
) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
    platform::regular_file_identity_from_file(file)
}

/// Capture a directory identity from an already-retained file object.
///
/// This function performs no pathname lookup and imposes no owner or DACL policy. It validates
/// that the retained object is a directory, rejects a Windows reparse-point handle, and derives
/// the canonical identity from that same handle or descriptor.
///
/// # Errors
///
/// Returns a typed validation or operating-system error when the retained object is not a plain
/// directory or the platform cannot supply its persistent identity.
pub fn directory_identity_from_file(
    file: &std::fs::File,
) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
    platform::directory_identity_from_file(file)
}

/// Open an absolute Windows path for policy-neutral exact regular-file removal.
///
/// The final path component is opened without following a reparse point. The retained handle
/// requests read and delete access while denying write and delete sharing, so pathname rename or
/// replacement is blocked on filesystems that enforce Windows share modes. No owner or DACL policy
/// is imposed; callers should compare [`ExactRegularFileRemoval::identity`] with their persisted
/// expected identity before calling [`ExactRegularFileRemoval::remove`].
///
/// # Errors
///
/// Returns a typed error when the path is not absolute, the final object is not a plain
/// single-link regular file, or the operating system cannot open and identify the retained object.
#[cfg(windows)]
pub fn open_regular_file_for_exact_removal(
    path: &Path,
) -> Result<ExactRegularFileRemoval, DirectoryIdentityError> {
    if !path.is_absolute() {
        return Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::InvalidPath,
            None,
        ));
    }
    platform::open_regular_file_for_exact_removal(path)
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

/// Reopen an absolute path without following its final component and require exact file identity.
///
/// # Errors
///
/// Returns a typed capture error, or [`DirectoryIdentityErrorKind::IdentityMismatch`] when the
/// reopened regular file differs from `expected`.
pub fn verify_regular_file_identity(
    path: &Path,
    expected: &RegularFileFilesystemIdentity,
) -> Result<(), DirectoryIdentityError> {
    let actual = RegularFileFilesystemIdentity::capture(path)?;
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

fn valid_identity_encoding(value: &str, prefix: &str) -> bool {
    let Some(encoded) = value.strip_prefix(prefix) else {
        return false;
    };
    if let Some(encoded) = encoded.strip_prefix(WINDOWS_PLATFORM) {
        valid_pair(encoded, WINDOWS_VOLUME_HEX_LEN, WINDOWS_FILE_ID_HEX_LEN)
    } else if let Some(encoded) = encoded.strip_prefix(UNIX_PLATFORM) {
        valid_pair(encoded, UNIX_COMPONENT_HEX_LEN, UNIX_COMPONENT_HEX_LEN)
    } else {
        false
    }
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

    use windows_sys::Wdk::Storage::FileSystem::NtFlushBuffersFileEx;
    use windows_sys::Win32::{
        Foundation::{INVALID_HANDLE_VALUE, RtlNtStatusToDosError},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CreateFileW, DELETE, FILE_ATTRIBUTE_DEVICE,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
            FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_GENERIC_READ, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_WRITE_DATA, FileAttributeTagInfo,
            FileDispositionInfo, FileIdInfo, GetFileInformationByHandle,
            GetFileInformationByHandleEx, GetFileType, OPEN_EXISTING, SetFileInformationByHandle,
        },
        System::IO::IO_STATUS_BLOCK,
    };

    use super::{
        DirectoryFilesystemIdentity, DirectoryIdentityError, DirectoryIdentityErrorKind,
        DirectoryIdentityOperation, ExactRegularFileRemoval, RegularFileFilesystemIdentity,
    };

    pub(super) fn capture(
        path: &Path,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        capture_with_hook(path, || {})
    }

    pub(super) fn open_retained_directory(
        path: &Path,
    ) -> Result<(File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        open_retained_directory_with_hook(path, || {})
    }

    #[cfg(test)]
    pub(super) fn open_retained_directory_after_open(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<(File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        open_retained_directory_with_hook(path, after_open)
    }

    #[cfg(test)]
    pub(super) fn open_retained_directory_without_write(
        path: &Path,
    ) -> Result<(File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        let wide_path = wide_path(path)?;
        let directory = open_directory_handle_with_access(
            &wide_path,
            FILE_GENERIC_READ,
            DirectoryIdentityOperation::OpenDirectory,
        )?;
        let identity = directory_identity_from_file(&directory)?;
        verify_retained_directory_path_wide(&directory, &identity, &wide_path)?;
        Ok((directory, identity))
    }

    fn open_retained_directory_with_hook(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<(File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        let wide_path = wide_path(path)?;
        let directory = open_retained_directory_handle(&wide_path)?;
        after_open();
        let identity = directory_identity_from_file(&directory)?;
        verify_retained_directory_path_wide(&directory, &identity, &wide_path)?;
        Ok((directory, identity))
    }

    pub(super) fn verify_retained_directory_path(
        directory: &File,
        expected: &DirectoryFilesystemIdentity,
        path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        let wide_path = wide_path(path)?;
        verify_retained_directory_path_wide(directory, expected, &wide_path)
    }

    pub(super) fn sync_retained_directory_metadata(
        directory: &File,
        expected: &DirectoryFilesystemIdentity,
        path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        let wide_path = wide_path(path)?;
        verify_retained_directory_path_wide(directory, expected, &wide_path)?;
        // The retained no-delete-sharing handle keeps `wide_path` bound to this exact object while
        // the write-capable flush handle is opened. Identity checks still fail closed if a
        // filesystem does not honor classic Windows sharing semantics.
        let sync_directory = open_directory_handle_with_access(
            &wide_path,
            FILE_GENERIC_READ | FILE_WRITE_DATA,
            DirectoryIdentityOperation::FlushDirectory,
        )?;
        if directory_identity_from_file(&sync_directory)? != *expected {
            return Err(identity_mismatch());
        }

        flush_directory_handle(&sync_directory)?;
        if directory_identity_from_file(&sync_directory)? != *expected {
            return Err(identity_mismatch());
        }
        verify_retained_directory_path_wide(directory, expected, &wide_path)
    }

    fn flush_directory_handle(directory: &File) -> Result<(), DirectoryIdentityError> {
        let mut io_status = IO_STATUS_BLOCK::default();
        // SAFETY: `directory` is a directory handle. Normal mode (`flags == 0`) synchronously
        // requests cached data, metadata, and the backing storage cache; this mode accepts no
        // optional parameter block.
        let status = unsafe {
            NtFlushBuffersFileEx(
                directory.as_raw_handle(),
                0,
                ptr::null(),
                0,
                &raw mut io_status,
            )
        };
        if status != 0 {
            // SAFETY: `status` is the exact failure returned by `NtFlushBuffersFileEx`.
            let os_code = i32::try_from(unsafe { RtlNtStatusToDosError(status) }).ok();
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::OperatingSystem(
                    DirectoryIdentityOperation::FlushDirectory,
                ),
                os_code,
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn flush_directory_handle_for_test(
        directory: &File,
    ) -> Result<(), DirectoryIdentityError> {
        flush_directory_handle(directory)
    }

    fn verify_retained_directory_path_wide(
        directory: &File,
        expected: &DirectoryFilesystemIdentity,
        wide_path: &[u16],
    ) -> Result<(), DirectoryIdentityError> {
        if directory_identity_from_file(directory)? != *expected {
            return Err(identity_mismatch());
        }
        let rebound = open_identity_handle(wide_path, DirectoryIdentityOperation::OpenDirectory)?;
        if directory_identity_from_file(&rebound)? != *expected
            || directory_identity_from_file(directory)? != *expected
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn capture_after_open(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        capture_with_hook(path, after_open)
    }

    fn capture_with_hook(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        let path = wide_path(path)?;
        let directory = open_identity_handle(&path, DirectoryIdentityOperation::OpenDirectory)?;
        after_open();

        let attributes = query_attributes(&directory)?;
        validate_directory_attributes(attributes)?;

        let identity = query_identity(&directory)?;
        validate_directory_attributes(query_attributes(&directory)?)?;
        let rebound = open_identity_handle(&path, DirectoryIdentityOperation::OpenDirectory)?;
        validate_directory_attributes(query_attributes(&rebound)?)?;
        let rebound_identity = query_identity(&rebound)?;
        validate_directory_attributes(query_attributes(&rebound)?)?;
        if !identities_match(&identity, &rebound_identity) {
            return Err(identity_mismatch());
        }
        Ok(DirectoryFilesystemIdentity::from_windows(
            identity.VolumeSerialNumber,
            identity.FileId.Identifier,
        ))
    }

    pub(super) fn capture_regular_file(
        path: &Path,
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        capture_regular_file_with_hook(path, || {})
    }

    pub(super) fn open_retained_regular_file(
        path: &Path,
    ) -> Result<(File, RegularFileFilesystemIdentity), DirectoryIdentityError> {
        let wide_path = wide_path(path)?;
        let file = open_retained_regular_file_handle(&wide_path)?;
        let identity = regular_file_identity_from_file(&file)?;
        verify_retained_regular_file_path_wide(&file, &identity, &wide_path)?;
        Ok((file, identity))
    }

    pub(super) fn verify_retained_regular_file_path(
        file: &File,
        expected: &RegularFileFilesystemIdentity,
        path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        let wide_path = wide_path(path)?;
        verify_retained_regular_file_path_wide(file, expected, &wide_path)
    }

    fn verify_retained_regular_file_path_wide(
        file: &File,
        expected: &RegularFileFilesystemIdentity,
        wide_path: &[u16],
    ) -> Result<(), DirectoryIdentityError> {
        if regular_file_identity_from_file(file)? != *expected {
            return Err(identity_mismatch());
        }
        let rebound = open_identity_handle(wide_path, DirectoryIdentityOperation::OpenRegularFile)?;
        if regular_file_identity_from_file(&rebound)? != *expected
            || regular_file_identity_from_file(file)? != *expected
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }

    pub(super) fn open_regular_file_for_exact_removal(
        path: &Path,
    ) -> Result<ExactRegularFileRemoval, DirectoryIdentityError> {
        let path = wide_path(path)?;
        let file = open_exact_removal_handle(&path)?;
        let identity = regular_file_identity_from_file(&file)?;
        Ok(ExactRegularFileRemoval { file, identity })
    }

    pub(super) fn remove_exact_regular_file(
        removal: ExactRegularFileRemoval,
    ) -> Result<(), DirectoryIdentityError> {
        let ExactRegularFileRemoval { file, identity } = removal;
        let actual = regular_file_identity_from_file(&file)?;
        if actual != identity {
            return Err(identity_mismatch());
        }
        validate_regular_file_information(&file, &query_regular_file_information(&file)?)?;

        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        let size =
            structure_size::<FILE_DISPOSITION_INFO>(DirectoryIdentityOperation::RemoveRegularFile)?;
        // SAFETY: `file` is the retained exact handle opened with DELETE access and `disposition`
        // is readable storage of the exact information-class structure for `size` bytes.
        let succeeded = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size,
            )
        };
        if succeeded == 0 {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::RemoveRegularFile,
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn capture_regular_file_after_open(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        capture_regular_file_with_hook(path, after_open)
    }

    fn capture_regular_file_with_hook(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        let path = wide_path(path)?;
        let file = open_identity_handle(&path, DirectoryIdentityOperation::OpenRegularFile)?;
        after_open();

        let information = query_regular_file_information(&file)?;
        validate_regular_file_information(&file, &information)?;

        let identity = query_identity(&file)?;
        validate_regular_file_information(&file, &query_regular_file_information(&file)?)?;
        let rebound = open_identity_handle(&path, DirectoryIdentityOperation::OpenRegularFile)?;
        validate_regular_file_information(&rebound, &query_regular_file_information(&rebound)?)?;
        let rebound_identity = query_identity(&rebound)?;
        validate_regular_file_information(&rebound, &query_regular_file_information(&rebound)?)?;
        if !identities_match(&identity, &rebound_identity) {
            return Err(identity_mismatch());
        }
        validate_regular_file_information(&file, &query_regular_file_information(&file)?)?;
        Ok(RegularFileFilesystemIdentity::from_windows(
            identity.VolumeSerialNumber,
            identity.FileId.Identifier,
        ))
    }

    fn open_identity_handle(
        path: &[u16],
        operation: DirectoryIdentityOperation,
    ) -> Result<File, DirectoryIdentityError> {
        open_directory_handle_with_access(path, FILE_READ_ATTRIBUTES, operation)
    }

    fn open_retained_directory_handle(path: &[u16]) -> Result<File, DirectoryIdentityError> {
        open_directory_handle_with_access(
            path,
            FILE_GENERIC_READ,
            DirectoryIdentityOperation::OpenDirectory,
        )
    }

    fn open_directory_handle_with_access(
        path: &[u16],
        desired_access: u32,
        operation: DirectoryIdentityOperation,
    ) -> Result<File, DirectoryIdentityError> {
        // SAFETY: `path` is NUL-terminated and all optional pointer parameters are null. The flags
        // open the final component itself and permit classifying directory handles. Omitting
        // delete sharing blocks replacement on filesystems that enforce classic share semantics;
        // the caller also reopens and compares identities before returning.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                desired_access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                operation,
            )));
        }
        // SAFETY: successful `CreateFileW` transferred one owned real handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) fn directory_identity_from_file(
        directory: &File,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        validate_directory_attributes(query_attributes(directory)?)?;
        let identity = query_identity(directory)?;
        validate_directory_attributes(query_attributes(directory)?)?;
        Ok(DirectoryFilesystemIdentity::from_windows(
            identity.VolumeSerialNumber,
            identity.FileId.Identifier,
        ))
    }

    fn open_exact_removal_handle(path: &[u16]) -> Result<File, DirectoryIdentityError> {
        // SAFETY: `path` is NUL-terminated and all optional pointer parameters are null. Opening
        // the final component itself plus omitting write/delete sharing binds rollback authority
        // to this exact object and blocks pathname replacement while the handle remains live.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_GENERIC_READ | DELETE,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::OpenRegularFile,
            )));
        }
        // SAFETY: successful `CreateFileW` transferred one owned real handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn open_retained_regular_file_handle(path: &[u16]) -> Result<File, DirectoryIdentityError> {
        // SAFETY: `path` is NUL-terminated and all optional pointer parameters are null. Opening
        // the final component itself plus omitting write/delete sharing binds reads to this exact
        // object and blocks modification or pathname replacement while the handle remains live.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::OpenRegularFile,
            )));
        }
        // SAFETY: successful `CreateFileW` transferred one owned real handle.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) fn regular_file_identity_from_file(
        file: &File,
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        validate_regular_file_information(file, &query_regular_file_information(file)?)?;
        let identity = query_identity(file)?;
        validate_regular_file_information(file, &query_regular_file_information(file)?)?;
        Ok(RegularFileFilesystemIdentity::from_windows(
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

    fn validate_directory_attributes(
        attributes: FILE_ATTRIBUTE_TAG_INFO,
    ) -> Result<(), DirectoryIdentityError> {
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
        Ok(())
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

    fn query_regular_file_information(
        file: &File,
    ) -> Result<BY_HANDLE_FILE_INFORMATION, DirectoryIdentityError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the retained file owns a live handle and `information` is writable initialized
        // storage of the exact structure expected by `GetFileInformationByHandle`.
        let succeeded =
            unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) };
        if succeeded == 0 {
            return Err(last_error(DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::QueryLinkCount,
            )));
        }
        Ok(information)
    }

    fn validate_regular_file_information(
        file: &File,
        information: &BY_HANDLE_FILE_INFORMATION,
    ) -> Result<(), DirectoryIdentityError> {
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::ReparsePoint,
                None,
            ));
        }
        // SAFETY: `file` owns a live retained handle for the duration of the query.
        if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE) != 0
            || unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::NotRegularFile,
                None,
            ));
        }
        if information.nNumberOfLinks != 1 {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::MultipleLinks,
                None,
            ));
        }
        Ok(())
    }

    fn identities_match(first: &FILE_ID_INFO, second: &FILE_ID_INFO) -> bool {
        first.VolumeSerialNumber == second.VolumeSerialNumber
            && first.FileId.Identifier == second.FileId.Identifier
    }

    fn identity_mismatch() -> DirectoryIdentityError {
        DirectoryIdentityError::new(DirectoryIdentityErrorKind::IdentityMismatch, None)
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
        DirectoryIdentityOperation, RegularFileFilesystemIdentity,
    };

    pub(super) fn capture(
        path: &Path,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        capture_with_hook(path, || {})
    }

    pub(super) fn open_retained_directory(
        path: &Path,
    ) -> Result<(std::fs::File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        open_retained_directory_with_hook(path, || {})
    }

    #[cfg(test)]
    pub(super) fn open_retained_directory_after_open(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<(std::fs::File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        open_retained_directory_with_hook(path, after_open)
    }

    fn open_retained_directory_with_hook(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<(std::fs::File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        let directory = open_directory(path)?;
        after_open();
        let identity = directory_identity_from_file(&directory)?;
        verify_retained_directory_path(&directory, &identity, path)?;
        Ok((directory, identity))
    }

    pub(super) fn verify_retained_directory_path(
        directory: &std::fs::File,
        expected: &DirectoryFilesystemIdentity,
        path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        if directory_identity_from_file(directory)? != *expected {
            return Err(identity_mismatch());
        }
        let rebound = open_directory(path)?;
        if directory_identity_from_file(&rebound)? != *expected
            || directory_identity_from_file(directory)? != *expected
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn capture_after_open(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        capture_with_hook(path, after_open)
    }

    fn capture_with_hook(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        let directory = open_directory(path)?;
        after_open();
        let identity = query_directory_identity(&directory)?;
        let reopened = open_directory(path)?;
        if query_directory_identity(&reopened)? != identity {
            return Err(identity_mismatch());
        }
        Ok(DirectoryFilesystemIdentity::from_unix(
            identity.0, identity.1,
        ))
    }

    fn open_directory(path: &Path) -> Result<std::fs::File, DirectoryIdentityError> {
        reject_final_symlink(path)?;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| open_error(path, &error))
    }

    fn query_directory_identity(
        directory: &std::fs::File,
    ) -> Result<(u64, u64), DirectoryIdentityError> {
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
        Ok((metadata.dev(), metadata.ino()))
    }

    pub(super) fn directory_identity_from_file(
        directory: &std::fs::File,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        let identity = query_directory_identity(directory)?;
        Ok(DirectoryFilesystemIdentity::from_unix(
            identity.0, identity.1,
        ))
    }

    pub(super) fn capture_regular_file(
        path: &Path,
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        capture_regular_file_with_hook(path, || {})
    }

    pub(super) fn open_retained_regular_file(
        path: &Path,
    ) -> Result<(std::fs::File, RegularFileFilesystemIdentity), DirectoryIdentityError> {
        let file = open_regular_file(path)?;
        let identity = regular_file_identity_from_file(&file)?;
        verify_retained_regular_file_path(&file, &identity, path)?;
        Ok((file, identity))
    }

    pub(super) fn verify_retained_regular_file_path(
        file: &std::fs::File,
        expected: &RegularFileFilesystemIdentity,
        path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        if regular_file_identity_from_file(file)? != *expected {
            return Err(identity_mismatch());
        }
        let rebound = open_regular_file(path)?;
        if regular_file_identity_from_file(&rebound)? != *expected
            || regular_file_identity_from_file(file)? != *expected
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }

    pub(super) fn regular_file_identity_from_file(
        file: &std::fs::File,
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        let identity = query_regular_file_identity(file)?;
        if query_regular_file_identity(file)? != identity {
            return Err(identity_mismatch());
        }
        Ok(RegularFileFilesystemIdentity::from_unix(
            identity.0, identity.1,
        ))
    }

    #[cfg(test)]
    pub(super) fn capture_regular_file_after_open(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        capture_regular_file_with_hook(path, after_open)
    }

    fn capture_regular_file_with_hook(
        path: &Path,
        after_open: impl FnOnce(),
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        let file = open_regular_file(path)?;
        after_open();
        let identity = query_regular_file_identity(&file)?;
        let reopened = open_regular_file(path)?;
        if query_regular_file_identity(&reopened)? != identity
            || query_regular_file_identity(&file)? != identity
        {
            return Err(identity_mismatch());
        }
        Ok(RegularFileFilesystemIdentity::from_unix(
            identity.0, identity.1,
        ))
    }

    fn open_regular_file(path: &Path) -> Result<std::fs::File, DirectoryIdentityError> {
        reject_final_symlink(path)?;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)
            .map_err(|error| open_regular_file_error(path, &error))
    }

    fn query_regular_file_identity(
        file: &std::fs::File,
    ) -> Result<(u64, u64), DirectoryIdentityError> {
        let metadata = file.metadata().map_err(|error| {
            DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::OperatingSystem(
                    DirectoryIdentityOperation::QueryMetadata,
                ),
                error.raw_os_error(),
            )
        })?;
        if !metadata.is_file() {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::NotRegularFile,
                None,
            ));
        }
        if metadata.nlink() != 1 {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::MultipleLinks,
                None,
            ));
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    fn reject_final_symlink(path: &Path) -> Result<(), DirectoryIdentityError> {
        if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(DirectoryIdentityError::new(
                DirectoryIdentityErrorKind::ReparsePoint,
                None,
            ));
        }
        Ok(())
    }

    fn open_error(path: &Path, error: &std::io::Error) -> DirectoryIdentityError {
        let os_code = error.raw_os_error();
        let kind = match (final_path_is_symlink(path), os_code) {
            (true, _) | (_, Some(libc::ELOOP)) => DirectoryIdentityErrorKind::ReparsePoint,
            (_, Some(libc::ENOTDIR)) => DirectoryIdentityErrorKind::NotDirectory,
            _ => DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::OpenDirectory,
            ),
        };
        DirectoryIdentityError::new(kind, os_code)
    }

    fn open_regular_file_error(path: &Path, error: &std::io::Error) -> DirectoryIdentityError {
        let os_code = error.raw_os_error();
        let kind = if final_path_is_symlink(path) || os_code == Some(libc::ELOOP) {
            DirectoryIdentityErrorKind::ReparsePoint
        } else {
            DirectoryIdentityErrorKind::OperatingSystem(DirectoryIdentityOperation::OpenRegularFile)
        };
        DirectoryIdentityError::new(kind, os_code)
    }

    fn final_path_is_symlink(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    }

    fn identity_mismatch() -> DirectoryIdentityError {
        DirectoryIdentityError::new(DirectoryIdentityErrorKind::IdentityMismatch, None)
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::path::Path;

    use super::{
        DirectoryFilesystemIdentity, DirectoryIdentityError, DirectoryIdentityErrorKind,
        RegularFileFilesystemIdentity,
    };

    pub(super) fn capture(
        _path: &Path,
    ) -> Result<DirectoryFilesystemIdentity, DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn open_retained_directory(
        _path: &Path,
    ) -> Result<(std::fs::File, DirectoryFilesystemIdentity), DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn verify_retained_directory_path(
        _directory: &std::fs::File,
        _expected: &DirectoryFilesystemIdentity,
        _path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn capture_regular_file(
        _path: &Path,
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn open_retained_regular_file(
        _path: &Path,
    ) -> Result<(std::fs::File, RegularFileFilesystemIdentity), DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn verify_retained_regular_file_path(
        _file: &std::fs::File,
        _expected: &RegularFileFilesystemIdentity,
        _path: &Path,
    ) -> Result<(), DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn regular_file_identity_from_file(
        _file: &std::fs::File,
    ) -> Result<RegularFileFilesystemIdentity, DirectoryIdentityError> {
        Err(DirectoryIdentityError::new(
            DirectoryIdentityErrorKind::UnsupportedPlatform,
            None,
        ))
    }

    pub(super) fn directory_identity_from_file(
        _file: &std::fs::File,
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
    fn retained_directory_identity_matches_same_handle_and_safe_clone() {
        let temporary = tempfile::tempdir().unwrap();
        let retained = RetainedDirectoryIdentity::open(temporary.path()).unwrap();

        assert_eq!(
            retained.identity(),
            &DirectoryFilesystemIdentity::capture(temporary.path()).unwrap()
        );
        assert!(retained.as_file().metadata().unwrap().is_dir());
        assert!(
            retained
                .try_clone_file()
                .unwrap()
                .metadata()
                .unwrap()
                .is_dir()
        );
        retained.verify_path(temporary.path()).unwrap();
        assert!(!format!("{retained:?}").contains(&temporary.path().to_string_lossy()[..]));
    }

    #[test]
    fn directory_identity_can_be_derived_from_a_retained_handle() {
        let temporary = tempfile::tempdir().unwrap();
        let retained = RetainedDirectoryIdentity::open(temporary.path()).unwrap();

        assert_eq!(
            directory_identity_from_file(retained.as_file()).unwrap(),
            *retained.identity()
        );
    }

    #[test]
    fn directory_identity_from_file_rejects_a_regular_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            directory_identity_from_file(file.as_file())
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::NotDirectory
        );
    }

    #[test]
    fn retained_directory_rejects_relative_and_regular_file_paths() {
        assert_eq!(
            RetainedDirectoryIdentity::open(Path::new("relative"))
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::InvalidPath
        );

        let file = tempfile::NamedTempFile::new().unwrap();
        assert_eq!(
            RetainedDirectoryIdentity::open(file.path())
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::NotDirectory
        );

        let missing = file.path().with_extension("missing");
        assert_eq!(
            RetainedDirectoryIdentity::open(&missing)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::OperatingSystem(
                DirectoryIdentityOperation::OpenDirectory
            )
        );
    }

    #[test]
    fn retained_directory_verify_path_rejects_another_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let retained_path = temporary.path().join("retained");
        let other_path = temporary.path().join("other");
        std::fs::create_dir(&retained_path).unwrap();
        std::fs::create_dir(&other_path).unwrap();
        let retained = RetainedDirectoryIdentity::open(&retained_path).unwrap();

        assert_eq!(
            retained.verify_path(&other_path).unwrap_err().kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
        assert_eq!(
            retained
                .verify_path(Path::new("relative"))
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::InvalidPath
        );
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

        let regular_file =
            "rustferry-regular-file-v1:windows:0000000000000001:00112233445566778899aabbccddeeff";
        assert!(
            regular_file
                .parse::<RegularFileFilesystemIdentity>()
                .is_ok()
        );
        assert!(regular_file.parse::<DirectoryFilesystemIdentity>().is_err());
        assert!(
            valid_windows
                .parse::<RegularFileFilesystemIdentity>()
                .is_err()
        );
        assert!(
            "rustferry-regular-file-v1:unix:0000000000000001:000000000000000G"
                .parse::<RegularFileFilesystemIdentity>()
                .is_err()
        );
    }

    #[test]
    fn regular_file_identity_is_stable_across_reopen() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        std::fs::write(&artifact, b"artifact").unwrap();

        let first = RegularFileFilesystemIdentity::capture(&artifact).unwrap();
        let second = RegularFileFilesystemIdentity::capture(&artifact).unwrap();
        let restored = first
            .to_string()
            .parse::<RegularFileFilesystemIdentity>()
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first, restored);
        assert!(first.as_str().is_ascii());
        assert!(
            !first
                .as_str()
                .contains(&temporary.path().to_string_lossy()[..])
        );
        verify_regular_file_identity(&artifact, &restored).unwrap();
    }

    #[test]
    fn retained_file_identity_matches_the_path_capture() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        let retained = std::fs::File::open(&artifact).unwrap();

        assert_eq!(
            regular_file_identity_from_file(&retained).unwrap(),
            RegularFileFilesystemIdentity::capture(&artifact).unwrap()
        );
    }

    #[test]
    fn retained_file_identity_does_not_reopen_a_replacement_path() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();
        let retained = std::fs::File::open(&artifact).unwrap();
        let original = regular_file_identity_from_file(&retained).unwrap();

        std::fs::rename(&artifact, &displaced).unwrap();
        std::fs::write(&artifact, b"replacement").unwrap();

        assert_eq!(
            regular_file_identity_from_file(&retained).unwrap(),
            original
        );
        assert_ne!(
            RegularFileFilesystemIdentity::capture(&artifact).unwrap(),
            original
        );
    }

    #[test]
    fn retained_file_identity_rejects_a_hardlink_added_after_open() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let linked = temporary.path().join("linked.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        let retained = std::fs::File::open(&artifact).unwrap();

        std::fs::hard_link(&artifact, &linked).unwrap();

        assert_eq!(
            regular_file_identity_from_file(&retained)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::MultipleLinks
        );
    }

    #[test]
    fn replacement_regular_file_has_a_different_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();
        let original = RegularFileFilesystemIdentity::capture(&artifact).unwrap();

        std::fs::rename(&artifact, &displaced).unwrap();
        std::fs::write(&artifact, b"replacement").unwrap();
        let replacement = RegularFileFilesystemIdentity::capture(&artifact).unwrap();

        assert_ne!(original, replacement);
        assert_eq!(
            verify_regular_file_identity(&artifact, &original)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
    }

    #[cfg(unix)]
    #[test]
    fn directory_capture_rejects_after_open_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();

        let error = platform::capture_after_open(&project, || {
            std::fs::rename(&project, &displaced).unwrap();
            std::fs::create_dir(&project).unwrap();
        })
        .unwrap_err();

        assert_eq!(error.kind(), DirectoryIdentityErrorKind::IdentityMismatch);
    }

    #[cfg(unix)]
    #[test]
    fn retained_directory_open_rejects_initial_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();

        let error = platform::open_retained_directory_after_open(&project, || {
            std::fs::rename(&project, &displaced).unwrap();
            std::fs::create_dir(&project).unwrap();
        })
        .unwrap_err();

        assert_eq!(error.kind(), DirectoryIdentityErrorKind::IdentityMismatch);
    }

    #[cfg(unix)]
    #[test]
    fn retained_unix_descriptor_detects_but_does_not_block_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        let retained = RetainedDirectoryIdentity::open(&project).unwrap();
        let original = retained.identity().clone();

        std::fs::rename(&project, &displaced).unwrap();
        std::fs::create_dir(&project).unwrap();

        assert!(retained.as_file().metadata().unwrap().is_dir());
        assert_eq!(
            retained.verify_path(&project).unwrap_err().kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
        assert_eq!(
            DirectoryFilesystemIdentity::capture(&displaced).unwrap(),
            original
        );
    }

    #[cfg(unix)]
    #[test]
    fn regular_file_capture_rejects_after_open_path_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();

        let error = platform::capture_regular_file_after_open(&artifact, || {
            std::fs::rename(&artifact, &displaced).unwrap();
            std::fs::write(&artifact, b"replacement").unwrap();
        })
        .unwrap_err();

        assert_eq!(error.kind(), DirectoryIdentityErrorKind::IdentityMismatch);
    }

    #[cfg(windows)]
    #[test]
    fn directory_capture_blocks_or_rejects_after_open_path_replacement() {
        use std::cell::Cell;

        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        let replaced = Cell::new(false);

        let result = platform::capture_after_open(&project, || {
            if std::fs::rename(&project, &displaced).is_ok() {
                std::fs::create_dir(&project).unwrap();
                replaced.set(true);
            }
        });

        if replaced.get() {
            assert_eq!(
                result.unwrap_err().kind(),
                DirectoryIdentityErrorKind::IdentityMismatch
            );
        } else {
            verify_directory_identity(&project, &result.unwrap()).unwrap();
            assert!(!displaced.exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_handle_blocks_replacement_until_all_clones_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        let retained = RetainedDirectoryIdentity::open(&project).unwrap();
        let original = retained.identity().clone();
        let clone = retained.try_clone_file().unwrap();

        assert!(std::fs::rename(&project, &displaced).is_err());
        assert!(std::fs::remove_dir(&project).is_err());
        retained.verify_path(&project).unwrap();
        drop(retained);
        assert!(std::fs::rename(&project, &displaced).is_err());
        drop(clone);

        std::fs::rename(&project, &displaced).unwrap();
        std::fs::create_dir(&project).unwrap();
        assert_eq!(
            verify_directory_identity(&project, &original)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_ordinary_parent_flushes_strict_child_namespace() {
        let temporary = tempfile::tempdir().unwrap();
        let parent_path = temporary.path().join("ordinary-parent");
        let displaced = temporary.path().join("displaced-parent");
        let child_path = parent_path.join("private-child");
        std::fs::create_dir(&parent_path).unwrap();
        let parent = RetainedDirectoryIdentity::open(&parent_path).unwrap();
        let child =
            crate::windows_private_directory::create_private_directory(&child_path).unwrap();

        parent.sync_metadata(&parent_path).unwrap();
        parent.verify_path(&parent_path).unwrap();
        assert!(child_path.is_dir());
        assert!(std::fs::rename(&parent_path, &displaced).is_err());

        drop(child);
        std::fs::remove_dir(&child_path).unwrap();
        parent.sync_metadata(&parent_path).unwrap();
        drop(parent);

        std::fs::rename(&parent_path, &displaced).unwrap();
        std::fs::remove_dir(&displaced).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn read_only_directory_handle_flush_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let parent_path = temporary.path().join("ordinary-parent");
        std::fs::create_dir(&parent_path).unwrap();
        let (file, identity) =
            platform::open_retained_directory_without_write(&parent_path).unwrap();
        let error = platform::flush_directory_handle_for_test(&file).unwrap_err();
        assert_eq!(
            error.kind(),
            DirectoryIdentityErrorKind::OperatingSystem(DirectoryIdentityOperation::FlushDirectory)
        );
        assert_eq!(error.os_code(), Some(5));
        platform::verify_retained_directory_path(&file, &identity, &parent_path).unwrap();
        assert!(parent_path.is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn retained_system_directory_does_not_require_write_access() {
        let system_directory = crate::windows_system_root().unwrap().join("System32");
        let retained = RetainedDirectoryIdentity::open(&system_directory).unwrap();
        retained.verify_path(&system_directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_open_blocks_or_rejects_initial_replacement() {
        use std::cell::Cell;

        let temporary = tempfile::tempdir().unwrap();
        let project = temporary.path().join("project");
        let displaced = temporary.path().join("displaced");
        std::fs::create_dir(&project).unwrap();
        let replaced = Cell::new(false);

        let result = platform::open_retained_directory_after_open(&project, || {
            if std::fs::rename(&project, &displaced).is_ok() {
                std::fs::create_dir(&project).unwrap();
                replaced.set(true);
            }
        });

        if replaced.get() {
            assert_eq!(
                result.unwrap_err().kind(),
                DirectoryIdentityErrorKind::IdentityMismatch
            );
        } else {
            let (file, identity) = result.unwrap();
            assert!(file.metadata().unwrap().is_dir());
            assert_eq!(
                identity,
                DirectoryFilesystemIdentity::capture(&project).unwrap()
            );
            assert!(!displaced.exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn regular_file_capture_blocks_or_rejects_after_open_path_replacement() {
        use std::cell::Cell;

        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();
        let replaced = Cell::new(false);

        let result = platform::capture_regular_file_after_open(&artifact, || {
            if std::fs::rename(&artifact, &displaced).is_ok() {
                std::fs::write(&artifact, b"replacement").unwrap();
                replaced.set(true);
            }
        });

        if replaced.get() {
            assert_eq!(
                result.unwrap_err().kind(),
                DirectoryIdentityErrorKind::IdentityMismatch
            );
        } else {
            verify_regular_file_identity(&artifact, &result.unwrap()).unwrap();
            assert!(!displaced.exists());
        }
    }

    #[test]
    fn regular_file_identity_rejects_relative_and_directory_paths() {
        assert_eq!(
            RegularFileFilesystemIdentity::capture(Path::new("relative"))
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::InvalidPath
        );

        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            RegularFileFilesystemIdentity::capture(directory.path())
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::NotRegularFile
        );
    }

    #[test]
    fn regular_file_identity_rejects_multiple_links() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let linked = temporary.path().join("linked.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        let identity = RegularFileFilesystemIdentity::capture(&artifact).unwrap();
        std::fs::hard_link(&artifact, &linked).unwrap();

        assert_eq!(
            RegularFileFilesystemIdentity::capture(&artifact)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::MultipleLinks
        );
        assert_eq!(
            verify_regular_file_identity(&artifact, &identity)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::MultipleLinks
        );
        assert_eq!(
            RetainedRegularFileIdentity::open(&artifact)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::MultipleLinks
        );
    }

    #[test]
    fn retained_regular_file_identity_rejects_mismatched_path() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let other = temporary.path().join("other.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        std::fs::write(&other, b"other").unwrap();
        let retained = RetainedRegularFileIdentity::open(&artifact).unwrap();

        assert_eq!(
            retained.verify_path(&other).unwrap_err().kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
        retained.verify_path(&artifact).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn retained_regular_file_blocks_modification_and_replacement_until_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();
        let retained = RetainedRegularFileIdentity::open(&artifact).unwrap();
        let expected = retained.identity().clone();

        assert!(std::fs::write(&artifact, b"modified").is_err());
        assert!(std::fs::rename(&artifact, &displaced).is_err());
        assert!(std::fs::remove_file(&artifact).is_err());
        retained.verify_path(&artifact).unwrap();
        drop(retained);

        std::fs::rename(&artifact, &displaced).unwrap();
        std::fs::write(&artifact, b"replacement").unwrap();
        assert_eq!(
            verify_regular_file_identity(&artifact, &expected)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_regular_file_detects_unix_namespace_rebinding() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();
        let retained = RetainedRegularFileIdentity::open(&artifact).unwrap();

        std::fs::rename(&artifact, &displaced).unwrap();
        std::fs::write(&artifact, b"replacement").unwrap();
        assert_eq!(
            retained.verify_path(&artifact).unwrap_err().kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
        assert_eq!(std::fs::read(&displaced).unwrap(), b"original");
    }

    #[cfg(windows)]
    #[test]
    fn retained_regular_file_supports_long_windows_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let mut parent = temporary.path().to_path_buf();
        while parent.as_os_str().len() < 280 {
            parent.push("retained-identity");
        }
        std::fs::create_dir_all(&parent).unwrap();
        let artifact = parent.join("artifact.bin");
        std::fs::write(&artifact, b"artifact").unwrap();

        let retained = RetainedRegularFileIdentity::open(&artifact).unwrap();
        retained.verify_path(&artifact).unwrap();
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

        assert_eq!(
            DirectoryFilesystemIdentity::capture(&link)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
        assert_eq!(
            RetainedDirectoryIdentity::open(&link).unwrap_err().kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
    }

    #[cfg(unix)]
    #[test]
    fn final_file_symbolic_link_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target.bin");
        let link = temporary.path().join("link.bin");
        std::fs::write(&target, b"artifact").unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(
            RegularFileFilesystemIdentity::capture(&link)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
        assert_eq!(
            RetainedRegularFileIdentity::open(&link).unwrap_err().kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
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
        assert_eq!(
            RetainedDirectoryIdentity::open(&link).unwrap_err().kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
    }

    #[cfg(windows)]
    #[test]
    fn final_file_reparse_point_is_rejected_when_supported() {
        use std::os::windows::fs::symlink_file;

        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target.bin");
        let link = temporary.path().join("link.bin");
        std::fs::write(&target, b"artifact").unwrap();
        if let Err(error) = symlink_file(&target, &link) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("could not create test file symlink: {error}");
        }

        assert_eq!(
            RegularFileFilesystemIdentity::capture(&link)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
        assert_eq!(
            RetainedRegularFileIdentity::open(&link).unwrap_err().kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
    }

    #[cfg(windows)]
    #[test]
    fn exact_regular_file_removal_is_handle_bound_and_preserves_replacement() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let displaced = temporary.path().join("displaced.bin");
        std::fs::write(&artifact, b"original").unwrap();
        let expected = RegularFileFilesystemIdentity::capture(&artifact).unwrap();

        let removal = open_regular_file_for_exact_removal(&artifact).unwrap();
        assert_eq!(removal.identity(), &expected);

        if std::fs::rename(&artifact, &displaced).is_ok() {
            std::fs::write(&artifact, b"replacement").unwrap();
            removal.remove().unwrap();

            assert_eq!(std::fs::read(&artifact).unwrap(), b"replacement");
            assert!(!displaced.exists());
        } else {
            assert!(std::fs::write(&artifact, b"replacement").is_err());
            removal.remove().unwrap();

            assert!(!artifact.exists());
            assert!(!displaced.exists());
        }
    }

    #[cfg(windows)]
    #[test]
    fn exact_regular_file_removal_revalidates_retained_identity() {
        let temporary = tempfile::tempdir().unwrap();
        let artifact = temporary.path().join("artifact.bin");
        let other = temporary.path().join("other.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        std::fs::write(&other, b"other").unwrap();

        let removal = open_regular_file_for_exact_removal(&artifact).unwrap();
        let wrong_identity = RegularFileFilesystemIdentity::capture(&other).unwrap();
        let removal = ExactRegularFileRemoval {
            file: removal.file,
            identity: wrong_identity,
        };

        assert_eq!(
            removal.remove().unwrap_err().kind(),
            DirectoryIdentityErrorKind::IdentityMismatch
        );
        assert_eq!(std::fs::read(&artifact).unwrap(), b"artifact");
        assert_eq!(std::fs::read(&other).unwrap(), b"other");
    }

    #[cfg(windows)]
    #[test]
    fn exact_regular_file_removal_rejects_hardlinks_before_and_after_open() {
        let temporary = tempfile::tempdir().unwrap();
        let linked_before = temporary.path().join("linked-before.bin");
        let before = temporary.path().join("before.bin");
        std::fs::write(&before, b"before").unwrap();
        std::fs::hard_link(&before, &linked_before).unwrap();

        assert_eq!(
            open_regular_file_for_exact_removal(&before)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::MultipleLinks
        );

        let after = temporary.path().join("after.bin");
        let linked_after = temporary.path().join("linked-after.bin");
        std::fs::write(&after, b"after").unwrap();
        let removal = open_regular_file_for_exact_removal(&after).unwrap();

        std::fs::hard_link(&after, &linked_after).unwrap();
        assert_eq!(
            removal.remove().unwrap_err().kind(),
            DirectoryIdentityErrorKind::MultipleLinks
        );
        assert_eq!(std::fs::read(&after).unwrap(), b"after");
        assert_eq!(std::fs::read(&linked_after).unwrap(), b"after");
    }

    #[cfg(windows)]
    #[test]
    fn exact_regular_file_removal_rejects_reparse_and_directory_targets_when_supported() {
        use std::os::windows::fs::symlink_file;

        let temporary = tempfile::tempdir().unwrap();
        assert_eq!(
            open_regular_file_for_exact_removal(temporary.path())
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::NotRegularFile
        );

        let target = temporary.path().join("target.bin");
        let link = temporary.path().join("link.bin");
        std::fs::write(&target, b"artifact").unwrap();
        if let Err(error) = symlink_file(&target, &link) {
            if error.kind() == std::io::ErrorKind::PermissionDenied
                || error.raw_os_error() == Some(1314)
            {
                return;
            }
            panic!("could not create test file symlink: {error}");
        }

        assert_eq!(
            open_regular_file_for_exact_removal(&link)
                .unwrap_err()
                .kind(),
            DirectoryIdentityErrorKind::ReparsePoint
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"artifact");
        assert!(link.exists());
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
        let retained = RetainedDirectoryIdentity::open(&directory).unwrap();
        assert_eq!(retained.identity(), &identity);
        retained.verify_path(&directory).unwrap();
        retained.sync_metadata(&directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn long_absolute_regular_file_path_is_supported() {
        use std::os::windows::ffi::OsStrExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let mut directory = temporary.path().to_owned();
        let mut segment = 0_u32;
        while directory.as_os_str().encode_wide().count() <= 300 {
            directory.push(format!("long-artifact-directory-segment-{segment:02}"));
            std::fs::create_dir(&directory).unwrap();
            segment += 1;
        }
        let artifact = directory.join("artifact.bin");
        std::fs::write(&artifact, b"artifact").unwrap();

        let identity = RegularFileFilesystemIdentity::capture(&artifact).unwrap();
        verify_regular_file_identity(&artifact, &identity).unwrap();
    }
}
