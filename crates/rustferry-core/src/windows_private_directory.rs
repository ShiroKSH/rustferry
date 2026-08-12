//! Atomic private filesystem-object creation and handle validation on Windows.

#![cfg_attr(windows, allow(unsafe_code))]

use std::{error::Error, fmt};

#[cfg(any(windows, test))]
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
#[cfg(any(windows, test))]
const ACL_REVISION: u8 = 2;
#[cfg(any(windows, test))]
const DIRECTORY_INHERIT_FLAGS: u8 = 0x01 | 0x02;
#[cfg(any(windows, test))]
const FILE_ACE_FLAGS: u8 = 0;
#[cfg(any(windows, test))]
const FILE_ALL_ACCESS_MASK: u32 = 0x001f_01ff;
#[cfg(any(windows, test))]
const ACL_HEADER_BYTES: usize = 8;
#[cfg(any(windows, test))]
const ACE_HEADER_BYTES: usize = 4;
#[cfg(any(windows, test))]
const ACCESS_ALLOWED_ACE_PREFIX_BYTES: usize = 8;
#[cfg(any(windows, test))]
const SID_HEADER_BYTES: usize = 8;
#[cfg(any(windows, test))]
const SID_REVISION: u8 = 1;
#[cfg(any(windows, test))]
const SID_MAX_SUB_AUTHORITIES: u8 = 15;

/// Windows operation that failed while creating or inspecting a private directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivateDirectoryOperation {
    /// Read the current process-token user SID.
    QueryProcessToken,
    /// Construct a well-known Windows SID.
    CreateWellKnownSid,
    /// Construct the explicit directory DACL.
    BuildAcl,
    /// Construct the absolute security descriptor.
    BuildSecurityDescriptor,
    /// Atomically create the named directory.
    CreateDirectory,
    /// Atomically create the named regular file.
    CreateFile,
    /// Open an existing regular file without following a reparse point.
    OpenFile,
    /// Open the newly created directory without following a reparse point.
    OpenDirectory,
    /// Read directory attributes from the retained handle.
    QueryAttributes,
    /// Resolve the stable DOS path of a retained no-delete-sharing directory handle.
    ResolvePath,
    /// Enumerate file identifiers through a retained directory handle.
    EnumerateDirectory,
    /// Open one enumerated directory-tree entry without following reparse points.
    OpenTreeEntry,
    /// Read filesystem capabilities from the retained handle.
    QueryFileSystem,
    /// Flush retained directory metadata through the exact handle.
    FlushDirectory,
    /// Read the security descriptor from the retained handle.
    QuerySecurityDescriptor,
    /// Mark the exact retained directory object for deletion.
    RemoveDirectory,
    /// Mark the exact retained regular-file link for deletion.
    RemoveFile,
    /// Atomically rename a retained private file into a retained directory.
    RenameFile,
}

/// Expected hard-link state for a private regular-file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivateFileLinkState {
    /// A normal private file with one filesystem link.
    Single,
    /// A staging file during create-only publication, with staging and final links.
    PublicationPair,
}

impl PrivateFileLinkState {
    #[cfg(windows)]
    const fn expected_links(self) -> u32 {
        match self {
            Self::Single => 1,
            Self::PublicationPair => 2,
        }
    }
}

/// Exact ACL-policy mismatch found on a retained directory handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivateDirectoryAclViolation {
    /// The ACL or one of its ACE records is structurally malformed.
    Malformed,
    /// The ACL uses a revision other than the supported basic ACL revision.
    WrongRevision,
    /// The ACL does not contain exactly one ACE per unique allowed principal.
    WrongAceCount,
    /// An ACE is not a basic access-allowed ACE.
    UnsupportedAceType,
    /// An ACE has flags other than object and container inheritance.
    UnexpectedAceFlags,
    /// An ACE grants a mask other than full file access.
    UnexpectedAccessMask,
    /// An ACE contains a malformed SID.
    InvalidSid,
    /// An ACE grants access to a principal outside the allowlist.
    UnknownPrincipal,
    /// More than one ACE grants access to the same allowed principal.
    DuplicatePrincipal,
    /// One of the three required principals is absent.
    MissingPrincipal,
}

/// Security or platform reason a private directory was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivateDirectoryErrorKind {
    /// The supplied Windows path contains an interior NUL.
    InvalidPath,
    /// Atomic creation failed because an object already occupies the path.
    AlreadyExists,
    /// A Windows API failed.
    WindowsApi(PrivateDirectoryOperation),
    /// The filesystem does not advertise persistent ACL support.
    UnsupportedFileSystem,
    /// The retained handle does not identify a directory.
    NotDirectory,
    /// The retained handle does not identify a regular file.
    NotRegularFile,
    /// The retained handle identifies a reparse point.
    ReparsePoint,
    /// A private regular file has a hard-link count that differs from the expected state.
    MultipleLinks,
    /// A pathname entry no longer identifies the object enumerated through its parent handle.
    IdentityMismatch,
    /// The security descriptor has no owner SID.
    OwnerMissing,
    /// The directory owner is not the current process-token user.
    OwnerMismatch,
    /// The security descriptor has no non-NULL DACL.
    DaclMissing,
    /// The DACL is not protected from parent inheritance.
    DaclUnprotected,
    /// The DACL does not exactly match the private-directory allowlist.
    DaclPolicy(PrivateDirectoryAclViolation),
}

/// Cleanup state after private-directory creation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivateDirectoryCleanupStatus {
    /// No directory was created, or this was a standalone handle verification.
    NotRequired,
    /// The exact retained directory object was marked for deletion.
    Confirmed,
    /// Identity-bound cleanup could not be performed or confirmed.
    Uncertain,
}

/// Sanitized, typed failure from private-directory creation or verification.
#[derive(Debug)]
pub struct PrivateDirectoryError {
    kind: PrivateDirectoryErrorKind,
    cleanup: PrivateDirectoryCleanupStatus,
    os_code: Option<i32>,
    cleanup_os_code: Option<i32>,
}

impl PrivateDirectoryError {
    #[cfg(windows)]
    const fn new(kind: PrivateDirectoryErrorKind, os_code: Option<i32>) -> Self {
        Self {
            kind,
            cleanup: PrivateDirectoryCleanupStatus::NotRequired,
            os_code,
            cleanup_os_code: None,
        }
    }

    /// Return the stable failure classification.
    pub const fn kind(&self) -> PrivateDirectoryErrorKind {
        self.kind
    }

    /// Return whether identity-bound cleanup was needed and confirmed.
    pub const fn cleanup_status(&self) -> PrivateDirectoryCleanupStatus {
        self.cleanup
    }

    /// Return the raw Windows error code, when the primary failure came from Windows.
    pub const fn os_code(&self) -> Option<i32> {
        self.os_code
    }

    /// Return the raw Windows cleanup error code when cleanup is uncertain.
    pub const fn cleanup_os_code(&self) -> Option<i32> {
        self.cleanup_os_code
    }

    #[cfg(windows)]
    fn with_cleanup(
        mut self,
        cleanup: PrivateDirectoryCleanupStatus,
        cleanup_os_code: Option<i32>,
    ) -> Self {
        self.cleanup = cleanup;
        self.cleanup_os_code = cleanup_os_code;
        self
    }
}

impl fmt::Display for PrivateDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "private filesystem object rejected: {:?}",
            self.kind
        )?;
        if let Some(code) = self.os_code {
            write!(formatter, " (Windows error {code})")?;
        }
        if self.cleanup == PrivateDirectoryCleanupStatus::Uncertain {
            write!(formatter, "; identity-bound cleanup is uncertain")?;
            if let Some(code) = self.cleanup_os_code {
                write!(formatter, " (Windows error {code})")?;
            }
        }
        Ok(())
    }
}

impl Error for PrivateDirectoryError {}

/// Whether a failed handle-bound private-file publication changed the destination namespace.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivatePublicationPhase {
    /// The handle-bound rename was not reported successful, so the staging name remains authoritative.
    Unpublished,
    /// The rename succeeded, but a handle-bound postcondition could not be confirmed.
    CommitUncertain,
}

/// Recoverable failure from handle-bound private-file publication.
///
/// The exact input file handle is always retained. Callers must branch on [`Self::phase`] before
/// deciding which durable record or namespace entry is authoritative; they must never fall back to
/// deleting a pathname after this error.
#[cfg(windows)]
#[derive(Debug)]
pub struct PrivatePublicationError {
    phase: PrivatePublicationPhase,
    file: std::fs::File,
    error: PrivateDirectoryError,
}

#[cfg(windows)]
impl PrivatePublicationError {
    fn new(
        phase: PrivatePublicationPhase,
        file: std::fs::File,
        error: PrivateDirectoryError,
    ) -> Self {
        Self { phase, file, error }
    }

    /// Return the namespace phase reached before publication failed.
    pub const fn phase(&self) -> PrivatePublicationPhase {
        self.phase
    }

    /// Return the underlying strict-policy or Windows failure.
    pub const fn error(&self) -> &PrivateDirectoryError {
        &self.error
    }

    /// Borrow the exact retained file involved in the attempted publication.
    pub const fn retained_file(&self) -> &std::fs::File {
        &self.file
    }

    /// Recover the phase, exact retained file, and underlying failure.
    pub fn into_parts(
        self,
    ) -> (
        PrivatePublicationPhase,
        std::fs::File,
        PrivateDirectoryError,
    ) {
        (self.phase, self.file, self.error)
    }
}

#[cfg(windows)]
impl fmt::Display for PrivatePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "private file publication failed in phase {:?}: {}",
            self.phase, self.error
        )
    }
}

#[cfg(windows)]
impl Error for PrivatePublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// Exact-handle state retained when legacy hard-link publication recovery fails.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PrivatePublicationPairPhase {
    /// Removal of the staging link was not reported successful; the retained handle is staging.
    PairIntact,
    /// The staging link was removed; the retained exact final handle still permits delete sharing.
    FinalSingleSharedDelete,
    /// A no-write/no-delete-sharing exact final handle was acquired, but validation failed.
    FinalSingleSealed,
}

/// Recoverable failure while collapsing a legacy private publication hard-link pair.
#[cfg(windows)]
#[derive(Debug)]
pub struct PrivatePublicationPairError {
    phase: PrivatePublicationPairPhase,
    file: std::fs::File,
    error: PrivateDirectoryError,
}

#[cfg(windows)]
impl PrivatePublicationPairError {
    fn new(
        phase: PrivatePublicationPairPhase,
        file: std::fs::File,
        error: PrivateDirectoryError,
    ) -> Self {
        Self { phase, file, error }
    }

    /// Return the exact-handle phase reached before recovery failed.
    pub const fn phase(&self) -> PrivatePublicationPairPhase {
        self.phase
    }

    /// Return the underlying strict-policy or Windows failure.
    pub const fn error(&self) -> &PrivateDirectoryError {
        &self.error
    }

    /// Borrow the exact retained staging or final file.
    pub const fn retained_file(&self) -> &std::fs::File {
        &self.file
    }

    /// Recover the phase, exact retained file, and underlying failure.
    pub fn into_parts(
        self,
    ) -> (
        PrivatePublicationPairPhase,
        std::fs::File,
        PrivateDirectoryError,
    ) {
        (self.phase, self.file, self.error)
    }
}

#[cfg(windows)]
impl fmt::Display for PrivatePublicationPairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "private publication-pair recovery failed in phase {:?}: {}",
            self.phase, self.error
        )
    }
}

#[cfg(windows)]
impl Error for PrivatePublicationPairError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(test)]
fn validate_acl(raw: &[u8], principals: &[&[u8]]) -> Result<(), PrivateDirectoryAclViolation> {
    validate_acl_with_flags(raw, principals, DIRECTORY_INHERIT_FLAGS)
}

#[cfg(any(windows, test))]
fn validate_acl_with_flags(
    raw: &[u8],
    principals: &[&[u8]],
    expected_flags: u8,
) -> Result<(), PrivateDirectoryAclViolation> {
    if raw.len() < ACL_HEADER_BYTES {
        return Err(PrivateDirectoryAclViolation::Malformed);
    }
    if raw[0] != ACL_REVISION {
        return Err(PrivateDirectoryAclViolation::WrongRevision);
    }
    let declared_size = usize::from(u16::from_le_bytes([raw[2], raw[3]]));
    if declared_size != raw.len() {
        return Err(PrivateDirectoryAclViolation::Malformed);
    }
    let ace_count = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
    if ace_count != principals.len() {
        return Err(PrivateDirectoryAclViolation::WrongAceCount);
    }

    let mut found = vec![false; principals.len()];
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..ace_count {
        let header = raw
            .get(offset..offset + ACE_HEADER_BYTES)
            .ok_or(PrivateDirectoryAclViolation::Malformed)?;
        if header[0] != ACCESS_ALLOWED_ACE_TYPE {
            return Err(PrivateDirectoryAclViolation::UnsupportedAceType);
        }
        if header[1] != expected_flags {
            return Err(PrivateDirectoryAclViolation::UnexpectedAceFlags);
        }
        let ace_size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if ace_size < ACCESS_ALLOWED_ACE_PREFIX_BYTES + SID_HEADER_BYTES || ace_size % 4 != 0 {
            return Err(PrivateDirectoryAclViolation::Malformed);
        }
        let end = offset
            .checked_add(ace_size)
            .filter(|end| *end <= raw.len())
            .ok_or(PrivateDirectoryAclViolation::Malformed)?;
        let mask = u32::from_le_bytes(
            raw[offset + ACE_HEADER_BYTES..offset + ACCESS_ALLOWED_ACE_PREFIX_BYTES]
                .try_into()
                .map_err(|_| PrivateDirectoryAclViolation::Malformed)?,
        );
        if mask != FILE_ALL_ACCESS_MASK {
            return Err(PrivateDirectoryAclViolation::UnexpectedAccessMask);
        }
        let sid = &raw[offset + ACCESS_ALLOWED_ACE_PREFIX_BYTES..end];
        if !valid_sid_bytes(sid) {
            return Err(PrivateDirectoryAclViolation::InvalidSid);
        }
        let principal = principals
            .iter()
            .position(|expected| *expected == sid)
            .ok_or(PrivateDirectoryAclViolation::UnknownPrincipal)?;
        if found[principal] {
            return Err(PrivateDirectoryAclViolation::DuplicatePrincipal);
        }
        found[principal] = true;
        offset = end;
    }
    if !raw[offset..].iter().all(|byte| *byte == 0) {
        return Err(PrivateDirectoryAclViolation::Malformed);
    }
    if found.iter().all(|present| *present) {
        Ok(())
    } else {
        Err(PrivateDirectoryAclViolation::MissingPrincipal)
    }
}

#[cfg(any(windows, test))]
fn valid_sid_bytes(sid: &[u8]) -> bool {
    let Some(header) = sid.get(..SID_HEADER_BYTES) else {
        return false;
    };
    let sub_authorities = header[1];
    if header[0] != SID_REVISION || sub_authorities > SID_MAX_SUB_AUTHORITIES {
        return false;
    }
    SID_HEADER_BYTES
        .checked_add(usize::from(sub_authorities) * size_of::<u32>())
        .is_some_and(|expected| expected == sid.len())
}

#[cfg(windows)]
mod platform {
    use std::{
        collections::BTreeSet,
        ffi::c_void,
        ffi::{OsStr, OsString},
        fs::File,
        io,
        mem::{offset_of, size_of, size_of_val},
        os::windows::{
            ffi::{OsStrExt as _, OsStringExt as _},
            io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle},
        },
        path::{Component, Path, PathBuf},
        ptr, slice,
    };

    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtFlushBuffersFileEx, NtSetInformationFile,
    };
    use windows_sys::Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER,
            ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE, RtlNtStatusToDosError,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CopySid,
            CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, GetLengthSid,
            GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
            GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
            IsValidSecurityDescriptor, IsValidSid, OWNER_SECURITY_INFORMATION, PSID,
            SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
            SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
            TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        },
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
            FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, FileDispositionInfo,
            FileDispositionInfoEx, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo,
            FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
            GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, OPEN_EXISTING, ReOpenFile,
            SetFileInformationByHandle, WRITE_DAC,
        },
        System::{
            IO::IO_STATUS_BLOCK,
            SystemServices::{FILE_PERSISTENT_ACLS, SECURITY_DESCRIPTOR_REVISION},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    use super::{
        DIRECTORY_INHERIT_FLAGS, FILE_ACE_FLAGS, PrivateDirectoryAclViolation,
        PrivateDirectoryCleanupStatus, PrivateDirectoryError, PrivateDirectoryErrorKind,
        PrivateDirectoryOperation, PrivateFileLinkState, PrivatePublicationError,
        PrivatePublicationPairError, PrivatePublicationPairPhase, PrivatePublicationPhase,
        SID_HEADER_BYTES, valid_sid_bytes, validate_acl_with_flags,
    };

    const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 128 * 1024;
    const DIRECTORY_ENUMERATION_BUFFER_BYTES: usize = 64 * 1024;

    #[derive(Debug, Eq, PartialEq)]
    struct DirectoryEntryIdentity {
        name: OsString,
        file_id: [u8; 16],
    }

    enum BoundTreeEntry {
        Directory { handle: File, path: PathBuf },
        RegularFile(File),
    }

    #[derive(Clone, Copy)]
    enum PrivateObjectKind {
        Directory,
        RegularFile(PrivateFileLinkState),
    }

    impl PrivateObjectKind {
        const fn ace_flags(self) -> u8 {
            match self {
                Self::Directory => DIRECTORY_INHERIT_FLAGS,
                Self::RegularFile(_) => FILE_ACE_FLAGS,
            }
        }

        const fn remove_operation(self) -> PrivateDirectoryOperation {
            match self {
                Self::Directory => PrivateDirectoryOperation::RemoveDirectory,
                Self::RegularFile(_) => PrivateDirectoryOperation::RemoveFile,
            }
        }
    }

    pub(super) fn create(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let ((), user) =
            with_private_security_attributes(PrivateObjectKind::Directory, |attributes| {
                // SAFETY: `wide_path` is NUL-terminated and `attributes` keeps its complete
                // security-descriptor graph alive for the atomic creation call.
                let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), attributes) };
                if created == 0 {
                    let code = last_os_code();
                    return Err(PrivateDirectoryError::new(
                        if is_win32_error(code, ERROR_ALREADY_EXISTS) {
                            PrivateDirectoryErrorKind::AlreadyExists
                        } else {
                            PrivateDirectoryErrorKind::WindowsApi(
                                PrivateDirectoryOperation::CreateDirectory,
                            )
                        },
                        code,
                    ));
                }
                Ok(())
            })?;

        let directory = match open_directory(&wide_path, false) {
            Ok(directory) => directory,
            Err(error) => {
                // `CreateDirectoryW` returns no identity. Reopening this pathname after the first
                // open failed could target a replacement controlled through the parent directory.
                return Err(error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, None));
            }
        };
        if let Err(error) = verify_with_user(
            directory.as_raw_handle(),
            &user,
            PrivateObjectKind::Directory,
        ) {
            let cleanup = remove_verified_private(
                directory.as_raw_handle(),
                &user,
                PrivateObjectKind::Directory,
            );
            return Err(match cleanup {
                Ok(()) => error.with_cleanup(PrivateDirectoryCleanupStatus::Confirmed, None),
                Err(cleanup) => {
                    error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, cleanup.os_code())
                }
            });
        }
        Ok(directory)
    }

    pub(super) fn open(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let directory = open_directory(&wide_path, false)?;
        let user = current_process_user_sid()?;
        verify_with_user(
            directory.as_raw_handle(),
            &user,
            PrivateObjectKind::Directory,
        )?;
        Ok(directory)
    }

    pub(super) fn open_read_guard(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let directory = open_directory_read_guard(&wide_path)?;
        let user = current_process_user_sid()?;
        verify_with_user(
            directory.as_raw_handle(),
            &user,
            PrivateObjectKind::Directory,
        )?;
        Ok(directory)
    }

    pub(super) fn create_file(
        path: &Path,
        share_delete: bool,
    ) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let share_mode = FILE_SHARE_READ | if share_delete { FILE_SHARE_DELETE } else { 0 };
        let (file, user) = with_private_security_attributes(
            PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
            |attributes| {
                // SAFETY: `wide_path` is NUL-terminated and `attributes` keeps its complete
                // security-descriptor graph alive. `CREATE_NEW` never replaces an existing entry.
                let handle = unsafe {
                    CreateFileW(
                        wide_path.as_ptr(),
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                        share_mode,
                        attributes,
                        CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                        ptr::null_mut(),
                    )
                };
                if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                    let code = last_os_code();
                    return Err(PrivateDirectoryError::new(
                        if is_win32_error(code, ERROR_ALREADY_EXISTS)
                            || is_win32_error(code, ERROR_FILE_EXISTS)
                        {
                            PrivateDirectoryErrorKind::AlreadyExists
                        } else {
                            PrivateDirectoryErrorKind::WindowsApi(
                                PrivateDirectoryOperation::CreateFile,
                            )
                        },
                        code,
                    ));
                }
                // SAFETY: successful `CreateFileW` transfers exactly one owned real handle.
                Ok(unsafe { File::from_raw_handle(handle) })
            },
        )?;
        let kind = PrivateObjectKind::RegularFile(PrivateFileLinkState::Single);
        if let Err(error) = verify_with_user(file.as_raw_handle(), &user, kind) {
            let cleanup = remove_verified_private(file.as_raw_handle(), &user, kind);
            return Err(match cleanup {
                Ok(()) => error.with_cleanup(PrivateDirectoryCleanupStatus::Confirmed, None),
                Err(cleanup) => {
                    error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, cleanup.os_code())
                }
            });
        }
        Ok(file)
    }

    pub(super) fn create_lock_file(path: &Path) -> Result<File, PrivateDirectoryError> {
        create_lock_file_with_callback(path, || {})
    }

    fn create_lock_file_with_callback(
        path: &Path,
        after_create: impl FnOnce(),
    ) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let (file, user) = with_private_security_attributes(
            PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
            |attributes| {
                // SAFETY: the path and strict security descriptor are retained for this call.
                // CREATE_NEW cannot replace a peer's existing lock file.
                let handle = unsafe {
                    CreateFileW(
                        wide_path.as_ptr(),
                        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        attributes,
                        CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                        ptr::null_mut(),
                    )
                };
                if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                    let code = last_os_code();
                    return Err(PrivateDirectoryError::new(
                        if is_win32_error(code, ERROR_ALREADY_EXISTS)
                            || is_win32_error(code, ERROR_FILE_EXISTS)
                        {
                            PrivateDirectoryErrorKind::AlreadyExists
                        } else {
                            PrivateDirectoryErrorKind::WindowsApi(
                                PrivateDirectoryOperation::CreateFile,
                            )
                        },
                        code,
                    ));
                }
                // SAFETY: successful CreateFileW returns one owned real handle.
                Ok(unsafe { File::from_raw_handle(handle) })
            },
        )?;
        after_create();
        let kind = PrivateObjectKind::RegularFile(PrivateFileLinkState::Single);
        if let Err(error) = verify_with_user(file.as_raw_handle(), &user, kind) {
            drop(file);
            return Err(error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, None));
        }
        Ok(file)
    }

    pub(super) fn open_lock_file(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let file = open_regular_file_with_access(
            &wide_path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        let user = current_process_user_sid()?;
        verify_with_user(
            file.as_raw_handle(),
            &user,
            PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
        )?;
        Ok(file)
    }

    pub(super) fn publish_file_create_new(
        file: File,
        destination_directory: BorrowedHandle<'_>,
        destination_name: &OsStr,
    ) -> Result<File, PrivatePublicationError> {
        publish_file_create_new_with_callback(file, destination_directory, destination_name, || {})
    }

    fn publish_file_create_new_with_callback(
        file: File,
        destination_directory: BorrowedHandle<'_>,
        destination_name: &OsStr,
        after_rename: impl FnOnce(),
    ) -> Result<File, PrivatePublicationError> {
        let encoded_name = match private_destination_name(destination_name) {
            Ok(name) => name,
            Err(error) => {
                return Err(PrivatePublicationError::new(
                    PrivatePublicationPhase::Unpublished,
                    file,
                    error,
                ));
            }
        };
        let user = match current_process_user_sid() {
            Ok(user) => user,
            Err(error) => {
                return Err(PrivatePublicationError::new(
                    PrivatePublicationPhase::Unpublished,
                    file,
                    error,
                ));
            }
        };
        if let Err(error) = verify_with_user(
            destination_directory.as_raw_handle(),
            &user,
            PrivateObjectKind::Directory,
        ) {
            return Err(PrivatePublicationError::new(
                PrivatePublicationPhase::Unpublished,
                file,
                error,
            ));
        }
        let file_kind = PrivateObjectKind::RegularFile(PrivateFileLinkState::Single);
        if let Err(error) = verify_with_user(file.as_raw_handle(), &user, file_kind) {
            return Err(PrivatePublicationError::new(
                PrivatePublicationPhase::Unpublished,
                file,
                error,
            ));
        }
        if let Err(error) = verify_directory_contains_file_identity(
            destination_directory.as_raw_handle(),
            file.as_raw_handle(),
        ) {
            return Err(PrivatePublicationError::new(
                PrivatePublicationPhase::Unpublished,
                file,
                error,
            ));
        }
        if let Err(error) = rename_file_handle_create_new(
            file.as_raw_handle(),
            destination_directory.as_raw_handle(),
            &encoded_name,
        ) {
            return Err(PrivatePublicationError::new(
                PrivatePublicationPhase::Unpublished,
                file,
                error,
            ));
        }

        after_rename();
        let postcondition = (|| {
            verify_with_user(
                destination_directory.as_raw_handle(),
                &user,
                PrivateObjectKind::Directory,
            )?;
            verify_with_user(file.as_raw_handle(), &user, file_kind)?;
            verify_directory_entry_identity(
                destination_directory.as_raw_handle(),
                destination_name,
                file.as_raw_handle(),
            )
        })();
        if let Err(error) = postcondition {
            return Err(PrivatePublicationError::new(
                PrivatePublicationPhase::CommitUncertain,
                file,
                error,
            ));
        }
        Ok(file)
    }

    pub(super) fn complete_publication_pair(
        staging: File,
        destination_directory: BorrowedHandle<'_>,
        destination_name: &OsStr,
    ) -> Result<File, PrivatePublicationPairError> {
        complete_publication_pair_with_callback(
            staging,
            destination_directory,
            destination_name,
            || {},
        )
    }

    fn complete_publication_pair_with_callback(
        staging: File,
        destination_directory: BorrowedHandle<'_>,
        destination_name: &OsStr,
        after_staging_unlink: impl FnOnce(),
    ) -> Result<File, PrivatePublicationPairError> {
        let user = match current_process_user_sid() {
            Ok(user) => user,
            Err(error) => {
                return Err(PrivatePublicationPairError::new(
                    PrivatePublicationPairPhase::PairIntact,
                    staging,
                    error,
                ));
            }
        };
        let final_transient = match open_bound_publication_pair_final(
            &staging,
            destination_directory,
            destination_name,
            &user,
        ) {
            Ok(file) => file,
            Err(error) => {
                return Err(PrivatePublicationPairError::new(
                    PrivatePublicationPairPhase::PairIntact,
                    staging,
                    error,
                ));
            }
        };
        if let Err(error) = remove_link_by_handle_posix(staging.as_raw_handle()) {
            drop(final_transient);
            return Err(PrivatePublicationPairError::new(
                PrivatePublicationPairPhase::PairIntact,
                staging,
                error,
            ));
        }
        drop(staging);

        after_staging_unlink();
        let sealed = match reopen_private_file(
            final_transient.as_raw_handle(),
            FILE_GENERIC_READ | DELETE,
            FILE_SHARE_READ,
        ) {
            Ok(file) => file,
            Err(error) => {
                return Err(PrivatePublicationPairError::new(
                    PrivatePublicationPairPhase::FinalSingleSharedDelete,
                    final_transient,
                    error,
                ));
            }
        };
        drop(final_transient);

        if let Err(error) =
            verify_completed_publication(&sealed, destination_directory, destination_name, &user)
        {
            return Err(PrivatePublicationPairError::new(
                PrivatePublicationPairPhase::FinalSingleSealed,
                sealed,
                error,
            ));
        }
        Ok(sealed)
    }

    fn open_bound_publication_pair_final(
        staging: &File,
        destination_directory: BorrowedHandle<'_>,
        destination_name: &OsStr,
        user: &Sid,
    ) -> Result<File, PrivateDirectoryError> {
        private_destination_name(destination_name)?;
        let pair_kind = PrivateObjectKind::RegularFile(PrivateFileLinkState::PublicationPair);
        verify_with_user(
            destination_directory.as_raw_handle(),
            user,
            PrivateObjectKind::Directory,
        )?;
        verify_with_user(staging.as_raw_handle(), user, pair_kind)?;
        verify_directory_entry_identity(
            destination_directory.as_raw_handle(),
            destination_name,
            staging.as_raw_handle(),
        )?;
        let destination_path =
            final_path_from_handle(destination_directory.as_raw_handle())?.join(destination_name);
        let destination_path = wide_path(&destination_path)?;
        let final_file = open_regular_file_with_access(
            &destination_path,
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )?;
        verify_with_user(final_file.as_raw_handle(), user, pair_kind)?;
        verify_same_file(staging.as_raw_handle(), final_file.as_raw_handle())?;
        verify_directory_entry_identity(
            destination_directory.as_raw_handle(),
            destination_name,
            final_file.as_raw_handle(),
        )?;
        verify_with_user(staging.as_raw_handle(), user, pair_kind)?;
        Ok(final_file)
    }

    fn verify_completed_publication(
        final_file: &File,
        destination_directory: BorrowedHandle<'_>,
        destination_name: &OsStr,
        user: &Sid,
    ) -> Result<(), PrivateDirectoryError> {
        verify_with_user(
            final_file.as_raw_handle(),
            user,
            PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
        )?;
        verify_with_user(
            destination_directory.as_raw_handle(),
            user,
            PrivateObjectKind::Directory,
        )?;
        verify_directory_entry_identity(
            destination_directory.as_raw_handle(),
            destination_name,
            final_file.as_raw_handle(),
        )
    }

    pub(super) fn seal_staging_file(file: File) -> Result<File, PrivateDirectoryError> {
        seal_staging_file_with_transition(file, || {})
    }

    fn seal_staging_file_with_transition(
        file: File,
        after_writer_drop: impl FnOnce(),
    ) -> Result<File, PrivateDirectoryError> {
        let kind = PrivateObjectKind::RegularFile(PrivateFileLinkState::Single);
        let user = match current_process_user_sid() {
            Ok(user) => user,
            Err(error) => {
                drop(file);
                return Err(error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, None));
            }
        };
        if let Err(error) = verify_with_user(file.as_raw_handle(), &user, kind) {
            let cleanup = remove_verified_private(file.as_raw_handle(), &user, kind);
            drop(file);
            return Err(error_after_cleanup(error, cleanup));
        }
        let transient = match reopen_private_staging_file(
            file.as_raw_handle(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        ) {
            Ok(transient) => transient,
            Err(error) => {
                let cleanup = remove_verified_private(file.as_raw_handle(), &user, kind);
                drop(file);
                return Err(error_after_cleanup(error, cleanup));
            }
        };
        drop(file);
        after_writer_drop();

        let sealed = match reopen_private_staging_file(
            transient.as_raw_handle(),
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        ) {
            Ok(sealed) => sealed,
            Err(error) => {
                let cleanup = remove_verified_private(transient.as_raw_handle(), &user, kind);
                drop(transient);
                return Err(error_after_cleanup(error, cleanup));
            }
        };
        drop(transient);
        if let Err(error) = verify_with_user(sealed.as_raw_handle(), &user, kind) {
            let cleanup = remove_verified_private(sealed.as_raw_handle(), &user, kind);
            drop(sealed);
            return Err(error_after_cleanup(error, cleanup));
        }
        Ok(sealed)
    }

    pub(super) fn verify(handle: BorrowedHandle<'_>) -> Result<(), PrivateDirectoryError> {
        let user = current_process_user_sid()?;
        verify_with_user(handle.as_raw_handle(), &user, PrivateObjectKind::Directory)
    }

    pub(super) fn sync_directory(
        directory: BorrowedHandle<'_>,
    ) -> Result<(), PrivateDirectoryError> {
        let user = current_process_user_sid()?;
        verify_with_user(
            directory.as_raw_handle(),
            &user,
            PrivateObjectKind::Directory,
        )?;

        let mut io_status = IO_STATUS_BLOCK::default();
        // SAFETY: `directory` is a retained, verified directory handle with directory-write access.
        // Normal mode (`flags == 0`) synchronously requests cached data, metadata, and the backing
        // storage cache; this mode accepts no optional parameter block.
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
            let code = i32::try_from(unsafe { RtlNtStatusToDosError(status) }).ok();
            return Err(operation_error(
                PrivateDirectoryOperation::FlushDirectory,
                code,
            ));
        }

        verify_with_user(
            directory.as_raw_handle(),
            &user,
            PrivateObjectKind::Directory,
        )
    }

    pub(super) fn open_file(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let file = open_regular_file(&wide_path)?;
        let user = current_process_user_sid()?;
        verify_with_user(
            file.as_raw_handle(),
            &user,
            PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
        )?;
        Ok(file)
    }

    pub(super) fn open_file_for_sync(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let file = open_regular_file_for_sync(&wide_path)?;
        let user = current_process_user_sid()?;
        verify_with_user(
            file.as_raw_handle(),
            &user,
            PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
        )?;
        Ok(file)
    }

    pub(super) fn open_file_for_removal(path: &Path) -> Result<File, PrivateDirectoryError> {
        open_file_for_removal_in_state(path, PrivateFileLinkState::Single)
    }

    pub(super) fn open_file_for_removal_in_state(
        path: &Path,
        link_state: PrivateFileLinkState,
    ) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        let file = open_regular_file_for_removal(&wide_path)?;
        let user = current_process_user_sid()?;
        verify_with_user(
            file.as_raw_handle(),
            &user,
            PrivateObjectKind::RegularFile(link_state),
        )?;
        Ok(file)
    }

    pub(super) fn verify_file(
        handle: BorrowedHandle<'_>,
        link_state: PrivateFileLinkState,
    ) -> Result<(), PrivateDirectoryError> {
        let user = current_process_user_sid()?;
        verify_with_user(
            handle.as_raw_handle(),
            &user,
            PrivateObjectKind::RegularFile(link_state),
        )
    }

    pub(super) fn regular_file_link_count(
        handle: BorrowedHandle<'_>,
    ) -> Result<u32, PrivateDirectoryError> {
        let information = query_attributes(handle.as_raw_handle())?;
        verify_regular_file_attributes(&information)?;
        Ok(information.nNumberOfLinks)
    }

    pub(super) fn remove(directory: File) -> Result<(), PrivateDirectoryError> {
        remove_private_object(directory, PrivateObjectKind::Directory)
    }

    pub(super) fn remove_file(
        file: File,
        link_state: PrivateFileLinkState,
    ) -> Result<(), PrivateDirectoryError> {
        remove_private_object(file, PrivateObjectKind::RegularFile(link_state))
    }

    pub(super) fn remove_directory_tree(directory: File) -> Result<(), PrivateDirectoryError> {
        remove_directory_tree_with_callback(directory, |_| {})
    }

    fn remove_directory_tree_with_callback(
        directory: File,
        before_removal: impl FnOnce(&Path),
    ) -> Result<(), PrivateDirectoryError> {
        let result = (|| {
            let user = current_process_user_sid()?;
            verify_with_user(
                directory.as_raw_handle(),
                &user,
                PrivateObjectKind::Directory,
            )?;
            let path = final_path_from_handle(directory.as_raw_handle())?;
            let children = bind_directory_children(&directory, &path)?;
            before_removal(&path);
            remove_bound_directory(directory, children)
        })();
        result.map_err(|error| {
            let code = error.os_code();
            error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, code)
        })
    }

    fn bind_directory_children(
        directory: &File,
        path: &Path,
    ) -> Result<Vec<BoundTreeEntry>, PrivateDirectoryError> {
        let entries = enumerate_directory(directory.as_raw_handle())?;
        let mut children = Vec::with_capacity(entries.len());
        for entry in entries {
            let child_path = path.join(&entry.name);
            let child = open_tree_entry(&child_path)?;
            let identity = query_file_identity(child.as_raw_handle())?;
            if identity.FileId.Identifier != entry.file_id {
                return Err(PrivateDirectoryError::new(
                    PrivateDirectoryErrorKind::IdentityMismatch,
                    None,
                ));
            }
            let information = query_attributes(child.as_raw_handle())?;
            if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(PrivateDirectoryError::new(
                    PrivateDirectoryErrorKind::ReparsePoint,
                    None,
                ));
            }
            if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                let child_path = final_path_from_handle(child.as_raw_handle())?;
                children.push(BoundTreeEntry::Directory {
                    handle: child,
                    path: child_path,
                });
            } else {
                verify_regular_file_attributes(&information)?;
                if information.nNumberOfLinks != 1 {
                    return Err(PrivateDirectoryError::new(
                        PrivateDirectoryErrorKind::MultipleLinks,
                        None,
                    ));
                }
                children.push(BoundTreeEntry::RegularFile(child));
            }
        }
        Ok(children)
    }

    fn remove_bound_directory(
        directory: File,
        children: Vec<BoundTreeEntry>,
    ) -> Result<(), PrivateDirectoryError> {
        for child in children {
            match child {
                BoundTreeEntry::Directory { handle, path } => {
                    let information = query_attributes(handle.as_raw_handle())?;
                    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(PrivateDirectoryError::new(
                            PrivateDirectoryErrorKind::ReparsePoint,
                            None,
                        ));
                    }
                    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                        return Err(PrivateDirectoryError::new(
                            PrivateDirectoryErrorKind::NotDirectory,
                            None,
                        ));
                    }
                    let grandchildren = bind_directory_children(&handle, &path)?;
                    remove_bound_directory(handle, grandchildren)?;
                }
                BoundTreeEntry::RegularFile(file) => {
                    let information = query_attributes(file.as_raw_handle())?;
                    verify_regular_file_attributes(&information)?;
                    if information.nNumberOfLinks != 1 {
                        return Err(PrivateDirectoryError::new(
                            PrivateDirectoryErrorKind::MultipleLinks,
                            None,
                        ));
                    }
                    remove_by_handle(
                        file.as_raw_handle(),
                        PrivateObjectKind::RegularFile(PrivateFileLinkState::Single),
                    )?;
                    drop(file);
                }
            }
        }
        let information = query_attributes(directory.as_raw_handle())?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::ReparsePoint,
                None,
            ));
        }
        if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::NotDirectory,
                None,
            ));
        }
        remove_by_handle(directory.as_raw_handle(), PrivateObjectKind::Directory)?;
        drop(directory);
        Ok(())
    }

    fn remove_private_object(
        object: File,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        let cleanup = current_process_user_sid().and_then(|user| {
            verify_with_user(object.as_raw_handle(), &user, kind)?;
            remove_by_handle(object.as_raw_handle(), kind)
        });
        match cleanup {
            Ok(()) => {
                drop(object);
                Ok(())
            }
            Err(error) => {
                let code = error.os_code();
                Err(error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, code))
            }
        }
    }

    fn verify_with_user(
        handle: HANDLE,
        user: &Sid,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        verify_object_policy(handle, user, kind)?;
        verify_filesystem(handle)
    }

    fn verify_object_policy(
        handle: HANDLE,
        user: &Sid,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        verify_attributes(handle, kind)?;
        let descriptor = read_security_descriptor(handle)?;
        verify_security_descriptor(&descriptor, user, kind)
    }

    fn remove_verified_private(
        handle: HANDLE,
        user: &Sid,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        verify_object_policy(handle, user, kind)?;
        remove_by_handle(handle, kind)
    }

    fn verify_attributes(
        handle: HANDLE,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        let information = query_attributes(handle)?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::ReparsePoint,
                None,
            ));
        }
        match kind {
            PrivateObjectKind::Directory
                if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 =>
            {
                return Err(PrivateDirectoryError::new(
                    PrivateDirectoryErrorKind::NotDirectory,
                    None,
                ));
            }
            PrivateObjectKind::RegularFile(link_state) => {
                verify_regular_file_attributes(&information)?;
                if information.nNumberOfLinks != link_state.expected_links() {
                    return Err(PrivateDirectoryError::new(
                        PrivateDirectoryErrorKind::MultipleLinks,
                        None,
                    ));
                }
            }
            PrivateObjectKind::Directory => {}
        }
        Ok(())
    }

    fn query_attributes(
        handle: HANDLE,
    ) -> Result<BY_HANDLE_FILE_INFORMATION, PrivateDirectoryError> {
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` is borrowed for the call and `information` is writable initialized
        // storage of the exact structure expected by `GetFileInformationByHandle`.
        unsafe {
            win_bool(
                GetFileInformationByHandle(handle, &raw mut information),
                PrivateDirectoryOperation::QueryAttributes,
            )?;
        }
        Ok(information)
    }

    fn query_file_identity(handle: HANDLE) -> Result<FILE_ID_INFO, PrivateDirectoryError> {
        let mut identity = FILE_ID_INFO::default();
        let size = u32::try_from(size_of::<FILE_ID_INFO>())
            .map_err(|_| operation_error(PrivateDirectoryOperation::QueryAttributes, None))?;
        // SAFETY: `handle` is borrowed and `identity` is writable storage of the advertised size.
        unsafe {
            win_bool(
                GetFileInformationByHandleEx(handle, FileIdInfo, (&raw mut identity).cast(), size),
                PrivateDirectoryOperation::QueryAttributes,
            )?;
        }
        Ok(identity)
    }

    fn verify_directory_entry_identity(
        directory: HANDLE,
        name: &OsStr,
        file: HANDLE,
    ) -> Result<(), PrivateDirectoryError> {
        let directory_identity = query_file_identity(directory)?;
        let file_identity = query_file_identity(file)?;
        if directory_identity.VolumeSerialNumber != file_identity.VolumeSerialNumber {
            return Err(directory_identity_error());
        }
        let entry = enumerate_directory(directory)?
            .into_iter()
            .find(|entry| entry.name == name)
            .ok_or_else(directory_identity_error)?;
        if entry.file_id != file_identity.FileId.Identifier {
            return Err(directory_identity_error());
        }
        Ok(())
    }

    fn verify_directory_contains_file_identity(
        directory: HANDLE,
        file: HANDLE,
    ) -> Result<(), PrivateDirectoryError> {
        let directory_identity = query_file_identity(directory)?;
        let file_identity = query_file_identity(file)?;
        if directory_identity.VolumeSerialNumber != file_identity.VolumeSerialNumber {
            return Err(directory_identity_error());
        }
        let matching_entries = enumerate_directory(directory)?
            .into_iter()
            .filter(|entry| entry.file_id == file_identity.FileId.Identifier)
            .count();
        if matching_entries != 1 {
            return Err(directory_identity_error());
        }
        Ok(())
    }

    fn verify_same_file(left: HANDLE, right: HANDLE) -> Result<(), PrivateDirectoryError> {
        let left = query_file_identity(left)?;
        let right = query_file_identity(right)?;
        if left.VolumeSerialNumber != right.VolumeSerialNumber
            || left.FileId.Identifier != right.FileId.Identifier
        {
            return Err(directory_identity_error());
        }
        Ok(())
    }

    fn enumerate_directory(
        handle: HANDLE,
    ) -> Result<Vec<DirectoryEntryIdentity>, PrivateDirectoryError> {
        let words = DIRECTORY_ENUMERATION_BUFFER_BYTES / size_of::<u64>();
        let buffer_size = u32::try_from(DIRECTORY_ENUMERATION_BUFFER_BYTES)
            .map_err(|_| operation_error(PrivateDirectoryOperation::EnumerateDirectory, None))?;
        let mut buffer = vec![0_u64; words];
        let mut entries = Vec::new();
        let mut names = BTreeSet::new();
        let mut restart = true;
        loop {
            let information_class = if restart {
                FileIdExtdDirectoryRestartInfo
            } else {
                FileIdExtdDirectoryInfo
            };
            // SAFETY: `handle` is a retained directory handle and `buffer` is aligned writable
            // storage of exactly `buffer_size` bytes for the requested directory records.
            let succeeded = unsafe {
                GetFileInformationByHandleEx(
                    handle,
                    information_class,
                    buffer.as_mut_ptr().cast(),
                    buffer_size,
                )
            };
            if succeeded == 0 {
                let code = last_os_code();
                if is_win32_error(code, ERROR_NO_MORE_FILES) {
                    break;
                }
                return Err(operation_error(
                    PrivateDirectoryOperation::EnumerateDirectory,
                    code,
                ));
            }
            restart = false;
            for entry in parse_directory_entries(&buffer)? {
                if entry.name.as_os_str() == "." || entry.name.as_os_str() == ".." {
                    continue;
                }
                let mut components = Path::new(&entry.name).components();
                if !matches!(components.next(), Some(Component::Normal(_)))
                    || components.next().is_some()
                    || !names.insert(entry.name.clone())
                {
                    return Err(PrivateDirectoryError::new(
                        PrivateDirectoryErrorKind::IdentityMismatch,
                        None,
                    ));
                }
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn parse_directory_entries(
        buffer: &[u64],
    ) -> Result<Vec<DirectoryEntryIdentity>, PrivateDirectoryError> {
        let bytes = size_of_val(buffer);
        // SAFETY: viewing initialized `u64` storage as bytes preserves its allocation and bounds.
        let raw_buffer = unsafe { slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), bytes) };
        let name_offset = offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
        let mut cursor = 0_usize;
        let mut entries = Vec::new();
        loop {
            let _header_end = cursor
                .checked_add(size_of::<FILE_ID_EXTD_DIR_INFO>())
                .filter(|end| *end <= bytes)
                .ok_or_else(directory_identity_error)?;
            // SAFETY: the bounds above cover one complete fixed record header. Windows aligns
            // records, but `read_unaligned` also keeps this parser sound if an invalid offset does
            // not preserve that alignment.
            let information = unsafe {
                ptr::read_unaligned(
                    raw_buffer
                        .as_ptr()
                        .add(cursor)
                        .cast::<FILE_ID_EXTD_DIR_INFO>(),
                )
            };
            let name_bytes = usize::try_from(information.FileNameLength)
                .map_err(|_| directory_identity_error())?;
            if name_bytes % size_of::<u16>() != 0 {
                return Err(directory_identity_error());
            }
            let name_start = cursor
                .checked_add(name_offset)
                .ok_or_else(directory_identity_error)?;
            let name_end = name_start
                .checked_add(name_bytes)
                .filter(|end| *end <= bytes)
                .ok_or_else(directory_identity_error)?;
            let name = raw_buffer[name_start..name_end]
                .chunks_exact(size_of::<u16>())
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                .collect::<Vec<_>>();
            entries.push(DirectoryEntryIdentity {
                name: OsString::from_wide(&name),
                file_id: information.FileId.Identifier,
            });

            if information.NextEntryOffset == 0 {
                break;
            }
            let next = usize::try_from(information.NextEntryOffset)
                .map_err(|_| directory_identity_error())?;
            if next < name_end - cursor {
                return Err(directory_identity_error());
            }
            cursor = cursor
                .checked_add(next)
                .filter(|next| *next < bytes)
                .ok_or_else(directory_identity_error)?;
        }
        Ok(entries)
    }

    fn directory_identity_error() -> PrivateDirectoryError {
        PrivateDirectoryError::new(PrivateDirectoryErrorKind::IdentityMismatch, None)
    }

    fn verify_regular_file_attributes(
        information: &BY_HANDLE_FILE_INFORMATION,
    ) -> Result<(), PrivateDirectoryError> {
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::ReparsePoint,
                None,
            ));
        }
        if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::NotRegularFile,
                None,
            ));
        }
        Ok(())
    }

    fn verify_filesystem(handle: HANDLE) -> Result<(), PrivateDirectoryError> {
        let mut flags = 0;
        // SAFETY: all optional output buffers are null with zero lengths; `flags` is valid writable
        // storage and `handle` remains borrowed for the duration of the call.
        let succeeded = unsafe {
            GetVolumeInformationByHandleW(
                handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut flags,
                ptr::null_mut(),
                0,
            )
        };
        win_bool(succeeded, PrivateDirectoryOperation::QueryFileSystem)?;
        if flags & FILE_PERSISTENT_ACLS == 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::UnsupportedFileSystem,
                None,
            ));
        }
        Ok(())
    }

    fn read_security_descriptor(handle: HANDLE) -> Result<AlignedBuffer, PrivateDirectoryError> {
        let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        let mut required = 0;
        // SAFETY: a null output buffer with length zero is the documented sizing query; `required`
        // is valid writable storage and `handle` remains borrowed.
        let sized = unsafe {
            GetKernelObjectSecurity(handle, requested, ptr::null_mut(), 0, &raw mut required)
        };
        let sizing_code = last_os_code();
        if sized != 0 || !is_win32_error(sizing_code, ERROR_INSUFFICIENT_BUFFER) {
            return Err(security_query_error(sizing_code));
        }
        let required = usize::try_from(required).map_err(|_| security_query_error(None))?;
        if required == 0 || required > MAX_SECURITY_DESCRIPTOR_BYTES {
            return Err(security_query_error(None));
        }
        let mut descriptor = AlignedBuffer::new(required);
        let length = u32::try_from(descriptor.len()).map_err(|_| security_query_error(None))?;
        let mut returned = length;
        // SAFETY: the aligned output buffer is writable for `length` bytes and the kernel fills a
        // self-relative security descriptor on success.
        let succeeded = unsafe {
            GetKernelObjectSecurity(
                handle,
                requested,
                descriptor.as_mut_ptr(),
                length,
                &raw mut returned,
            )
        };
        win_bool(
            succeeded,
            PrivateDirectoryOperation::QuerySecurityDescriptor,
        )?;
        if returned == 0 || returned > length {
            return Err(security_query_error(None));
        }
        descriptor.len = usize::try_from(returned).map_err(|_| security_query_error(None))?;
        Ok(descriptor)
    }

    fn verify_security_descriptor(
        descriptor: &AlignedBuffer,
        user: &Sid,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        // SAFETY: `descriptor` is an aligned buffer populated by `GetKernelObjectSecurity` and
        // remains alive while Windows returns pointers into it.
        let valid = unsafe { IsValidSecurityDescriptor(descriptor.as_ptr()) };
        if valid == 0 {
            return Err(security_query_error(last_os_code()));
        }
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: both outputs are writable and the descriptor has passed Windows validation.
        unsafe {
            win_bool(
                GetSecurityDescriptorControl(
                    descriptor.as_ptr(),
                    &raw mut control,
                    &raw mut revision,
                ),
                PrivateDirectoryOperation::QuerySecurityDescriptor,
            )?;
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::DaclUnprotected,
                None,
            ));
        }

        let mut owner = ptr::null_mut();
        let mut owner_defaulted = 0;
        // SAFETY: outputs are writable and the validated descriptor remains alive.
        unsafe {
            win_bool(
                GetSecurityDescriptorOwner(
                    descriptor.as_ptr(),
                    &raw mut owner,
                    &raw mut owner_defaulted,
                ),
                PrivateDirectoryOperation::QuerySecurityDescriptor,
            )?;
        }
        if owner.is_null() {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::OwnerMissing,
                None,
            ));
        }
        let owner = descriptor_sid(descriptor, owner).ok_or_else(|| {
            PrivateDirectoryError::new(PrivateDirectoryErrorKind::OwnerMismatch, None)
        })?;
        if owner != user.as_bytes() {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::OwnerMismatch,
                None,
            ));
        }

        let mut dacl_present = 0;
        let mut dacl = ptr::null_mut();
        let mut dacl_defaulted = 0;
        // SAFETY: outputs are writable and the validated descriptor remains alive.
        unsafe {
            win_bool(
                GetSecurityDescriptorDacl(
                    descriptor.as_ptr(),
                    &raw mut dacl_present,
                    &raw mut dacl,
                    &raw mut dacl_defaulted,
                ),
                PrivateDirectoryOperation::QuerySecurityDescriptor,
            )?;
        }
        if dacl_present == 0 || dacl.is_null() {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::DaclMissing,
                None,
            ));
        }
        let raw_acl = descriptor_acl(descriptor, dacl).ok_or_else(|| {
            PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::DaclPolicy(PrivateDirectoryAclViolation::Malformed),
                None,
            )
        })?;
        let system = Sid::well_known(WinLocalSystemSid)?;
        let administrators = Sid::well_known(WinBuiltinAdministratorsSid)?;
        let allowed = allowed_sids(user, &system, &administrators);
        let allowed = allowed.iter().map(|sid| sid.as_bytes()).collect::<Vec<_>>();
        validate_acl_with_flags(raw_acl, &allowed, kind.ace_flags()).map_err(|violation| {
            PrivateDirectoryError::new(PrivateDirectoryErrorKind::DaclPolicy(violation), None)
        })
    }

    fn allowed_sids<'a>(user: &'a Sid, system: &'a Sid, administrators: &'a Sid) -> Vec<&'a Sid> {
        let mut allowed = Vec::with_capacity(3);
        for sid in [user, system, administrators] {
            if !allowed
                .iter()
                .any(|present: &&Sid| present.as_bytes() == sid.as_bytes())
            {
                allowed.push(sid);
            }
        }
        allowed
    }

    fn descriptor_sid(descriptor: &AlignedBuffer, sid: PSID) -> Option<&[u8]> {
        let bytes = descriptor.as_bytes();
        let offset = pointer_offset(bytes, sid.cast(), SID_HEADER_BYTES)?;
        let header = bytes.get(offset..offset + SID_HEADER_BYTES)?;
        let length = SID_HEADER_BYTES.checked_add(usize::from(header[1]) * size_of::<u32>())?;
        let sid = bytes.get(offset..offset.checked_add(length)?)?;
        valid_sid_bytes(sid).then_some(sid)
    }

    fn descriptor_acl(descriptor: &AlignedBuffer, acl: *const ACL) -> Option<&[u8]> {
        let bytes = descriptor.as_bytes();
        let offset = pointer_offset(bytes, acl.cast(), size_of::<ACL>())?;
        let header = bytes.get(offset..offset + size_of::<ACL>())?;
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        bytes.get(offset..offset.checked_add(length)?)
    }

    fn pointer_offset(bytes: &[u8], pointer: *const u8, minimum: usize) -> Option<usize> {
        let base = bytes.as_ptr() as usize;
        let end = base.checked_add(bytes.len())?;
        let pointer = pointer as usize;
        let required_end = pointer.checked_add(minimum)?;
        (pointer >= base && required_end <= end).then_some(pointer - base)
    }

    fn current_process_user_sid() -> Result<Sid, PrivateDirectoryError> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: `token` is writable and receives an owned real handle when the call succeeds.
        unsafe {
            win_bool(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token),
                PrivateDirectoryOperation::QueryProcessToken,
            )?;
        }
        if token.is_null() {
            return Err(operation_error(
                PrivateDirectoryOperation::QueryProcessToken,
                None,
            ));
        }
        // SAFETY: successful `OpenProcessToken` transfers one owned handle, closed by `OwnedHandle`.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut required = 0;
        // SAFETY: this is the documented zero-length sizing query.
        let sized = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &raw mut required,
            )
        };
        let sizing_code = last_os_code();
        if sized != 0 || !is_win32_error(sizing_code, ERROR_INSUFFICIENT_BUFFER) || required == 0 {
            return Err(operation_error(
                PrivateDirectoryOperation::QueryProcessToken,
                sizing_code,
            ));
        }
        let mut information =
            AlignedBuffer::new(usize::try_from(required).map_err(|_| {
                operation_error(PrivateDirectoryOperation::QueryProcessToken, None)
            })?);
        // SAFETY: the aligned buffer is writable for the requested number of bytes.
        unsafe {
            win_bool(
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    information.as_mut_ptr(),
                    required,
                    &raw mut required,
                ),
                PrivateDirectoryOperation::QueryProcessToken,
            )?;
            let token_user = information.as_ptr().cast::<TOKEN_USER>();
            Sid::copy_from((*token_user).User.Sid)
        }
    }

    fn with_private_security_attributes<T>(
        kind: PrivateObjectKind,
        operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> Result<T, PrivateDirectoryError>,
    ) -> Result<(T, Sid), PrivateDirectoryError> {
        let user = current_process_user_sid()?;
        let system = Sid::well_known(WinLocalSystemSid)?;
        let administrators = Sid::well_known(WinBuiltinAdministratorsSid)?;
        let allowed = allowed_sids(&user, &system, &administrators);
        let mut acl = build_acl_with_flags(&allowed, kind.ace_flags())?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();

        // SAFETY: the absolute descriptor and every referenced SID/ACL remain alive and fixed in
        // memory through `operation`; each API receives its documented initialized buffer.
        unsafe {
            win_bool(
                InitializeSecurityDescriptor(
                    (&raw mut descriptor).cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                ),
                PrivateDirectoryOperation::BuildSecurityDescriptor,
            )?;
            win_bool(
                SetSecurityDescriptorOwner((&raw mut descriptor).cast(), user.as_psid(), 0),
                PrivateDirectoryOperation::BuildSecurityDescriptor,
            )?;
            win_bool(
                SetSecurityDescriptorDacl(
                    (&raw mut descriptor).cast(),
                    1,
                    acl.as_mut_ptr().cast(),
                    0,
                ),
                PrivateDirectoryOperation::BuildSecurityDescriptor,
            )?;
            win_bool(
                SetSecurityDescriptorControl(
                    (&raw mut descriptor).cast(),
                    SE_DACL_PROTECTED,
                    SE_DACL_PROTECTED,
                ),
                PrivateDirectoryOperation::BuildSecurityDescriptor,
            )?;
        }

        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
                operation_error(PrivateDirectoryOperation::BuildSecurityDescriptor, None)
            })?,
            lpSecurityDescriptor: (&raw mut descriptor).cast(),
            bInheritHandle: 0,
        };
        let value = operation(&raw const attributes)?;
        Ok((value, user))
    }

    #[cfg(test)]
    fn build_acl(sids: &[&Sid]) -> Result<AlignedBuffer, PrivateDirectoryError> {
        build_acl_with_flags(sids, DIRECTORY_INHERIT_FLAGS)
    }

    fn build_acl_with_flags(
        sids: &[&Sid],
        ace_flags: u8,
    ) -> Result<AlignedBuffer, PrivateDirectoryError> {
        let length = size_of::<ACL>()
            + sids
                .iter()
                .map(|sid| {
                    size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.as_bytes().len()
                })
                .sum::<usize>();
        let mut acl = AlignedBuffer::new(length);
        let length = u32::try_from(length)
            .map_err(|_| operation_error(PrivateDirectoryOperation::BuildAcl, None))?;
        // SAFETY: `acl` is aligned writable storage of `length` bytes and every SID is valid and
        // remains alive while its access-allowed ACE is copied into the ACL.
        unsafe {
            win_bool(
                InitializeAcl(acl.as_mut_ptr().cast(), length, ACL_REVISION),
                PrivateDirectoryOperation::BuildAcl,
            )?;
            for sid in sids {
                win_bool(
                    AddAccessAllowedAceEx(
                        acl.as_mut_ptr().cast(),
                        ACL_REVISION,
                        u32::from(ace_flags),
                        FILE_ALL_ACCESS,
                        sid.as_psid(),
                    ),
                    PrivateDirectoryOperation::BuildAcl,
                )?;
            }
        }
        Ok(acl)
    }

    fn open_directory(path: &[u16], write_dacl: bool) -> Result<File, PrivateDirectoryError> {
        let desired_access =
            FILE_GENERIC_READ | FILE_WRITE_DATA | DELETE | if write_dacl { WRITE_DAC } else { 0 };
        open_directory_with_access(path, desired_access, FILE_SHARE_READ | FILE_SHARE_WRITE)
    }

    fn open_directory_read_guard(path: &[u16]) -> Result<File, PrivateDirectoryError> {
        open_directory_with_access(
            path,
            FILE_GENERIC_READ | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
    }

    fn open_directory_with_access(
        path: &[u16],
        desired_access: u32,
        share_mode: u32,
    ) -> Result<File, PrivateDirectoryError> {
        // SAFETY: `path` is NUL-terminated; null security/template pointers are permitted. Opening
        // with `OPEN_REPARSE_POINT` ensures verification observes the named object itself.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                desired_access,
                share_mode,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(operation_error(
                PrivateDirectoryOperation::OpenDirectory,
                last_os_code(),
            ));
        }
        // SAFETY: `CreateFileW` returned one owned real handle, transferred exactly once to File.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn open_tree_entry(path: &Path) -> Result<File, PrivateDirectoryError> {
        let wide_path = wide_path(path)?;
        // SAFETY: `wide_path` is NUL-terminated. `OPEN_REPARSE_POINT` binds the named entry rather
        // than its target, while omitting write/delete sharing keeps that entry stable until the
        // retained handle is either discarded or used for exact disposition.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                FILE_GENERIC_READ | DELETE,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(operation_error(
                PrivateDirectoryOperation::OpenTreeEntry,
                last_os_code(),
            ));
        }
        // SAFETY: `CreateFileW` returned one owned real handle, transferred exactly once to File.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn final_path_from_handle(handle: HANDLE) -> Result<PathBuf, PrivateDirectoryError> {
        let mut buffer = vec![0_u16; 512];
        loop {
            let capacity = u32::try_from(buffer.len())
                .map_err(|_| operation_error(PrivateDirectoryOperation::ResolvePath, None))?;
            // SAFETY: `handle` is retained and `buffer` is writable for `capacity` UTF-16 units.
            let length =
                unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity, 0) };
            if length == 0 {
                return Err(operation_error(
                    PrivateDirectoryOperation::ResolvePath,
                    last_os_code(),
                ));
            }
            let length = usize::try_from(length)
                .map_err(|_| operation_error(PrivateDirectoryOperation::ResolvePath, None))?;
            if length < buffer.len() {
                buffer.truncate(length);
                return Ok(PathBuf::from(OsString::from_wide(&buffer)));
            }
            let required = length
                .checked_add(1)
                .ok_or_else(|| operation_error(PrivateDirectoryOperation::ResolvePath, None))?;
            buffer.resize(required, 0);
        }
    }

    fn open_regular_file(path: &[u16]) -> Result<File, PrivateDirectoryError> {
        open_regular_file_with_access(path, FILE_GENERIC_READ, FILE_SHARE_READ)
    }

    fn open_regular_file_for_sync(path: &[u16]) -> Result<File, PrivateDirectoryError> {
        open_regular_file_with_access(
            path,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
        )
    }

    fn open_regular_file_for_removal(path: &[u16]) -> Result<File, PrivateDirectoryError> {
        open_regular_file_with_access(
            path,
            FILE_GENERIC_READ | DELETE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
        )
    }

    fn reopen_private_staging_file(
        original: HANDLE,
        share_mode: u32,
    ) -> Result<File, PrivateDirectoryError> {
        reopen_private_file(original, FILE_GENERIC_READ | DELETE, share_mode)
    }

    fn reopen_private_file(
        original: HANDLE,
        desired_access: u32,
        share_mode: u32,
    ) -> Result<File, PrivateDirectoryError> {
        // SAFETY: `original` is a retained verified file handle. `ReOpenFile` binds the new handle
        // to that exact file object and performs no pathname lookup.
        let handle = unsafe {
            ReOpenFile(
                original,
                desired_access,
                share_mode,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(operation_error(
                PrivateDirectoryOperation::OpenFile,
                last_os_code(),
            ));
        }
        // SAFETY: `ReOpenFile` returned one owned real handle, transferred exactly once to `File`.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn open_regular_file_with_access(
        path: &[u16],
        desired_access: u32,
        share_mode: u32,
    ) -> Result<File, PrivateDirectoryError> {
        // SAFETY: `path` is NUL-terminated; null security/template pointers are permitted. The
        // caller selects access and sharing appropriate to the lifetime contract of its handle.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                desired_access,
                share_mode,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(operation_error(
                PrivateDirectoryOperation::OpenFile,
                last_os_code(),
            ));
        }
        // SAFETY: `CreateFileW` returned one owned real handle, transferred exactly once to File.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn remove_by_handle(
        handle: HANDLE,
        kind: PrivateObjectKind,
    ) -> Result<(), PrivateDirectoryError> {
        let operation = kind.remove_operation();
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        let size = u32::try_from(size_of::<FILE_DISPOSITION_INFO>())
            .map_err(|_| operation_error(operation, None))?;
        // SAFETY: `handle` was opened with DELETE access and `disposition` is readable for `size`.
        let succeeded = unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfo,
                (&raw const disposition).cast(),
                size,
            )
        };
        win_bool(succeeded, operation)
    }

    fn remove_link_by_handle_posix(handle: HANDLE) -> Result<(), PrivateDirectoryError> {
        let disposition = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };
        let size = u32::try_from(size_of::<FILE_DISPOSITION_INFO_EX>())
            .map_err(|_| operation_error(PrivateDirectoryOperation::RemoveFile, None))?;
        // SAFETY: `handle` is the verified publication-pair staging handle with DELETE access.
        // POSIX disposition removes that exact opened link while other shared-delete handles live.
        let succeeded = unsafe {
            SetFileInformationByHandle(
                handle,
                FileDispositionInfoEx,
                (&raw const disposition).cast(),
                size,
            )
        };
        win_bool(succeeded, PrivateDirectoryOperation::RemoveFile)
    }

    fn rename_file_handle_create_new(
        file: HANDLE,
        destination_directory: HANDLE,
        destination_name: &[u16],
    ) -> Result<(), PrivateDirectoryError> {
        let name_bytes = destination_name
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| operation_error(PrivateDirectoryOperation::RenameFile, None))?;
        // Windows requires at least the fixed structure size plus the complete variable name,
        // even though that fixed size already includes the first UTF-16 array element.
        let total_bytes = size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(name_bytes)
            .ok_or_else(|| operation_error(PrivateDirectoryOperation::RenameFile, None))?;
        let name_bytes = u32::try_from(name_bytes)
            .map_err(|_| operation_error(PrivateDirectoryOperation::RenameFile, None))?;
        let total_bytes = u32::try_from(total_bytes)
            .map_err(|_| operation_error(PrivateDirectoryOperation::RenameFile, None))?;
        let mut buffer = AlignedBuffer::new(total_bytes as usize);
        let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let mut io_status = IO_STATUS_BLOCK::default();
        // SAFETY: `AlignedBuffer` is aligned for `FILE_RENAME_INFORMATION` and sized through the
        // complete variable-length UTF-16 name. Both handles remain retained for the atomic native
        // rename call, and `io_status` is writable for the synchronous result.
        let status = unsafe {
            information.write(FILE_RENAME_INFORMATION::default());
            (*information).Anonymous.ReplaceIfExists = false;
            (*information).RootDirectory = destination_directory;
            (*information).FileNameLength = name_bytes;
            ptr::copy_nonoverlapping(
                destination_name.as_ptr(),
                ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
                destination_name.len(),
            );
            NtSetInformationFile(
                file,
                &raw mut io_status,
                buffer.as_ptr(),
                total_bytes,
                FileRenameInformation,
            )
        };
        if status >= 0 {
            return Ok(());
        }
        // SAFETY: `status` is the failure value returned directly by `NtSetInformationFile`.
        let code = i32::try_from(unsafe { RtlNtStatusToDosError(status) }).ok();
        Err(PrivateDirectoryError::new(
            if is_win32_error(code, ERROR_ALREADY_EXISTS) || is_win32_error(code, ERROR_FILE_EXISTS)
            {
                PrivateDirectoryErrorKind::AlreadyExists
            } else {
                PrivateDirectoryErrorKind::WindowsApi(PrivateDirectoryOperation::RenameFile)
            },
            code,
        ))
    }

    fn private_destination_name(name: &OsStr) -> Result<Vec<u16>, PrivateDirectoryError> {
        const INVALID_ASCII: [u16; 9] = [0x22, 0x2a, 0x2f, 0x3a, 0x3c, 0x3e, 0x3f, 0x5c, 0x7c];

        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(component)) if component == name)
            || components.next().is_some()
        {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::InvalidPath,
                None,
            ));
        }
        let encoded = name.encode_wide().collect::<Vec<_>>();
        let invalid_ascii = |unit: u16| unit < 32 || INVALID_ASCII.contains(&unit);
        if encoded.is_empty()
            || encoded.iter().copied().any(invalid_ascii)
            || matches!(encoded.last(), Some(unit) if *unit == u16::from(b'.') || *unit == u16::from(b' '))
        {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::InvalidPath,
                None,
            ));
        }
        Ok(encoded)
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>, PrivateDirectoryError> {
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
        if !path.is_absolute() || encoded.contains(&0) {
            return Err(PrivateDirectoryError::new(
                PrivateDirectoryErrorKind::InvalidPath,
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

    fn security_query_error(code: Option<i32>) -> PrivateDirectoryError {
        operation_error(PrivateDirectoryOperation::QuerySecurityDescriptor, code)
    }

    fn error_after_cleanup(
        error: PrivateDirectoryError,
        cleanup: Result<(), PrivateDirectoryError>,
    ) -> PrivateDirectoryError {
        match cleanup {
            Ok(()) => error.with_cleanup(PrivateDirectoryCleanupStatus::Confirmed, None),
            Err(cleanup) => {
                error.with_cleanup(PrivateDirectoryCleanupStatus::Uncertain, cleanup.os_code())
            }
        }
    }

    fn operation_error(
        operation: PrivateDirectoryOperation,
        code: Option<i32>,
    ) -> PrivateDirectoryError {
        PrivateDirectoryError::new(PrivateDirectoryErrorKind::WindowsApi(operation), code)
    }

    fn win_bool(
        result: i32,
        operation: PrivateDirectoryOperation,
    ) -> Result<(), PrivateDirectoryError> {
        if result != 0 {
            Ok(())
        } else {
            Err(operation_error(operation, last_os_code()))
        }
    }

    fn last_os_code() -> Option<i32> {
        io::Error::last_os_error().raw_os_error()
    }

    fn is_win32_error(code: Option<i32>, expected: u32) -> bool {
        code.and_then(|code| u32::try_from(code).ok()) == Some(expected)
    }

    struct AlignedBuffer {
        words: Vec<usize>,
        len: usize,
    }

    impl AlignedBuffer {
        fn new(len: usize) -> Self {
            let words = len.div_ceil(size_of::<usize>()).max(1);
            Self {
                words: vec![0; words],
                len,
            }
        }

        fn len(&self) -> usize {
            self.len
        }

        fn as_ptr(&self) -> *mut c_void {
            self.words.as_ptr().cast_mut().cast()
        }

        fn as_mut_ptr(&mut self) -> *mut c_void {
            self.words.as_mut_ptr().cast()
        }

        fn as_bytes(&self) -> &[u8] {
            // SAFETY: the backing allocation is live and initialized; `len` never exceeds it.
            unsafe { slice::from_raw_parts(self.words.as_ptr().cast(), self.len) }
        }
    }

    struct Sid {
        bytes: AlignedBuffer,
    }

    impl Sid {
        fn well_known(kind: i32) -> Result<Self, PrivateDirectoryError> {
            let mut bytes = AlignedBuffer::new(SECURITY_MAX_SID_SIZE as usize);
            let mut length = SECURITY_MAX_SID_SIZE;
            // SAFETY: the aligned output buffer is writable for `length`; a null domain SID is
            // required for these machine-independent well-known SID kinds.
            let succeeded = unsafe {
                CreateWellKnownSid(kind, ptr::null_mut(), bytes.as_mut_ptr(), &raw mut length)
            };
            win_bool(succeeded, PrivateDirectoryOperation::CreateWellKnownSid)?;
            bytes.len = usize::try_from(length).map_err(|_| {
                operation_error(PrivateDirectoryOperation::CreateWellKnownSid, None)
            })?;
            Ok(Self { bytes })
        }

        unsafe fn copy_from(source: PSID) -> Result<Self, PrivateDirectoryError> {
            if source.is_null() || unsafe { IsValidSid(source) } == 0 {
                return Err(operation_error(
                    PrivateDirectoryOperation::QueryProcessToken,
                    last_os_code(),
                ));
            }
            let length = unsafe { GetLengthSid(source) };
            let mut bytes = AlignedBuffer::new(usize::try_from(length).map_err(|_| {
                operation_error(PrivateDirectoryOperation::QueryProcessToken, None)
            })?);
            // SAFETY: the source is a valid SID from TokenUser and the destination has its exact
            // reported length.
            unsafe {
                win_bool(
                    CopySid(length, bytes.as_mut_ptr(), source),
                    PrivateDirectoryOperation::QueryProcessToken,
                )?;
            }
            Ok(Self { bytes })
        }

        fn as_psid(&self) -> PSID {
            self.bytes.as_ptr()
        }

        fn as_bytes(&self) -> &[u8] {
            self.bytes.as_bytes()
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            fs,
            os::windows::{
                fs::{symlink_dir, symlink_file},
                io::AsHandle as _,
            },
        };

        use super::*;
        use windows_sys::Win32::Security::{
            SetKernelObjectSecurity, UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, READ_CONTROL,
        };

        #[test]
        fn protected_child_ignores_permissive_parent_inheritance() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let parent = temporary.path().join("permissive");
            fs::create_dir(&parent).expect("parent directory");
            set_world_writable(&parent);
            let child = parent.join("private");

            let handle = create(&child).expect("protected private directory");
            verify(handle.as_handle()).expect("retained handle policy");
            drop(handle);
            fs::remove_dir(&child).expect("remove child");
        }

        #[test]
        fn retained_handle_detects_dacl_tampering() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let child = temporary.path().join("private");
            let handle = create(&child).expect("protected private directory");
            set_world_writable(&child);

            let error = verify(handle.as_handle()).expect_err("tampered DACL");
            assert!(matches!(
                error.kind(),
                PrivateDirectoryErrorKind::DaclUnprotected
                    | PrivateDirectoryErrorKind::DaclPolicy(_)
            ));
            remove(handle).expect_err("tampered object must not be cleanup-eligible");
            assert!(child.is_dir());
            fs::remove_dir(&child).expect("remove child");
        }

        #[test]
        fn retained_reparse_handle_is_rejected_when_symlinks_are_available() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let target = temporary.path().join("target");
            let link = temporary.path().join("link");
            fs::create_dir(&target).expect("target directory");
            if symlink_dir(&target, &link).is_err() {
                return;
            }
            let wide = wide_path(&link).expect("wide path");
            let handle = open_directory(&wide, false).expect("open reparse point");
            let error = verify(handle.as_handle()).expect_err("reparse rejected");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::ReparsePoint);
        }

        #[test]
        fn existing_directory_is_never_removed() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let existing = temporary.path().join("existing");
            fs::create_dir(&existing).expect("existing directory");

            let error = create(&existing).expect_err("atomic create must reject an existing path");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::AlreadyExists);
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::NotRequired
            );
            assert!(existing.is_dir());
        }

        #[test]
        fn retained_handle_blocks_path_replacement_until_drop() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let child = temporary.path().join("private");
            let renamed = temporary.path().join("renamed");
            let handle = create(&child).expect("protected private directory");

            assert!(fs::rename(&child, &renamed).is_err());
            assert!(fs::remove_dir(&child).is_err());
            verify(handle.as_handle()).expect("retained handle policy");

            drop(handle);
            fs::rename(&child, &renamed).expect("rename after retained handle drop");
            fs::remove_dir(&renamed).expect("cleanup after retained handle drop");
        }

        #[test]
        fn private_directory_read_guards_coexist_and_collectively_block_rename() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let child = temporary.path().join("private");
            let renamed = temporary.path().join("renamed");
            drop(create(&child).expect("protected private directory"));

            let first = open_read_guard(&child).expect("first private read guard");
            let second = open_read_guard(&child).expect("second private read guard");
            verify(first.as_handle()).expect("first strict directory policy");
            verify(second.as_handle()).expect("second strict directory policy");
            assert!(fs::rename(&child, &renamed).is_err());

            drop(first);
            assert!(fs::rename(&child, &renamed).is_err());
            drop(second);
            fs::rename(&child, &renamed).expect("rename after all read guards drop");
            fs::remove_dir(&renamed).expect("cleanup renamed directory");
        }

        #[test]
        fn private_directory_metadata_flush_accepts_mutation_and_read_guards() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let directory_path = temporary.path().join("private");
            let staging = directory_path.join("staging");
            let final_path = directory_path.join("final");
            let directory = create(&directory_path).expect("protected private directory");
            fs::write(&staging, b"durable namespace").expect("write staging file");
            fs::rename(&staging, &final_path).expect("publish final file");

            crate::windows_private_directory::sync_private_directory_handle(directory.as_handle())
                .expect("flush mutation guard");
            verify(directory.as_handle()).expect("mutation guard remains strict");
            drop(directory);

            let read_guard = open_read_guard(&directory_path).expect("private read guard");
            crate::windows_private_directory::sync_private_directory_handle(read_guard.as_handle())
                .expect("flush read guard");
            verify(read_guard.as_handle()).expect("read guard remains strict");
            assert_eq!(
                fs::read(&final_path).expect("read final file"),
                b"durable namespace"
            );

            drop(read_guard);
            fs::remove_file(&final_path).expect("remove final file");
            fs::remove_dir(&directory_path).expect("remove private directory");
        }

        #[test]
        fn private_directory_metadata_flush_fails_closed_without_write_access() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let directory_path = temporary.path().join("private");
            drop(create(&directory_path).expect("protected private directory"));
            let wide = wide_path(&directory_path).expect("wide directory path");
            let read_only = open_directory_with_access(
                &wide,
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )
            .expect("strict read-only directory handle");
            verify(read_only.as_handle()).expect("read-only handle remains strict");

            let error = crate::windows_private_directory::sync_private_directory_handle(
                read_only.as_handle(),
            )
            .expect_err("Windows must reject a flush without directory-write access");
            assert_eq!(
                error.kind(),
                PrivateDirectoryErrorKind::WindowsApi(PrivateDirectoryOperation::FlushDirectory)
            );
            assert_eq!(error.os_code(), Some(5));
            verify(read_only.as_handle()).expect("failed flush leaves exact handle usable");
            assert!(directory_path.is_dir());

            drop(read_only);
            fs::remove_dir(&directory_path).expect("remove private directory");
        }

        #[test]
        fn retained_handle_removes_the_exact_empty_directory() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let child = temporary.path().join("private");
            let handle = create(&child).expect("protected private directory");

            remove(handle).expect("handle-bound removal");
            assert!(!child.exists());
        }

        #[test]
        fn private_lock_file_peers_coexist_and_fs2_arbitrates() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let moved_root = temporary.path().join("moved-private");
            let lock_path = root.join("store.lock");
            let directory = create(&root).expect("protected private directory");
            let creator = create_lock_file(&lock_path).expect("create strict private lock file");
            let peer = open_lock_file(&lock_path).expect("open compatible lock-file peer");

            fs2::FileExt::try_lock_exclusive(&creator).expect("creator exclusive lock");
            assert!(fs2::FileExt::try_lock_shared(&peer).is_err());
            fs2::FileExt::unlock(&creator).expect("unlock creator");
            fs2::FileExt::try_lock_shared(&creator).expect("creator shared lock");
            fs2::FileExt::try_lock_shared(&peer).expect("peer shared lock");
            let contender = open_lock_file(&lock_path).expect("open exclusive contender");
            assert!(fs2::FileExt::try_lock_exclusive(&contender).is_err());

            assert!(fs::remove_file(&lock_path).is_err());
            assert!(fs::rename(&root, &moved_root).is_err());
            assert!(!moved_root.exists());
            fs2::FileExt::unlock(&peer).expect("unlock peer");
            fs2::FileExt::unlock(&creator).expect("unlock creator shared lock");
            drop(contender);
            drop(peer);
            drop(creator);

            let removal = open_file_for_removal(&lock_path).expect("open exact lock removal");
            remove_file(removal, PrivateFileLinkState::Single).expect("remove exact lock file");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn private_lock_file_creation_never_replaces_existing_peer() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let lock_path = root.join("store.lock");
            let directory = create(&root).expect("protected private directory");
            let existing = create_lock_file(&lock_path).expect("create strict private lock file");

            let error = create_lock_file(&lock_path).expect_err("CREATE_NEW must reject peer");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::AlreadyExists);
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::NotRequired
            );
            verify_file(existing.as_handle(), PrivateFileLinkState::Single)
                .expect("existing peer remains strict");

            drop(existing);
            let removal = open_file_for_removal(&lock_path).expect("open exact lock removal");
            remove_file(removal, PrivateFileLinkState::Single).expect("remove exact lock file");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn private_lock_file_post_create_policy_failure_is_uncertain() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let path = temporary.path().join("store.lock");

            let error = create_lock_file_with_callback(&path, || set_world_writable(&path))
                .expect_err("post-create DACL tamper must fail strict verification");
            assert!(matches!(
                error.kind(),
                PrivateDirectoryErrorKind::DaclUnprotected
                    | PrivateDirectoryErrorKind::DaclPolicy(_)
            ));
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::Uncertain
            );
            assert!(path.is_file());
            fs::remove_file(&path).expect("remove test-owned uncertain residue");
        }

        #[test]
        fn handle_bound_publication_is_create_new_and_retains_final_guard() {
            use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let staging_path = root.join("artifact.tmp");
            let final_path = root.join("artifact.bin");
            let renamed_path = root.join("renamed.bin");
            let directory = create(&root).expect("protected private directory");
            let mut staging = create_file(&staging_path, false).expect("protected staging file");
            staging
                .write_all(b"complete artifact\n")
                .expect("write complete staging file");
            staging.sync_all().expect("sync complete staging file");

            let mut published = publish_file_create_new_with_callback(
                staging,
                directory.as_handle(),
                OsStr::new("artifact.bin"),
                || {
                    assert!(fs::rename(&final_path, &renamed_path).is_err());
                    assert!(fs::remove_file(&final_path).is_err());
                },
            )
            .expect("atomic handle-bound publication");

            assert!(!staging_path.exists());
            assert!(final_path.is_file());
            assert!(!renamed_path.exists());
            verify_file(published.as_handle(), PrivateFileLinkState::Single)
                .expect("retained strict final handle");
            published
                .seek(SeekFrom::Start(0))
                .expect("rewind final handle");
            let mut bytes = Vec::new();
            published
                .read_to_end(&mut bytes)
                .expect("read final through retained handle");
            assert_eq!(bytes, b"complete artifact\n");

            remove_file(published, PrivateFileLinkState::Single)
                .expect("remove exact published file");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn handle_bound_publication_preserves_occupied_destination() {
            use std::io::Write as _;

            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let staging_path = root.join("artifact.tmp");
            let final_path = root.join("artifact.bin");
            let directory = create(&root).expect("protected private directory");
            let mut staging = create_file(&staging_path, false).expect("protected staging file");
            staging
                .write_all(b"new artifact\n")
                .expect("write staging file");
            staging.sync_all().expect("sync staging file");
            let mut existing = create_file(&final_path, false).expect("existing private file");
            existing
                .write_all(b"existing artifact\n")
                .expect("write existing file");
            existing.sync_all().expect("sync existing file");
            drop(existing);

            let publication =
                publish_file_create_new(staging, directory.as_handle(), OsStr::new("artifact.bin"))
                    .expect_err("occupied destination must not be replaced");
            assert_eq!(publication.phase(), PrivatePublicationPhase::Unpublished);
            assert_eq!(
                publication.error().kind(),
                PrivateDirectoryErrorKind::AlreadyExists
            );
            let (_, staging, _) = publication.into_parts();
            verify_file(staging.as_handle(), PrivateFileLinkState::Single)
                .expect("exact staging handle retained");
            assert_eq!(
                fs::read(&final_path).expect("read existing destination"),
                b"existing artifact\n"
            );

            remove_file(staging, PrivateFileLinkState::Single).expect("remove exact staging file");
            let existing = open_file_for_removal(&final_path).expect("open existing destination");
            remove_file(existing, PrivateFileLinkState::Single)
                .expect("remove existing destination");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn handle_bound_publication_rejects_unsafe_names_before_mutation() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let staging_path = root.join("artifact.tmp");
            let directory = create(&root).expect("protected private directory");
            let mut staging = create_file(&staging_path, false).expect("protected staging file");

            for name in ["", "..", r"nested\artifact", "artifact:stream", "artifact."] {
                let error =
                    publish_file_create_new(staging, directory.as_handle(), OsStr::new(name))
                        .expect_err("unsafe destination name must be rejected");
                assert_eq!(error.phase(), PrivatePublicationPhase::Unpublished);
                assert_eq!(error.error().kind(), PrivateDirectoryErrorKind::InvalidPath);
                let (_, retained, _) = error.into_parts();
                staging = retained;
                assert!(staging_path.is_file());
            }

            remove_file(staging, PrivateFileLinkState::Single).expect("remove exact staging file");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn post_rename_link_injection_returns_recoverable_exact_handle() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let staging_path = root.join("artifact.tmp");
            let final_path = root.join("artifact.bin");
            let injected_link = root.join("injected.bin");
            let directory = create(&root).expect("protected private directory");
            let staging = create_file(&staging_path, false).expect("protected staging file");

            let publication = publish_file_create_new_with_callback(
                staging,
                directory.as_handle(),
                OsStr::new("artifact.bin"),
                || fs::hard_link(&final_path, &injected_link).expect("inject second hard link"),
            )
            .expect_err("post-rename link-state mismatch must fail closed");
            assert_eq!(
                publication.phase(),
                PrivatePublicationPhase::CommitUncertain
            );
            assert_eq!(
                publication.error().kind(),
                PrivateDirectoryErrorKind::MultipleLinks
            );
            let (_, published, _) = publication.into_parts();
            verify_file(published.as_handle(), PrivateFileLinkState::PublicationPair)
                .expect("exact publication-pair handle retained");

            remove_file(published, PrivateFileLinkState::PublicationPair)
                .expect("remove exact final link");
            assert!(!final_path.exists());
            assert!(injected_link.is_file());
            let injected =
                open_file_for_removal(&injected_link).expect("open remaining exact link");
            remove_file(injected, PrivateFileLinkState::Single)
                .expect("remove remaining injected link");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn publication_pair_completion_returns_sealed_exact_final_handle() {
            use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let staging_path = root.join("artifact.tmp");
            let final_path = root.join("artifact.bin");
            let moved_path = root.join("moved.bin");
            let directory = create(&root).expect("protected private directory");
            let mut writer = create_file(&staging_path, true).expect("protected staging file");
            writer
                .write_all(b"legacy artifact\n")
                .expect("write complete staging file");
            writer.sync_all().expect("sync complete staging file");
            let staging = seal_staging_file(writer).expect("seal staging handle");
            fs::hard_link(&staging_path, &final_path).expect("create legacy final hard link");

            let mut published = complete_publication_pair(
                staging,
                directory.as_handle(),
                OsStr::new("artifact.bin"),
            )
            .expect("collapse publication pair");

            assert!(!staging_path.exists());
            assert!(final_path.is_file());
            assert!(fs::rename(&final_path, &moved_path).is_err());
            assert!(fs::remove_file(&final_path).is_err());
            verify_file(published.as_handle(), PrivateFileLinkState::Single)
                .expect("strict single final handle");
            published
                .seek(SeekFrom::Start(0))
                .expect("rewind final handle");
            let mut bytes = Vec::new();
            published
                .read_to_end(&mut bytes)
                .expect("read final through sealed handle");
            assert_eq!(bytes, b"legacy artifact\n");

            remove_file(published, PrivateFileLinkState::Single).expect("remove exact final link");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn publication_pair_boundary_replacement_is_preserved_and_reported() {
            use std::io::Write as _;

            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let staging_path = root.join("artifact.tmp");
            let final_path = root.join("artifact.bin");
            let moved_path = root.join("moved.bin");
            let directory = create(&root).expect("protected private directory");
            let mut writer = create_file(&staging_path, true).expect("protected staging file");
            writer.write_all(b"original\n").expect("write staging file");
            writer.sync_all().expect("sync staging file");
            let staging = seal_staging_file(writer).expect("seal staging handle");
            fs::hard_link(&staging_path, &final_path).expect("create legacy final hard link");

            let recovery = complete_publication_pair_with_callback(
                staging,
                directory.as_handle(),
                OsStr::new("artifact.bin"),
                || {
                    fs::rename(&final_path, &moved_path).expect("move original final link");
                    fs::write(&final_path, b"replacement\n").expect("create replacement");
                },
            )
            .expect_err("replacement boundary must fail closed");
            assert_eq!(
                recovery.phase(),
                PrivatePublicationPairPhase::FinalSingleSealed
            );
            assert_eq!(
                recovery.error().kind(),
                PrivateDirectoryErrorKind::IdentityMismatch
            );
            let (_, original, _) = recovery.into_parts();
            verify_file(original.as_handle(), PrivateFileLinkState::Single)
                .expect("exact original retained and sealed");

            remove_file(original, PrivateFileLinkState::Single)
                .expect("remove exact moved original");
            assert!(!moved_path.exists());
            assert_eq!(
                fs::read(&final_path).expect("read preserved replacement"),
                b"replacement\n"
            );
            fs::remove_file(&final_path).expect("remove preserved replacement");
            remove(directory).expect("remove empty private directory");
        }

        #[test]
        fn private_regular_file_is_created_verified_and_removed_by_handle() {
            use std::io::Write as _;

            let temporary = tempfile::tempdir().expect("temporary directory");
            let path = temporary.path().join("endpoint.json");
            let mut handle = create_file(&path, false).expect("protected private file");
            handle.write_all(b"{}\n").expect("write private file");
            handle.sync_all().expect("sync private file");
            verify_file(handle.as_handle(), PrivateFileLinkState::Single)
                .expect("retained private-file policy");
            assert!(fs::rename(&path, temporary.path().join("moved.json")).is_err());
            assert!(fs::remove_file(&path).is_err());

            remove_file(handle, PrivateFileLinkState::Single)
                .expect("handle-bound private-file removal");
            assert!(!path.exists());
        }

        #[test]
        fn private_file_sync_handle_flushes_and_blocks_mutation_or_replacement() {
            use std::io::{Read as _, Write as _};

            let temporary = tempfile::tempdir().expect("temporary directory");
            let path = temporary.path().join("revision.json");
            let moved = temporary.path().join("moved.json");
            let mut creator = create_file(&path, false).expect("protected private file");
            creator
                .write_all(b"published\n")
                .expect("write final bytes");
            creator.sync_all().expect("initial file sync");
            drop(creator);

            let sync = crate::windows_private_directory::open_private_file_for_sync(&path)
                .expect("open strict sync handle");
            sync.sync_all().expect("retry final file sync");
            verify_file(sync.as_handle(), PrivateFileLinkState::Single)
                .expect("sync handle remains strict");
            let mut reader = fs::File::open(&path).expect("compatible read peer");
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).expect("read final bytes");
            assert_eq!(bytes, b"published\n");

            assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
            assert!(fs::rename(&path, &moved).is_err());
            assert!(fs::remove_file(&path).is_err());
            assert!(!moved.exists());

            drop(reader);
            drop(sync);
            fs::rename(&path, &moved).expect("rename after sync guard drop");
            fs::write(&path, b"replacement\n").expect("create replacement");
            assert_eq!(fs::read(&moved).expect("read original"), b"published\n");
            assert_eq!(fs::read(&path).expect("read replacement"), b"replacement\n");
            fs::remove_file(&path).expect("remove replacement");
            fs::remove_file(&moved).expect("remove original");
        }

        #[test]
        fn private_file_sync_open_rejects_dacl_and_hardlink_policy_violations() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let dacl_path = temporary.path().join("dacl.json");
            drop(create_file(&dacl_path, false).expect("protected private file"));
            set_world_writable(&dacl_path);

            let dacl_error =
                crate::windows_private_directory::open_private_file_for_sync(&dacl_path)
                    .expect_err("permissive DACL must be rejected");
            assert!(matches!(
                dacl_error.kind(),
                PrivateDirectoryErrorKind::DaclUnprotected
                    | PrivateDirectoryErrorKind::DaclPolicy(_)
            ));
            fs::remove_file(&dacl_path).expect("remove permissive test file");

            let linked_path = temporary.path().join("linked.json");
            let extra_link = temporary.path().join("extra-link.json");
            drop(create_file(&linked_path, false).expect("protected private file"));
            fs::hard_link(&linked_path, &extra_link).expect("create extra hard link");
            let link_error =
                crate::windows_private_directory::open_private_file_for_sync(&linked_path)
                    .expect_err("multiple links must be rejected");
            assert_eq!(link_error.kind(), PrivateDirectoryErrorKind::MultipleLinks);
            fs::remove_file(&extra_link).expect("remove extra hard link");
            fs::remove_file(&linked_path).expect("remove original hard link");
        }

        #[test]
        fn private_file_sync_open_rejects_final_reparse_point_when_supported() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let target = temporary.path().join("target.json");
            let link = temporary.path().join("link.json");
            drop(create_file(&target, false).expect("protected private file"));
            if symlink_file(&target, &link).is_err() {
                fs::remove_file(&target).expect("remove target after skipped symlink test");
                return;
            }

            let error = crate::windows_private_directory::open_private_file_for_sync(&link)
                .expect_err("final reparse point must be rejected");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::ReparsePoint);
            fs::remove_file(&link).expect("remove test symlink");
            fs::remove_file(&target).expect("remove target");
        }

        #[test]
        fn private_regular_file_rejects_additional_hard_links() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let path = temporary.path().join("endpoint.json");
            let linked = temporary.path().join("linked.json");
            let handle = create_file(&path, false).expect("protected private file");
            fs::hard_link(&path, &linked).expect("test hard link");

            let error = verify_file(handle.as_handle(), PrivateFileLinkState::Single)
                .expect_err("multiple links rejected");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::MultipleLinks);
            drop(handle);
            fs::remove_file(&linked).expect("remove added link");
            fs::remove_file(&path).expect("remove original link");
        }

        #[test]
        fn removal_handle_survives_rename_and_removes_the_exact_file() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let original = temporary.path().join("endpoint.json");
            let renamed = temporary.path().join("renamed.json");
            let replacement = b"replacement\n";
            drop(create_file(&original, false).expect("protected private file"));

            let handle = open_file_for_removal(&original).expect("open private file for removal");
            fs::rename(&original, &renamed).expect("rename while removal handle is retained");
            fs::write(&original, replacement).expect("create replacement at original path");

            remove_file(handle, PrivateFileLinkState::Single)
                .expect("remove renamed object by retained handle");
            assert!(!renamed.exists());
            assert_eq!(fs::read(&original).expect("read replacement"), replacement);
            fs::remove_file(&original).expect("remove replacement");
        }

        #[test]
        fn removal_open_rejects_additional_hard_links() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let original = temporary.path().join("endpoint.json");
            let linked = temporary.path().join("linked.json");
            drop(create_file(&original, false).expect("protected private file"));
            fs::hard_link(&original, &linked).expect("test hard link");

            let error = open_file_for_removal(&original)
                .expect_err("removal open must reject multiple links");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::MultipleLinks);
            fs::remove_file(&linked).expect("remove added link");
            fs::remove_file(&original).expect("remove original link");
        }

        #[test]
        fn publication_pair_can_be_reopened_and_staging_link_removed_by_handle() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let staged = temporary.path().join("endpoint.tmp");
            let published = temporary.path().join("endpoint.json");
            drop(create_file(&staged, true).expect("protected staging file"));
            fs::hard_link(&staged, &published).expect("publish final hard link");

            let handle =
                open_file_for_removal_in_state(&staged, PrivateFileLinkState::PublicationPair)
                    .expect("reopen publication pair for removal");
            remove_file(handle, PrivateFileLinkState::PublicationPair)
                .expect("remove exact staging link");

            assert!(!staged.exists());
            let final_handle = open_file(&published).expect("open final private file");
            verify_file(final_handle.as_handle(), PrivateFileLinkState::Single)
                .expect("final file returned to single-link state");
            drop(final_handle);
            fs::remove_file(&published).expect("remove final file");
        }

        #[test]
        fn publication_pair_removal_open_rejects_single_link_state() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let staged = temporary.path().join("endpoint.tmp");
            let published = temporary.path().join("endpoint.json");
            drop(create_file(&staged, true).expect("protected staging file"));
            fs::hard_link(&staged, &published).expect("publish final hard link");

            let error = open_file_for_removal(&staged)
                .expect_err("single-link removal open must reject publication pair");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::MultipleLinks);
            fs::remove_file(&staged).expect("remove staging link");
            fs::remove_file(&published).expect("remove final link");
        }

        #[test]
        fn regular_file_link_count_tracks_added_hard_link_without_acl_policy() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let original = temporary.path().join("ordinary.txt");
            let linked = temporary.path().join("linked.txt");
            fs::write(&original, b"ordinary\n").expect("ordinary inherited-ACL file");
            let handle = File::open(&original).expect("open ordinary file");

            assert_eq!(
                regular_file_link_count(handle.as_handle()).expect("single link count"),
                1
            );
            fs::hard_link(&original, &linked).expect("add hard link");
            assert_eq!(
                regular_file_link_count(handle.as_handle()).expect("two-link count"),
                2
            );

            drop(handle);
            fs::remove_file(&linked).expect("remove added link");
            fs::remove_file(&original).expect("remove original link");
        }

        #[test]
        fn inherited_regular_file_acl_is_not_private_policy() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let path = temporary.path().join("ordinary.json");
            fs::write(&path, b"{}\n").expect("ordinary file");
            let file = File::open(&path).expect("open ordinary file");

            assert!(verify_file(file.as_handle(), PrivateFileLinkState::Single).is_err());
        }

        #[test]
        fn staging_file_publication_transitions_from_one_link_to_two_and_back() {
            use std::io::Write as _;

            let temporary = tempfile::tempdir().expect("temporary directory");
            let staged = temporary.path().join("endpoint.tmp");
            let published = temporary.path().join("endpoint.json");
            let mut handle = create_file(&staged, true).expect("protected staging file");
            handle.write_all(b"{}\n").expect("write staging file");
            handle.sync_all().expect("sync staging file");
            verify_file(handle.as_handle(), PrivateFileLinkState::Single)
                .expect("single staging link");

            fs::hard_link(&staged, &published).expect("create final hard link");
            verify_file(handle.as_handle(), PrivateFileLinkState::PublicationPair)
                .expect("staging and final links");
            remove_file(handle, PrivateFileLinkState::PublicationPair)
                .expect("remove exact staging link");

            assert!(!staged.exists());
            let final_handle = open_file(&published).expect("open final private file");
            verify_file(final_handle.as_handle(), PrivateFileLinkState::Single)
                .expect("single final link");
            drop(final_handle);
            fs::remove_file(&published).expect("remove final file");
        }

        #[test]
        fn sealed_staging_handle_is_path_free_and_denies_new_writers() {
            use std::{fs::OpenOptions, io::Write as _, os::windows::fs::OpenOptionsExt as _};

            let temporary = tempfile::tempdir().expect("temporary directory");
            let original = temporary.path().join("endpoint.tmp");
            let renamed = temporary.path().join("renamed.tmp");
            let mut writer = create_file(&original, true).expect("protected staging file");
            writer.write_all(b"sealed\n").expect("write staging file");
            writer.sync_all().expect("sync staging file");
            fs::rename(&original, &renamed).expect("rename retained staging file");

            let sealed = seal_staging_file(writer).expect("path-free staging seal");
            verify_file(sealed.as_handle(), PrivateFileLinkState::Single)
                .expect("sealed private-file policy");
            assert!(
                OpenOptions::new()
                    .write(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .open(&renamed)
                    .is_err()
            );

            remove_file(sealed, PrivateFileLinkState::Single).expect("remove sealed staging file");
            assert!(!renamed.exists());
        }

        #[test]
        fn sealed_staging_handle_supports_strict_dual_handle_publication() {
            use std::io::Write as _;

            let temporary = tempfile::tempdir().expect("temporary directory");
            let staged = temporary.path().join("endpoint.tmp");
            let published = temporary.path().join("endpoint.json");
            let mut writer = create_file(&staged, true).expect("protected staging file");
            writer.write_all(b"sealed\n").expect("write staging file");
            writer.sync_all().expect("sync staging file");
            let sealed = seal_staging_file(writer).expect("sealed staging handle");

            fs::hard_link(&staged, &published).expect("publish final hard link");
            verify_file(sealed.as_handle(), PrivateFileLinkState::PublicationPair)
                .expect("staging publication pair");
            let final_handle =
                open_file_for_removal_in_state(&published, PrivateFileLinkState::PublicationPair)
                    .expect("strict final publication handle");

            remove_file(final_handle, PrivateFileLinkState::PublicationPair)
                .expect("roll back exact final link");
            remove_file(sealed, PrivateFileLinkState::Single).expect("remove exact staging link");
            assert!(!staged.exists());
            assert!(!published.exists());
        }

        #[test]
        fn competing_writer_makes_seal_fail_with_confirmed_exact_cleanup() {
            use std::{cell::RefCell, fs::OpenOptions, os::windows::fs::OpenOptionsExt as _};

            let temporary = tempfile::tempdir().expect("temporary directory");
            let staged = temporary.path().join("endpoint.tmp");
            let writer = create_file(&staged, true).expect("protected staging file");
            let competing = RefCell::new(None);

            let error = seal_staging_file_with_transition(writer, || {
                let writer = OpenOptions::new()
                    .write(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .open(&staged)
                    .expect("competing writer during transition");
                competing.replace(Some(writer));
            })
            .expect_err("competing writer must prevent sealed reopen");

            assert_eq!(
                error.kind(),
                PrivateDirectoryErrorKind::WindowsApi(PrivateDirectoryOperation::OpenFile)
            );
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::Confirmed
            );
            drop(competing.take());
            assert!(!staged.exists());
        }

        #[test]
        fn closed_mutating_writer_requires_post_seal_content_revalidation() {
            use std::{
                fs::OpenOptions,
                io::{Read as _, Write as _},
                os::windows::fs::OpenOptionsExt as _,
            };

            let temporary = tempfile::tempdir().expect("temporary directory");
            let staged = temporary.path().join("endpoint.tmp");
            let mut writer = create_file(&staged, true).expect("protected staging file");
            writer.write_all(b"trusted").expect("write trusted bytes");
            writer.sync_all().expect("sync trusted bytes");

            let mut sealed = seal_staging_file_with_transition(writer, || {
                let mut competing = OpenOptions::new()
                    .write(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .open(&staged)
                    .expect("short-lived competing writer");
                competing.set_len(0).expect("truncate staging file");
                competing
                    .write_all(b"mutated")
                    .expect("mutate staging file");
                competing.sync_all().expect("sync mutation");
            })
            .expect("closed writer does not block sealed reopen");
            let mut bytes = Vec::new();
            sealed
                .read_to_end(&mut bytes)
                .expect("read sealed staging bytes");
            assert_eq!(bytes, b"mutated");

            remove_file(sealed, PrivateFileLinkState::Single).expect("remove mutated staging file");
            assert!(!staged.exists());
        }

        #[test]
        fn private_tree_removal_accepts_ordinary_inherited_descendants() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let handle = create(&root).expect("strict private root");
            let nested = root.join("Products/Applications/App.app");
            fs::create_dir_all(&nested).expect("ordinary nested directories");
            fs::write(nested.join("App"), b"ordinary inherited child")
                .expect("ordinary nested file");

            remove_directory_tree(handle).expect("exact recursive removal");
            assert!(!root.exists());
        }

        #[test]
        fn private_tree_removal_rejects_hard_linked_descendant() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let handle = create(&root).expect("strict private root");
            let child = root.join("child.txt");
            let linked = temporary.path().join("linked.txt");
            fs::write(&child, b"preserve").expect("ordinary nested file");
            fs::hard_link(&child, &linked).expect("additional hard link");

            let error = remove_directory_tree(handle).expect_err("hard link must fail closed");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::MultipleLinks);
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::Uncertain
            );
            assert_eq!(fs::read(&child).expect("original survives"), b"preserve");
            assert_eq!(
                fs::read(&linked).expect("linked copy survives"),
                b"preserve"
            );

            fs::remove_file(&linked).expect("remove added link");
            fs::remove_file(&child).expect("remove original link");
            fs::remove_dir(&root).expect("remove root");
        }

        #[test]
        fn private_tree_guard_blocks_root_replacement_at_removal_boundary() {
            use std::cell::RefCell;

            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let moved = temporary.path().join("moved");
            let replacement = temporary.path().join("replacement");
            let replacement_marker = replacement.join("preserve.txt");
            let handle = create(&root).expect("strict private root");
            fs::write(root.join("owned.txt"), b"owned").expect("owned nested file");
            fs::create_dir(&replacement).expect("replacement candidate");
            fs::write(&replacement_marker, b"preserve").expect("replacement marker");
            let attempts = RefCell::new(None);

            remove_directory_tree_with_callback(handle, |_| {
                let move_owned = fs::rename(&root, &moved);
                let install_replacement = fs::rename(&replacement, &root);
                attempts.replace(Some((move_owned, install_replacement)));
            })
            .expect("remove retained original tree");

            let (move_owned, install_replacement) = attempts
                .into_inner()
                .expect("replacement attempts recorded");
            assert!(move_owned.is_err());
            assert!(install_replacement.is_err());
            assert!(!root.exists());
            assert!(!moved.exists());
            assert_eq!(
                fs::read(&replacement_marker).expect("replacement survives"),
                b"preserve"
            );
        }

        #[test]
        fn private_tree_cleanup_failure_is_reported_uncertain() {
            use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt as _};

            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let handle = create(&root).expect("strict private root");
            let child = root.join("busy.txt");
            fs::write(&child, b"busy").expect("ordinary nested file");
            let busy = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&child)
                .expect("non-delete-sharing competing handle");

            let error = remove_directory_tree(handle).expect_err("busy child blocks cleanup");
            assert_eq!(
                error.kind(),
                PrivateDirectoryErrorKind::WindowsApi(PrivateDirectoryOperation::OpenTreeEntry)
            );
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::Uncertain
            );
            assert!(root.is_dir());
            assert_eq!(fs::read(&child).expect("busy child survives"), b"busy");

            drop(busy);
            fs::remove_file(&child).expect("remove busy child");
            fs::remove_dir(&root).expect("remove root");
        }

        #[test]
        fn private_tree_removal_rejects_nested_reparse_without_touching_target() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let root = temporary.path().join("private");
            let target = temporary.path().join("target");
            let marker = target.join("preserve.txt");
            let linked = root.join("linked");
            let handle = create(&root).expect("strict private root");
            fs::create_dir(&target).expect("external target");
            fs::write(&marker, b"preserve").expect("external marker");
            if symlink_dir(&target, &linked).is_err() {
                drop(handle);
                fs::remove_dir(&root).expect("remove unused root");
                return;
            }

            let error = remove_directory_tree(handle).expect_err("reparse must fail closed");
            assert_eq!(error.kind(), PrivateDirectoryErrorKind::ReparsePoint);
            assert_eq!(
                error.cleanup_status(),
                PrivateDirectoryCleanupStatus::Uncertain
            );
            assert_eq!(fs::read(&marker).expect("target survives"), b"preserve");

            fs::remove_dir(&linked).expect("remove directory symlink");
            assert_eq!(
                fs::symlink_metadata(&linked)
                    .expect_err("directory symlink is absent")
                    .kind(),
                std::io::ErrorKind::NotFound
            );
            assert!(target.is_dir());
            assert_eq!(
                fs::read(&marker).expect("target survives link cleanup"),
                b"preserve"
            );
            fs::remove_dir(&root).expect("remove root");
        }

        #[test]
        fn private_objects_support_extended_length_absolute_paths() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let mut parent = temporary.path().to_path_buf();
            while parent.as_os_str().encode_wide().count() < 280 {
                parent.push("long-private-path-segment");
            }
            fs::create_dir_all(&parent).expect("long parent path");
            let directory_path = parent.join("private");
            let directory = create(&directory_path).expect("long private directory path");
            verify(directory.as_handle()).expect("long directory policy");

            let file_path = directory_path.join("endpoint.json");
            let file = create_file(&file_path, false).expect("long private file path");
            verify_file(file.as_handle(), PrivateFileLinkState::Single).expect("long file policy");
            remove_file(file, PrivateFileLinkState::Single).expect("remove long private file");
            remove(directory).expect("remove long private directory");
        }

        fn set_world_writable(path: &Path) {
            let wide = wide_path(path).expect("wide path");
            let handle = open_test_directory(&wide);
            let world = Sid::well_known(WinWorldSid).expect("world SID");
            let mut acl = build_acl(&[&world]).expect("world ACL");
            let mut descriptor = SECURITY_DESCRIPTOR::default();
            // SAFETY: the descriptor and ACL are initialized, live buffers and the handle was
            // opened with WRITE_DAC for this isolated test directory.
            unsafe {
                assert_ne!(
                    InitializeSecurityDescriptor(
                        (&raw mut descriptor).cast(),
                        SECURITY_DESCRIPTOR_REVISION,
                    ),
                    0
                );
                assert_ne!(
                    SetSecurityDescriptorDacl(
                        (&raw mut descriptor).cast(),
                        1,
                        acl.as_mut_ptr().cast(),
                        0,
                    ),
                    0
                );
                assert_eq!(
                    SetKernelObjectSecurity(
                        handle.as_raw_handle(),
                        DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                        (&raw mut descriptor).cast(),
                    ),
                    1
                );
            }
        }

        fn open_test_directory(path: &[u16]) -> File {
            // SAFETY: `path` is NUL-terminated and every pointer/flag follows CreateFileW's
            // directory-handle contract.
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    ptr::null_mut(),
                )
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE);
            // SAFETY: the successful call transferred one owned handle.
            unsafe { File::from_raw_handle(handle) }
        }
    }
}

/// Atomically create one Windows directory with the strict private ACL and return its retained
/// standard-library handle after handle-bound verification.
///
/// No pathname-based permission repair or cleanup is attempted. If validation fails after
/// creation, the exact opened object is marked for deletion through its retained handle.
///
/// # Security
///
/// `CreateDirectoryW` does not return a handle. A permissive parent therefore leaves a narrow
/// create-to-open window in which another principal could substitute a different directory that
/// already has the same owner and exact ACL. Callers must write no sensitive data before this
/// function returns and must retain the returned no-delete-sharing handle until all sensitive
/// pathname use and handle-bound cleanup are complete.
///
/// # Errors
///
/// Returns a typed, path-free failure if the path is invalid or occupied, Windows cannot create
/// or open the directory, the filesystem lacks persistent ACLs, handle verification fails, or
/// post-create cleanup cannot be confirmed.
#[cfg(windows)]
pub fn create_private_directory(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::create(path)
}

/// Open an existing Windows directory without following reparse points, verify the strict private
/// ACL policy, and return a retained handle that denies delete sharing.
///
/// # Errors
///
/// Returns a typed, path-free failure if the path cannot be opened or the object, filesystem,
/// owner, or protected DACL differs from the private-directory policy.
#[cfg(windows)]
pub fn open_private_directory(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open(path)
}

/// Open a strict private directory as a multi-reader, no-delete-sharing guard.
///
/// The handle requests read access plus the minimal directory-write right required by
/// [`sync_private_directory_handle`], shares read/write access with equivalent guards, and omits
/// delete sharing. Multiple readers can therefore coexist while every retained guard blocks
/// directory rename, deletion, and pathname replacement. The handle has no DELETE access and
/// cannot be consumed by [`remove_private_directory_handle`] or
/// [`remove_private_directory_tree_handle`].
///
/// This sharing mode is intentionally incompatible with a live deletion-capable handle returned
/// by [`create_private_directory`] or [`open_private_directory`]. Callers transitioning from a
/// mutation/removal lifetime must release that handle only under a separate identity/lock protocol
/// and revalidate the path-to-handle binding.
///
/// # Errors
///
/// Returns a typed failure if the path cannot be opened or the retained object fails the strict
/// private directory, owner, protected-DACL, reparse, or ACL-filesystem policy.
#[cfg(windows)]
pub fn open_private_directory_read_guard(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open_read_guard(path)
}

/// Atomically create one Windows regular file with the strict private ACL and return its verified
/// no-delete-sharing handle.
///
/// The file is created with `CREATE_NEW`; an existing filesystem entry is never replaced.
///
/// # Errors
///
/// Returns a typed, path-free failure if the path is invalid or occupied, Windows cannot create
/// the file, the filesystem lacks persistent ACLs, or handle-bound validation fails.
#[cfg(windows)]
pub fn create_private_file(path: &std::path::Path) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::create_file(path, false)
}

/// Atomically create a strict private lock file with peer-compatible Windows sharing.
///
/// The returned handle requests read/write access, shares read/write access with other lock peers,
/// and omits delete sharing. Peers can therefore coexist at the filesystem layer while every live
/// handle prevents pathname deletion or replacement; callers must use a byte-range/file-locking
/// primitive such as `fs2` for shared/exclusive arbitration. The path uses `CREATE_NEW` and an
/// existing entry is never replaced.
///
/// # Errors
///
/// Returns a typed error if atomic creation or strict private-file verification fails. Because this
/// deliberately non-delete-capable handle cannot remove itself exactly, a post-create policy
/// failure reports [`PrivateDirectoryCleanupStatus::Uncertain`]. Callers should clean the enclosing
/// private directory through its retained exact directory capability.
#[cfg(windows)]
pub fn create_private_lock_file(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::create_lock_file(path)
}

/// Open an existing strict private lock file with peer-compatible Windows sharing.
///
/// The returned read/write handle shares read/write access, omits delete sharing, rejects reparse
/// points and multiple links, and verifies the exact private owner/protected-DACL policy. It is
/// suitable for acquiring an `fs2` lock before opening no-delete ancestor directory guards.
///
/// # Errors
///
/// Returns a typed failure if the path cannot be opened or the retained object fails strict
/// private-file verification.
#[cfg(windows)]
pub fn open_private_lock_file(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open_lock_file(path)
}

/// Atomically publish a completed private file under a new name in a retained private directory.
///
/// `staging` must be the strict single-link, no-delete-sharing handle returned by
/// [`create_private_file`]. `destination_directory` must be a retained handle returned by
/// [`create_private_directory`] or [`open_private_directory`], and `destination_name` must be one
/// ordinary Windows filename component. The rename is handle-relative, does not consult the
/// staging pathname, and never replaces an existing destination. Success is returned only after
/// the same retained file handle still satisfies the strict single-link policy and its filesystem
/// identity is bound to `destination_name` through retained-directory enumeration.
///
/// The returned handle continues to deny write and delete sharing. Callers should retain it and
/// the directory handle through final readback, synchronization, and durable metadata commit.
///
/// # Errors
///
/// Every error owns the exact input file handle. [`PrivatePublicationPhase::Unpublished`] means
/// the rename was not reported successful; [`PrivateDirectoryErrorKind::AlreadyExists`] in that
/// phase guarantees the existing destination was not replaced. A
/// [`PrivatePublicationPhase::CommitUncertain`] error means the rename succeeded but strict
/// postconditions could not be confirmed. Callers must recover through the returned handle and
/// must not delete either pathname speculatively.
#[cfg(windows)]
pub fn publish_private_file_handle_create_new(
    staging: std::fs::File,
    destination_directory: std::os::windows::io::BorrowedHandle<'_>,
    destination_name: &std::ffi::OsStr,
) -> Result<std::fs::File, PrivatePublicationError> {
    platform::publish_file_create_new(staging, destination_directory, destination_name)
}

/// Collapse a verified legacy staging/final hard-link pair into one sealed final link.
///
/// `staging` must be an exact strict [`PrivateFileLinkState::PublicationPair`] removal handle.
/// The destination directory must remain retained without delete sharing, and
/// `destination_name` must be one safe filename component. This function opens the named final
/// link while the pair exists, binds it to the staging handle by filesystem identity, removes the
/// exact staging link with handle-bound POSIX disposition, and then uses `ReOpenFile` to acquire a
/// final handle that denies write and delete sharing. Success requires strict single-link policy
/// and a second retained-directory identity binding.
///
/// # Errors
///
/// Every failure owns an exact staging or final handle. [`PrivatePublicationPairPhase::PairIntact`]
/// means staging-link removal was not reported successful. Later phases mean the staging link was
/// removed; callers must inspect the phase and retain or consume the exact returned handle rather
/// than deleting either pathname. In [`PrivatePublicationPairPhase::FinalSingleSharedDelete`], a
/// competing same-user namespace operation may still be live. In
/// [`PrivatePublicationPairPhase::FinalSingleSealed`], the exact original final object is stable,
/// but its requested destination binding or strict policy was not confirmed.
#[cfg(windows)]
pub fn complete_private_publication_pair(
    staging: std::fs::File,
    destination_directory: std::os::windows::io::BorrowedHandle<'_>,
    destination_name: &std::ffi::OsStr,
) -> Result<std::fs::File, PrivatePublicationPairError> {
    platform::complete_publication_pair(staging, destination_directory, destination_name)
}

/// Atomically create a private staging file whose handle permits delete sharing.
///
/// This variant exists for create-only hard-link publication. The strict parent-directory handles
/// must remain retained while this handle is live, and callers must validate the transition from
/// [`PrivateFileLinkState::Single`] to [`PrivateFileLinkState::PublicationPair`] before removing
/// the staging link by handle.
///
/// # Errors
///
/// Returns a typed, path-free failure under the same conditions as [`create_private_file`].
#[cfg(windows)]
pub fn create_private_staging_file(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::create_file(path, true)
}

/// Consume a writable private staging handle and return an exact read/delete handle that denies
/// write sharing, without reopening the file by pathname.
///
/// The transition uses handle-relative Windows reopen operations. A short-lived intermediate
/// handle admits the consumed writer, then a second reopen proves that no competing writer remains
/// before the intermediate handle is dropped. The returned handle is suitable for create-only
/// hard-link publication and strict [`PrivateFileLinkState::PublicationPair`] verification.
/// A competing same-user writer can open, mutate, and close during that transition; callers whose
/// integrity decision predates sealing must revalidate contents through the returned sealed handle
/// before publication.
///
/// # Errors
///
/// Returns a typed, path-free failure if the input is not a strict single-link private file, an
/// exact handle transition fails, a competing writer prevents the sealed reopen, or handle-bound
/// cleanup cannot be confirmed. Once transition begins, every failure attempts deletion through a
/// retained exact handle and reports its cleanup status.
#[cfg(windows)]
pub fn seal_private_staging_file(
    file: std::fs::File,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::seal_staging_file(file)
}

/// Open an existing private regular file without following reparse points.
///
/// The retained handle permits concurrent readers but denies write and delete sharing, keeping
/// both contents and pathname stable through the caller's validation and read.
///
/// # Errors
///
/// Returns a typed, path-free failure if the path cannot be opened or the file, filesystem,
/// owner, hard-link state, or protected DACL differs from the private-file policy.
#[cfg(windows)]
pub fn open_private_file(path: &std::path::Path) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open_file(path)
}

/// Open an existing strict private file for a durability-only synchronization retry.
///
/// The retained handle requests read/write access so [`std::fs::File::sync_all`] can issue the
/// Windows flush, shares only reads, and therefore denies competing writers, deletion, rename, and
/// pathname replacement. It opens the final component without following reparse points and accepts
/// only a strict, single-link private file. The function never creates or replaces a path.
///
/// Callers should use the write access only for `sync_all`; writing through this handle would mutate
/// the already-published artifact whose durability is being retried.
///
/// # Errors
///
/// Returns a typed, path-free failure if the path cannot be opened or the file, filesystem, owner,
/// single-link state, or protected DACL differs from the strict private-file policy.
#[cfg(windows)]
pub fn open_private_file_for_sync(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open_file_for_sync(path)
}

/// Open an existing private regular file for identity-bound removal after a same-volume rename.
///
/// The returned handle requests `DELETE` access and permits read and delete sharing. It therefore
/// remains bound to the verified file while another handle renames the file, and can subsequently
/// be consumed by [`remove_private_file_handle`] to remove that exact renamed object. Write sharing
/// remains denied while the handle is live.
///
/// # Errors
///
/// Returns a typed, path-free failure if the path cannot be opened or the file, filesystem,
/// owner, single-link state, or protected DACL differs from the private-file policy.
#[cfg(windows)]
pub fn open_private_file_for_removal(
    path: &std::path::Path,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open_file_for_removal(path)
}

/// Open an existing private regular file for identity-bound removal in an explicit link state.
///
/// Like [`open_private_file_for_removal`], the returned handle requests `DELETE` access, permits
/// read and delete sharing, denies write sharing, and does not follow reparse points. The file must
/// satisfy the strict private owner, protected-DACL, ACL-filesystem, and requested hard-link-state
/// policy before the handle is returned. This permits crash recovery to reopen a staging path in
/// [`PrivateFileLinkState::PublicationPair`] and safely consume it with
/// [`remove_private_file_handle_in_state`].
///
/// # Errors
///
/// Returns a typed, path-free failure if the path cannot be opened or the file, filesystem,
/// owner, requested link state, or protected DACL differs from the private-file policy.
#[cfg(windows)]
pub fn open_private_file_for_removal_in_state(
    path: &std::path::Path,
    link_state: PrivateFileLinkState,
) -> Result<std::fs::File, PrivateDirectoryError> {
    platform::open_file_for_removal_in_state(path, link_state)
}

/// Verify a retained Windows directory handle against the strict private-directory policy.
///
/// # Errors
///
/// Returns a typed, path-free failure if the handle is not a plain directory on an ACL-capable
/// filesystem or its owner, protected-DACL state, or exact ACE allowlist differs from policy.
#[cfg(windows)]
pub fn verify_private_directory_handle(
    handle: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<(), PrivateDirectoryError> {
    platform::verify(handle)
}

/// Synchronize cached metadata for one retained strict private directory.
///
/// This operation performs no pathname lookup. It verifies the exact retained directory before
/// and after issuing synchronous `NtFlushBuffersFileEx` normal mode, which requests cached data,
/// filesystem metadata, and the underlying storage cache to be flushed. Handles returned by
/// [`create_private_directory`], [`open_private_directory`], and
/// [`open_private_directory_read_guard`] include the minimal directory-write access required by
/// Windows while retaining their documented no-delete-sharing behavior.
///
/// A successful return means Windows reported completion of the flush request. Physical hardware
/// can still fail to honor cache-flush commands; this API cannot strengthen the storage device's
/// durability guarantees.
///
/// # Errors
///
/// Returns a typed, path-free failure if the retained object no longer satisfies strict private
/// directory policy, its handle lacks directory-write access, or Windows does not report successful
/// synchronous completion. The function never converts an unsupported or rejected flush into
/// success.
#[cfg(windows)]
pub fn sync_private_directory_handle(
    directory: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<(), PrivateDirectoryError> {
    platform::sync_directory(directory)
}

/// Verify a retained Windows regular-file handle against the strict private-file policy.
///
/// The file must be non-reparse, have exactly one hard link, be owned by the current process-token
/// user, and use the protected current-user/SYSTEM/Administrators DACL.
///
/// # Errors
///
/// Returns a typed, path-free failure if the handle or its ACL differs from policy.
#[cfg(windows)]
pub fn verify_private_file_handle(
    handle: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<(), PrivateDirectoryError> {
    platform::verify_file(handle, PrivateFileLinkState::Single)
}

/// Verify a retained Windows private-file handle in an explicit hard-link publication state.
///
/// # Errors
///
/// Returns a typed, path-free failure if the handle or its ACL/link state differs from policy.
#[cfg(windows)]
pub fn verify_private_file_handle_in_state(
    handle: std::os::windows::io::BorrowedHandle<'_>,
    link_state: PrivateFileLinkState,
) -> Result<(), PrivateDirectoryError> {
    platform::verify_file(handle, link_state)
}

/// Return the hard-link count for an arbitrary retained Windows regular-file handle.
///
/// This policy-neutral query rejects directories and reparse points, but deliberately does not
/// inspect filesystem ACL support, owner identity, or DACL contents. Callers that require the
/// strict private-file policy must separately use [`verify_private_file_handle`] or
/// [`verify_private_file_handle_in_state`].
///
/// # Errors
///
/// Returns a typed, path-free failure if Windows cannot query the handle or if it identifies a
/// directory or reparse point rather than a regular file.
#[cfg(windows)]
pub fn regular_file_link_count(
    handle: std::os::windows::io::BorrowedHandle<'_>,
) -> Result<u32, PrivateDirectoryError> {
    platform::regular_file_link_count(handle)
}

/// Verify and remove the exact empty private directory identified by a retained Windows handle.
///
/// The consumed handle must be the no-delete-sharing handle returned by
/// [`create_private_directory`]. No pathname lookup or recursive pathname deletion occurs.
///
/// # Errors
///
/// Returns a typed, path-free failure if the handle no longer satisfies private-directory policy
/// or Windows cannot mark the exact empty directory for deletion. Every error reports
/// [`PrivateDirectoryCleanupStatus::Uncertain`].
#[cfg(windows)]
pub fn remove_private_directory_handle(
    directory: std::fs::File,
) -> Result<(), PrivateDirectoryError> {
    platform::remove(directory)
}

/// Recursively remove the strict private root identified by a retained Windows directory handle.
///
/// The root path is resolved from the handle itself while its no-delete-sharing contract remains
/// active. Every descendant is enumerated with a filesystem identifier, reopened without
/// following reparse points and without delete sharing, matched to that identifier, and retained
/// through exact handle disposition. Descendant directories may use ordinary inherited security
/// descriptors; reparse points, non-regular files, and multiply linked regular files are rejected.
/// Concurrently added entries are never traversed and make final directory disposition fail.
///
/// # Errors
///
/// Returns a typed failure if the root is not strict and private, a descendant cannot be bound or
/// violates the tree policy, or Windows cannot remove an exact retained object. Because recursive
/// cleanup may already have removed siblings, every failure reports
/// [`PrivateDirectoryCleanupStatus::Uncertain`].
#[cfg(windows)]
pub fn remove_private_directory_tree_handle(
    directory: std::fs::File,
) -> Result<(), PrivateDirectoryError> {
    platform::remove_directory_tree(directory)
}

/// Verify and remove the exact private regular file identified by a retained Windows handle.
///
/// # Errors
///
/// Returns a typed, path-free failure if the handle no longer satisfies the private-file policy
/// or Windows cannot mark the exact file for deletion.
#[cfg(windows)]
pub fn remove_private_file_handle(file: std::fs::File) -> Result<(), PrivateDirectoryError> {
    platform::remove_file(file, PrivateFileLinkState::Single)
}

/// Verify and remove the exact private regular-file link in an explicit publication state.
///
/// This is intended for the staging handle returned by [`create_private_staging_file`]. With
/// [`PrivateFileLinkState::PublicationPair`], Windows removes the staging link opened by that
/// handle while preserving the separately verified final hard link.
///
/// # Errors
///
/// Returns a typed, path-free failure if the handle no longer satisfies the requested private-file
/// policy or Windows cannot mark the exact link for deletion.
#[cfg(windows)]
pub fn remove_private_file_handle_in_state(
    file: std::fs::File,
    link_state: PrivateFileLinkState,
) -> Result<(), PrivateDirectoryError> {
    platform::remove_file(file, link_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];
    const SYSTEM: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    const ADMINISTRATORS: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];

    #[test]
    fn exact_private_acl_is_accepted_independent_of_ace_order() {
        let raw = acl(&[
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                ADMINISTRATORS,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(validate_acl(&raw, &[USER, SYSTEM, ADMINISTRATORS]), Ok(()));
    }

    #[test]
    fn regular_file_acl_requires_non_inheriting_aces() {
        let raw = acl(&[
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                FILE_ACE_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                FILE_ACE_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                ADMINISTRATORS,
                ACCESS_ALLOWED_ACE_TYPE,
                FILE_ACE_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(
            validate_acl_with_flags(&raw, &[USER, SYSTEM, ADMINISTRATORS], FILE_ACE_FLAGS),
            Ok(())
        );
        assert_eq!(
            validate_acl(&raw, &[USER, SYSTEM, ADMINISTRATORS]),
            Err(PrivateDirectoryAclViolation::UnexpectedAceFlags)
        );
    }

    #[test]
    fn unknown_allow_ace_is_rejected() {
        let unknown = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
        let raw = acl(&[
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                &unknown,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(
            validate_acl(&raw, &[USER, SYSTEM, ADMINISTRATORS]),
            Err(PrivateDirectoryAclViolation::UnknownPrincipal)
        );
    }

    #[test]
    fn deny_object_and_inherited_aces_are_rejected() {
        for (ace_type, flags, expected) in [
            (
                1,
                DIRECTORY_INHERIT_FLAGS,
                PrivateDirectoryAclViolation::UnsupportedAceType,
            ),
            (
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS | 0x10,
                PrivateDirectoryAclViolation::UnexpectedAceFlags,
            ),
            (
                5,
                DIRECTORY_INHERIT_FLAGS,
                PrivateDirectoryAclViolation::UnsupportedAceType,
            ),
        ] {
            let raw = acl(&[
                ace(USER, ace_type, flags, FILE_ALL_ACCESS_MASK),
                ace(
                    SYSTEM,
                    ACCESS_ALLOWED_ACE_TYPE,
                    DIRECTORY_INHERIT_FLAGS,
                    FILE_ALL_ACCESS_MASK,
                ),
                ace(
                    ADMINISTRATORS,
                    ACCESS_ALLOWED_ACE_TYPE,
                    DIRECTORY_INHERIT_FLAGS,
                    FILE_ALL_ACCESS_MASK,
                ),
            ]);
            assert_eq!(
                validate_acl(&raw, &[USER, SYSTEM, ADMINISTRATORS]),
                Err(expected)
            );
        }
    }

    #[test]
    fn broad_or_root_inherit_only_access_is_rejected() {
        for (flags, mask, expected) in [
            (
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK | 0x0040_0000,
                PrivateDirectoryAclViolation::UnexpectedAccessMask,
            ),
            (
                DIRECTORY_INHERIT_FLAGS | 0x08,
                FILE_ALL_ACCESS_MASK,
                PrivateDirectoryAclViolation::UnexpectedAceFlags,
            ),
        ] {
            let raw = acl(&[
                ace(USER, ACCESS_ALLOWED_ACE_TYPE, flags, mask),
                ace(
                    SYSTEM,
                    ACCESS_ALLOWED_ACE_TYPE,
                    DIRECTORY_INHERIT_FLAGS,
                    FILE_ALL_ACCESS_MASK,
                ),
                ace(
                    ADMINISTRATORS,
                    ACCESS_ALLOWED_ACE_TYPE,
                    DIRECTORY_INHERIT_FLAGS,
                    FILE_ALL_ACCESS_MASK,
                ),
            ]);
            assert_eq!(
                validate_acl(&raw, &[USER, SYSTEM, ADMINISTRATORS]),
                Err(expected)
            );
        }
    }

    #[test]
    fn duplicate_missing_and_malformed_principals_are_rejected() {
        let duplicate = acl(&[
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                ADMINISTRATORS,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(
            validate_acl(&duplicate, &[USER, SYSTEM, ADMINISTRATORS]),
            Err(PrivateDirectoryAclViolation::DuplicatePrincipal)
        );

        let malformed_sid = [1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let malformed = acl(&[
            ace(
                &malformed_sid,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                ADMINISTRATORS,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(
            validate_acl(&malformed, &[USER, SYSTEM, ADMINISTRATORS]),
            Err(PrivateDirectoryAclViolation::InvalidSid)
        );

        let missing = acl(&[
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(
            validate_acl(&missing, &[USER, SYSTEM, ADMINISTRATORS]),
            Err(PrivateDirectoryAclViolation::WrongAceCount)
        );

        let mut truncated = acl(&[
            ace(
                USER,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                ADMINISTRATORS,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        truncated.pop();
        assert_eq!(
            validate_acl(&truncated, &[USER, SYSTEM, ADMINISTRATORS]),
            Err(PrivateDirectoryAclViolation::Malformed)
        );
    }

    #[test]
    fn duplicate_fixed_principal_uses_one_exact_ace() {
        let deduplicated = acl(&[
            ace(
                SYSTEM,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
            ace(
                ADMINISTRATORS,
                ACCESS_ALLOWED_ACE_TYPE,
                DIRECTORY_INHERIT_FLAGS,
                FILE_ALL_ACCESS_MASK,
            ),
        ]);
        assert_eq!(
            validate_acl(&deduplicated, &[SYSTEM, ADMINISTRATORS]),
            Ok(())
        );
    }

    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let length = ACL_HEADER_BYTES + aces.iter().map(Vec::len).sum::<usize>();
        let mut raw = vec![0; ACL_HEADER_BYTES];
        raw[0] = ACL_REVISION;
        raw[2..4].copy_from_slice(
            &u16::try_from(length)
                .expect("test ACL length")
                .to_le_bytes(),
        );
        raw[4..6].copy_from_slice(
            &u16::try_from(aces.len())
                .expect("test ACE count")
                .to_le_bytes(),
        );
        for ace in aces {
            raw.extend_from_slice(ace);
        }
        raw
    }

    fn ace(sid: &[u8], ace_type: u8, flags: u8, mask: u32) -> Vec<u8> {
        let length = ACCESS_ALLOWED_ACE_PREFIX_BYTES + sid.len();
        let mut raw = Vec::with_capacity(length);
        raw.push(ace_type);
        raw.push(flags);
        raw.extend_from_slice(
            &u16::try_from(length)
                .expect("test ACE length")
                .to_le_bytes(),
        );
        raw.extend_from_slice(&mask.to_le_bytes());
        raw.extend_from_slice(sid);
        raw
    }
}
