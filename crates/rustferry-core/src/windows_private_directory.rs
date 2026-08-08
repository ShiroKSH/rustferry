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
    /// Read filesystem capabilities from the retained handle.
    QueryFileSystem,
    /// Read the security descriptor from the retained handle.
    QuerySecurityDescriptor,
    /// Mark the exact retained directory object for deletion.
    RemoveDirectory,
    /// Mark the exact retained regular-file link for deletion.
    RemoveFile,
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
        ffi::c_void,
        fs::File,
        io,
        mem::size_of,
        os::windows::{
            ffi::OsStrExt as _,
            io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle},
        },
        path::Path,
        ptr, slice,
    };

    use windows_sys::Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, HANDLE,
            INVALID_HANDLE_VALUE,
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
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FileDispositionInfo, GetFileInformationByHandle,
            GetVolumeInformationByHandleW, OPEN_EXISTING, SetFileInformationByHandle, WRITE_DAC,
        },
        System::{
            SystemServices::{FILE_PERSISTENT_ACLS, SECURITY_DESCRIPTOR_REVISION},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    use super::{
        DIRECTORY_INHERIT_FLAGS, FILE_ACE_FLAGS, PrivateDirectoryAclViolation,
        PrivateDirectoryCleanupStatus, PrivateDirectoryError, PrivateDirectoryErrorKind,
        PrivateDirectoryOperation, PrivateFileLinkState, SID_HEADER_BYTES, valid_sid_bytes,
        validate_acl_with_flags,
    };

    const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 128 * 1024;

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

    pub(super) fn verify(handle: BorrowedHandle<'_>) -> Result<(), PrivateDirectoryError> {
        let user = current_process_user_sid()?;
        verify_with_user(handle.as_raw_handle(), &user, PrivateObjectKind::Directory)
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

    pub(super) fn remove(directory: File) -> Result<(), PrivateDirectoryError> {
        remove_private_object(directory, PrivateObjectKind::Directory)
    }

    pub(super) fn remove_file(
        file: File,
        link_state: PrivateFileLinkState,
    ) -> Result<(), PrivateDirectoryError> {
        remove_private_object(file, PrivateObjectKind::RegularFile(link_state))
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
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` is borrowed for the call and `information` is writable initialized
        // storage of the exact structure expected by `GetFileInformationByHandle`.
        unsafe {
            win_bool(
                GetFileInformationByHandle(handle, &raw mut information),
                PrivateDirectoryOperation::QueryAttributes,
            )?;
        }
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
            PrivateObjectKind::RegularFile(_)
                if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 =>
            {
                return Err(PrivateDirectoryError::new(
                    PrivateDirectoryErrorKind::NotRegularFile,
                    None,
                ));
            }
            PrivateObjectKind::RegularFile(link_state)
                if information.nNumberOfLinks != link_state.expected_links() =>
            {
                return Err(PrivateDirectoryError::new(
                    PrivateDirectoryErrorKind::MultipleLinks,
                    None,
                ));
            }
            PrivateObjectKind::Directory | PrivateObjectKind::RegularFile(_) => {}
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
        let desired_access = FILE_GENERIC_READ | DELETE | if write_dacl { WRITE_DAC } else { 0 };
        // SAFETY: `path` is NUL-terminated; null security/template pointers are permitted. Opening
        // with `OPEN_REPARSE_POINT` ensures verification observes the named object itself.
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
            return Err(operation_error(
                PrivateDirectoryOperation::OpenDirectory,
                last_os_code(),
            ));
        }
        // SAFETY: `CreateFileW` returned one owned real handle, transferred exactly once to File.
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    fn open_regular_file(path: &[u16]) -> Result<File, PrivateDirectoryError> {
        // SAFETY: `path` is NUL-terminated; null security/template pointers are permitted. The
        // retained handle allows only other readers, so content and pathname remain stable.
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
            os::windows::{fs::symlink_dir, io::AsHandle as _},
        };

        use super::*;
        use windows_sys::Win32::Security::{
            SetKernelObjectSecurity, UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, READ_CONTROL,
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
        fn retained_handle_removes_the_exact_empty_directory() {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let child = temporary.path().join("private");
            let handle = create(&child).expect("protected private directory");

            remove(handle).expect("handle-bound removal");
            assert!(!child.exists());
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
