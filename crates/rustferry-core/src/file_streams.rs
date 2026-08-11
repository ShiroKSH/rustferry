//! Retained-handle inspection for regular-file data streams.

#![cfg_attr(windows, allow(unsafe_code))]

use std::{error::Error, fmt, fs::File};

/// Stable class of a retained regular-file stream inspection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RegularFileStreamErrorKind {
    /// The supplied handle does not identify a regular file.
    NotRegularFile,
    /// The operating system rejected the retained-handle stream query.
    QueryFailed,
    /// Stream metadata exceeded the fixed defensive query bound.
    ResponseTooLarge,
    /// The operating system returned malformed or ambiguous stream metadata.
    MalformedResponse,
    /// A named alternate data stream exists on the retained regular file.
    NamedStream,
}

/// Secret-free retained-handle stream inspection error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegularFileStreamError {
    kind: RegularFileStreamErrorKind,
    os_code: Option<i32>,
}

impl RegularFileStreamError {
    const fn new(kind: RegularFileStreamErrorKind, os_code: Option<i32>) -> Self {
        Self { kind, os_code }
    }

    /// Return the stable failure class.
    pub const fn kind(self) -> RegularFileStreamErrorKind {
        self.kind
    }

    /// Return a public operating-system error code when the query itself failed.
    pub const fn os_code(self) -> Option<i32> {
        self.os_code
    }
}

impl fmt::Display for RegularFileStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            RegularFileStreamErrorKind::NotRegularFile => {
                formatter.write_str("stream inspection requires a retained regular-file handle")
            }
            RegularFileStreamErrorKind::QueryFailed => {
                if let Some(code) = self.os_code {
                    write!(
                        formatter,
                        "retained file stream query failed with OS error {code}"
                    )
                } else {
                    formatter.write_str("retained file stream query failed")
                }
            }
            RegularFileStreamErrorKind::ResponseTooLarge => {
                formatter.write_str("retained file stream metadata exceeded its fixed bound")
            }
            RegularFileStreamErrorKind::MalformedResponse => {
                formatter.write_str("retained file stream metadata was malformed")
            }
            RegularFileStreamErrorKind::NamedStream => {
                formatter.write_str("retained regular file has a named alternate data stream")
            }
        }
    }
}

impl Error for RegularFileStreamError {}

/// Verify that a retained regular-file handle exposes only its unnamed default data stream.
///
/// Windows performs a bounded handle query and rejects every named stream without retaining or
/// rendering its name. Filesystems without Windows alternate data streams return success after
/// confirming the handle is a regular file.
///
/// # Errors
///
/// Returns a typed failure for a non-file handle, query failure, oversized or malformed metadata,
/// or any named alternate data stream.
pub fn verify_regular_file_has_no_named_streams(file: &File) -> Result<(), RegularFileStreamError> {
    let metadata = file.metadata().map_err(|error| {
        RegularFileStreamError::new(
            RegularFileStreamErrorKind::QueryFailed,
            error.raw_os_error(),
        )
    })?;
    if !metadata.is_file() {
        return Err(RegularFileStreamError::new(
            RegularFileStreamErrorKind::NotRegularFile,
            None,
        ));
    }

    #[cfg(windows)]
    return windows::verify(file);

    #[cfg(not(windows))]
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::{fs::File, io, os::windows::io::AsRawHandle as _, slice};

    use windows_sys::Win32::{
        Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA},
        Storage::FileSystem::{FileStreamInfo, GetFileInformationByHandleEx},
    };

    use super::{RegularFileStreamError, RegularFileStreamErrorKind};

    const INITIAL_QUERY_BYTES: usize = 1_024;
    const MAX_QUERY_BYTES: usize = 1024 * 1024;
    const ENTRY_HEADER_BYTES: usize = 24;
    pub(super) fn verify(file: &File) -> Result<(), RegularFileStreamError> {
        let mut capacity = INITIAL_QUERY_BYTES;
        loop {
            let mut storage = vec![0_u64; capacity / size_of::<u64>()];
            let succeeded = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    FileStreamInfo,
                    storage.as_mut_ptr().cast(),
                    u32::try_from(capacity).expect("bounded stream query capacity fits u32"),
                )
            };
            if succeeded != 0 {
                let bytes =
                    unsafe { slice::from_raw_parts(storage.as_ptr().cast::<u8>(), capacity) };
                return parse_streams(bytes);
            }

            let os_code = io::Error::last_os_error().raw_os_error();
            let retryable = os_code
                .and_then(|code| u32::try_from(code).ok())
                .is_some_and(|code| code == ERROR_MORE_DATA || code == ERROR_INSUFFICIENT_BUFFER);
            if !retryable {
                return Err(RegularFileStreamError::new(
                    RegularFileStreamErrorKind::QueryFailed,
                    os_code,
                ));
            }
            if capacity == MAX_QUERY_BYTES {
                return Err(RegularFileStreamError::new(
                    RegularFileStreamErrorKind::ResponseTooLarge,
                    None,
                ));
            }
            capacity = capacity.saturating_mul(2).min(MAX_QUERY_BYTES);
        }
    }

    fn parse_streams(bytes: &[u8]) -> Result<(), RegularFileStreamError> {
        let mut offset = 0_usize;
        let mut entries = 0_usize;
        loop {
            let next = read_u32(bytes, offset)? as usize;
            let name_bytes = read_u32(bytes, offset + 4)? as usize;
            if name_bytes == 0 || !name_bytes.is_multiple_of(size_of::<u16>()) {
                return Err(malformed());
            }
            let name_start = offset
                .checked_add(ENTRY_HEADER_BYTES)
                .ok_or_else(malformed)?;
            let name_end = name_start.checked_add(name_bytes).ok_or_else(malformed)?;
            let entry_end = if next == 0 {
                bytes.len()
            } else {
                if !next.is_multiple_of(align_of::<u64>()) || next < ENTRY_HEADER_BYTES + name_bytes
                {
                    return Err(malformed());
                }
                offset.checked_add(next).ok_or_else(malformed)?
            };
            if name_end > entry_end || entry_end > bytes.len() {
                return Err(malformed());
            }
            if !is_default_stream(&bytes[name_start..name_end]) {
                return Err(RegularFileStreamError::new(
                    RegularFileStreamErrorKind::NamedStream,
                    None,
                ));
            }
            entries = entries.checked_add(1).ok_or_else(malformed)?;
            if entries != 1 || next == 0 {
                break;
            }
            offset = entry_end;
        }
        if entries == 1 {
            Ok(())
        } else {
            Err(malformed())
        }
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RegularFileStreamError> {
        let end = offset.checked_add(size_of::<u32>()).ok_or_else(malformed)?;
        let raw: [u8; 4] = bytes
            .get(offset..end)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?;
        Ok(u32::from_ne_bytes(raw))
    }

    fn is_default_stream(name: &[u8]) -> bool {
        if name.len() != 14 {
            return false;
        }
        let mut units = [0_u16; 7];
        for (index, chunk) in name.chunks_exact(2).enumerate() {
            units[index] = u16::from_ne_bytes([chunk[0], chunk[1]]);
        }
        units[0] == u16::from(b':')
            && units[1] == u16::from(b':')
            && units[2] == u16::from(b'$')
            && units[3..].iter().zip(b"DATA").all(|(actual, expected)| {
                *actual == u16::from(*expected)
                    || *actual == u16::from(expected.to_ascii_lowercase())
            })
    }

    const fn malformed() -> RegularFileStreamError {
        RegularFileStreamError::new(RegularFileStreamErrorKind::MalformedResponse, None)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, fs::File};

    use super::{RegularFileStreamErrorKind, verify_regular_file_has_no_named_streams};

    #[test]
    fn regular_file_without_named_streams_is_accepted() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("source.txt");
        fs::write(&path, b"source").unwrap();
        verify_regular_file_has_no_named_streams(&File::open(path).unwrap()).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn directory_handle_is_not_a_regular_file() {
        let temporary = tempfile::tempdir().unwrap();
        let error =
            verify_regular_file_has_no_named_streams(&File::open(temporary.path()).unwrap())
                .unwrap_err();
        assert_eq!(error.kind(), RegularFileStreamErrorKind::NotRegularFile);
    }

    #[cfg(windows)]
    #[test]
    fn retained_handle_rejects_named_stream_after_path_replacement() {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt as _};

        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        const FILE_SHARE_DELETE: u32 = 0x0000_0004;

        let temporary = tempfile::tempdir().unwrap();
        let original = temporary.path().join("source.txt");
        let moved = temporary.path().join("moved.txt");
        fs::write(&original, b"source").unwrap();
        fs::write(format!("{}:private", original.display()), b"credential").unwrap();
        let retained = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&original)
            .unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::write(&original, b"clean replacement").unwrap();

        let error = verify_regular_file_has_no_named_streams(&retained).unwrap_err();
        assert_eq!(error.kind(), RegularFileStreamErrorKind::NamedStream);
        assert!(!error.to_string().contains("private"));
        verify_regular_file_has_no_named_streams(&File::open(original).unwrap()).unwrap();
    }
}
