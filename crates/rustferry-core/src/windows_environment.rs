//! Trusted Windows process-environment values derived from the operating system.

#![allow(unsafe_code)]

use std::{
    ffi::OsString,
    fs, io,
    os::windows::ffi::OsStringExt as _,
    path::{Component, PathBuf},
};

use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;

use crate::filesystem_identity::DirectoryFilesystemIdentity;

const INITIAL_WINDOWS_DIRECTORY_CAPACITY: usize = 260;
const MAX_WINDOWS_DIRECTORY_CAPACITY: usize = 32_768;

/// Return the authoritative shared Windows directory for use as `SystemRoot`.
///
/// The value comes directly from Windows rather than the ambient process
/// environment. The returned path is absolute, normal, and bound to a real
/// non-reparse directory before it is returned.
///
/// # Errors
///
/// Returns an I/O error when Windows does not provide a usable directory or
/// the reported filesystem object cannot be validated safely.
pub fn windows_system_root() -> io::Result<PathBuf> {
    let path = query_windows_directory()?;
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an invalid system directory",
        ));
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned an unusable system directory",
        ));
    }
    DirectoryFilesystemIdentity::capture(&path).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Windows system directory validation failed: {error}"),
        )
    })?;
    Ok(path)
}

fn query_windows_directory() -> io::Result<PathBuf> {
    let mut buffer = vec![0_u16; INITIAL_WINDOWS_DIRECTORY_CAPACITY];
    loop {
        let capacity = u32::try_from(buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows system directory exceeded the supported length",
            )
        })?;
        // SAFETY: `buffer` is writable for exactly `capacity` UTF-16 code units.
        let length = unsafe { GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), capacity) };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid system directory length",
            )
        })?;
        if length < buffer.len() {
            if buffer[..length].contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Windows returned an invalid system directory",
                ));
            }
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        let grown_capacity = buffer.len().checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows system directory exceeded the supported length",
            )
        })?;
        let next_capacity = length.max(grown_capacity);
        if next_capacity > MAX_WINDOWS_DIRECTORY_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows system directory exceeded the supported length",
            ));
        }
        buffer.resize(next_capacity, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_root_is_an_absolute_stable_directory() {
        let first = windows_system_root().expect("Windows system root");
        let second = windows_system_root().expect("stable Windows system root");

        assert_eq!(first, second);
        assert!(first.is_absolute());
        assert!(first.is_dir());
        DirectoryFilesystemIdentity::capture(&first).expect("handle-bound directory identity");
    }
}
