//! Small serde-based key/value storage.
//!
//! This module is not a database or secure credential store. [`FileStorage`] uses same-directory
//! temporary files and atomic rename on platforms that provide atomic filesystem rename. Each
//! record carries a format version and checksum so truncated or modified records return
//! [`Error::CorruptStorage`] instead of silently becoming defaults.

use crate::runtime::current_runtime;
use crate::{Error, Result};
use parking_lot::RwLock;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize as DeriveSerialize};
use serde_json::Value;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Raw thread-safe storage implemented by platform and host adapters.
pub trait StorageBackend: Send + Sync + 'static {
    /// Read raw application bytes.
    fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Atomically replace raw application bytes.
    fn set_raw(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Remove one value. Missing keys are not errors.
    fn remove(&self, key: &str) -> Result<()>;

    /// Return whether a key exists without decoding it.
    fn contains(&self, key: &str) -> Result<bool>;

    /// Remove all values owned by this backend.
    fn clear(&self) -> Result<()>;
}

/// Thread-safe in-memory storage for tests and previews.
#[derive(Debug, Default)]
pub struct InMemoryStorage {
    values: RwLock<BTreeMap<String, Vec<u8>>>,
}

impl InMemoryStorage {
    /// Construct an empty backend.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject raw bytes, including intentionally corrupt values for tests.
    pub fn insert_raw(&self, key: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.values.write().insert(key.into(), value.into());
    }

    /// Snapshot raw values for assertions.
    pub fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
        self.values.read().clone()
    }
}

impl StorageBackend for InMemoryStorage {
    fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        Ok(self.values.read().get(key).cloned())
    }

    fn set_raw(&self, key: &str, value: &[u8]) -> Result<()> {
        validate_key(key)?;
        self.values.write().insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        self.values.write().remove(key);
        Ok(())
    }

    fn contains(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        Ok(self.values.read().contains_key(key))
    }

    fn clear(&self) -> Result<()> {
        self.values.write().clear();
        Ok(())
    }
}

#[derive(Debug, DeriveSerialize, Deserialize)]
struct FileRecord {
    format_version: u32,
    checksum: u64,
    value: Vec<u8>,
}

/// Filesystem-backed atomic storage suitable for generated mobile hosts.
#[derive(Debug)]
pub struct FileStorage {
    root: PathBuf,
    access: Mutex<()>,
}

impl FileStorage {
    /// Open or create a dedicated application storage directory.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|error| io_error("create directory", &root, &error))?;
        if !root.is_dir() {
            return Err(Error::StorageIo {
                action: "open directory",
                path: root.display().to_string(),
                message: "path is not a directory".to_owned(),
            });
        }
        Ok(Self {
            root,
            access: Mutex::new(()),
        })
    }

    /// Storage directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for_key(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        let mut encoded = String::with_capacity(key.len() * 2);
        for byte in key.as_bytes() {
            use std::fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        Ok(self.root.join(format!("{encoded}.rustferry-store")))
    }
}

impl StorageBackend for FileStorage {
    fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let _access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = self.path_for_key(key)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("read", &path, &error)),
        };
        let record: FileRecord =
            serde_json::from_slice(&bytes).map_err(|error| Error::CorruptStorage {
                key: key.to_owned(),
                message: format!("record cannot be decoded: {error}"),
            })?;
        if record.format_version != 1 {
            return Err(Error::CorruptStorage {
                key: key.to_owned(),
                message: format!("unsupported record format {}", record.format_version),
            });
        }
        if checksum(&record.value) != record.checksum {
            return Err(Error::CorruptStorage {
                key: key.to_owned(),
                message: "checksum mismatch".to_owned(),
            });
        }
        Ok(Some(record.value))
    }

    fn set_raw(&self, key: &str, value: &[u8]) -> Result<()> {
        let _access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = self.path_for_key(key)?;
        let record = FileRecord {
            format_version: 1,
            checksum: checksum(value),
            value: value.to_vec(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|error| Error::CorruptStorage {
            key: key.to_owned(),
            message: format!("record cannot be encoded: {error}"),
        })?;
        let temporary = self.root.join(format!(".{}.tmp", Uuid::new_v4()));

        let write_result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temporary)
                .map_err(|error| io_error("create temporary record", &temporary, &error))?;
            file.write_all(&bytes)
                .map_err(|error| io_error("write temporary record", &temporary, &error))?;
            file.sync_all()
                .map_err(|error| io_error("sync temporary record", &temporary, &error))?;
            fs::rename(&temporary, &path)
                .map_err(|error| io_error("replace record", &path, &error))?;
            sync_directory(&self.root)?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    fn remove(&self, key: &str) -> Result<()> {
        let _access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let path = self.path_for_key(key)?;
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(&self.root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error("remove", &path, &error)),
        }
    }

    fn contains(&self, key: &str) -> Result<bool> {
        let _access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(self.path_for_key(key)?.is_file())
    }

    fn clear(&self) -> Result<()> {
        let _access = self
            .access
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entries = fs::read_dir(&self.root)
            .map_err(|error| io_error("list directory", &self.root, &error))?;
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error("read directory entry", &self.root, &error))?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "rustferry-store")
            {
                fs::remove_file(&path).map_err(|error| io_error("remove", &path, &error))?;
            }
        }
        sync_directory(&self.root)
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync directory", path, &error))?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_: &Path) -> Result<()> {
    Ok(())
}

fn checksum(bytes: &[u8]) -> u64 {
    // FNV-1a is an integrity check against partial/corrupt writes, not a cryptographic MAC.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn io_error(action: &'static str, path: &Path, error: &std::io::Error) -> Error {
    Error::StorageIo {
        action,
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::invalid("storage key", "must not be empty"));
    }
    if key.len() > 512 {
        return Err(Error::invalid("storage key", "must not exceed 512 bytes"));
    }
    Ok(())
}

fn backend() -> Result<Arc<dyn StorageBackend>> {
    current_runtime()
        .storage_backend()
        .ok_or_else(|| Error::unsupported(crate::Operation::Storage))
}

/// Whether storage is configured on the active runtime.
pub fn is_supported() -> bool {
    current_runtime().storage_backend().is_some()
}

/// Serialize and atomically store a value.
pub fn set<T: Serialize>(key: &str, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|error| Error::CorruptStorage {
        key: key.to_owned(),
        message: format!("value cannot be encoded: {error}"),
    })?;
    backend()?.set_raw(key, &bytes)
}

/// Load and deserialize a value, or return `None` when absent.
pub fn get<T: DeserializeOwned>(key: &str) -> Result<Option<T>> {
    let Some(bytes) = backend()?.get_raw(key)? else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| Error::CorruptStorage {
            key: key.to_owned(),
            message: format!("stored value cannot be decoded: {error}"),
        })
}

/// Remove one value. Missing keys are accepted.
pub fn remove(key: &str) -> Result<()> {
    backend()?.remove(key)
}

/// Test whether a key exists without deserializing its value.
pub fn contains(key: &str) -> Result<bool> {
    backend()?.contains(key)
}

/// Remove all ordinary and typed values owned by the active storage backend.
pub fn clear() -> Result<()> {
    backend()?.clear()
}

#[derive(DeriveSerialize, Deserialize)]
struct TypedRecord {
    version: u32,
    value: Value,
}

type Migration<T> = dyn Fn(u32, Value) -> Result<T> + Send + Sync + 'static;

/// A named typed value with an explicit schema version and optional migration hook.
pub struct Store<T> {
    name: String,
    key: String,
    current_version: u32,
    migration: Option<Arc<Migration<T>>>,
    backend: Arc<dyn StorageBackend>,
    marker: PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for Store<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Store")
            .field("name", &self.name)
            .field("current_version", &self.current_version)
            .finish_non_exhaustive()
    }
}

impl<T> Store<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Open a version-1 typed store using the active runtime backend.
    pub fn open(name: impl Into<String>) -> Result<Self> {
        Self::open_with_backend(name, 1, None, backend()?)
    }

    /// Open a versioned store with a migration function.
    ///
    /// The function receives the stored version and JSON value. A successful migration is
    /// immediately persisted at `current_version`.
    pub fn open_versioned(
        name: impl Into<String>,
        current_version: u32,
        migration: impl Fn(u32, Value) -> Result<T> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::open_with_backend(name, current_version, Some(Arc::new(migration)), backend()?)
    }

    /// Open a store against an explicitly supplied backend.
    pub fn open_on(name: impl Into<String>, backend: Arc<dyn StorageBackend>) -> Result<Self> {
        Self::open_with_backend(name, 1, None, backend)
    }

    fn open_with_backend(
        name: impl Into<String>,
        current_version: u32,
        migration: Option<Arc<Migration<T>>>,
        backend: Arc<dyn StorageBackend>,
    ) -> Result<Self> {
        let name = name.into();
        validate_key(&name)?;
        if current_version == 0 {
            return Err(Error::invalid("store version", "must be at least 1"));
        }
        Ok(Self {
            key: format!("typed:{name}"),
            name,
            current_version,
            migration,
            backend,
            marker: PhantomData,
        })
    }

    /// Load the value, running and persisting a configured migration when necessary.
    pub fn load(&self) -> Result<Option<T>> {
        let Some(bytes) = self.backend.get_raw(&self.key)? else {
            return Ok(None);
        };
        let record: TypedRecord =
            serde_json::from_slice(&bytes).map_err(|error| Error::CorruptStorage {
                key: self.name.clone(),
                message: format!("typed record cannot be decoded: {error}"),
            })?;
        if record.version == self.current_version {
            return serde_json::from_value(record.value)
                .map(Some)
                .map_err(|error| Error::CorruptStorage {
                    key: self.name.clone(),
                    message: format!("typed value cannot be decoded: {error}"),
                });
        }
        let Some(migration) = &self.migration else {
            return Err(Error::MigrationRequired {
                store: self.name.clone(),
                stored: record.version,
                current: self.current_version,
            });
        };
        let migrated = migration(record.version, record.value)?;
        self.save(&migrated)?;
        Ok(Some(migrated))
    }

    /// Atomically serialize and persist the value at the current schema version.
    pub fn save(&self, value: &T) -> Result<()> {
        let value = serde_json::to_value(value).map_err(|error| Error::CorruptStorage {
            key: self.name.clone(),
            message: format!("typed value cannot be encoded: {error}"),
        })?;
        let bytes = serde_json::to_vec(&TypedRecord {
            version: self.current_version,
            value,
        })
        .map_err(|error| Error::CorruptStorage {
            key: self.name.clone(),
            message: format!("typed record cannot be encoded: {error}"),
        })?;
        self.backend.set_raw(&self.key, &bytes)
    }

    /// Remove the typed value.
    pub fn remove(&self) -> Result<()> {
        self.backend.remove(&self.key)
    }

    /// Whether the typed value exists.
    pub fn contains(&self) -> Result<bool> {
        self.backend.contains(&self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Settings {
        count: u32,
    }

    #[test]
    fn file_storage_round_trips_and_reports_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::open(directory.path()).unwrap();
        storage.set_raw("counter", br#"{"value":42}"#).unwrap();
        assert_eq!(
            storage.get_raw("counter").unwrap(),
            Some(br#"{"value":42}"#.to_vec())
        );

        let path = storage.path_for_key("counter").unwrap();
        fs::write(path, b"truncated").unwrap();
        assert!(matches!(
            storage.get_raw("counter"),
            Err(Error::CorruptStorage { .. })
        ));
    }

    #[test]
    fn typed_store_migrates_and_persists_new_version() {
        let backend = Arc::new(InMemoryStorage::new());
        let v1 = Store::<Settings>::open_on("settings", backend.clone()).unwrap();
        v1.save(&Settings { count: 7 }).unwrap();

        let v2 = Store::<Settings>::open_with_backend(
            "settings",
            2,
            Some(Arc::new(|version, value| {
                assert_eq!(version, 1);
                Ok(Settings {
                    count: u32::try_from(value["count"].as_u64().unwrap()).unwrap() + 1,
                })
            })),
            backend,
        )
        .unwrap();
        assert_eq!(v2.load().unwrap(), Some(Settings { count: 8 }));
        assert_eq!(v2.load().unwrap(), Some(Settings { count: 8 }));
    }

    #[test]
    fn arbitrary_keys_cannot_escape_file_root() {
        let directory = tempfile::tempdir().unwrap();
        let storage = FileStorage::open(directory.path()).unwrap();
        storage.set_raw("../../outside", b"safe").unwrap();
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        assert!(!directory.path().parent().unwrap().join("outside").exists());
    }
}
