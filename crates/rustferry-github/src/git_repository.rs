//! Private bare Git repository layout for isolated temporary-ref publication.

#[cfg(windows)]
mod windows {
    use std::{
        error::Error,
        ffi::OsString,
        fmt,
        fs::{self, File},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::{
            fs::{MetadataExt as _, OpenOptionsExt as _},
            io::AsHandle as _,
        },
        path::{Component, Path, PathBuf},
    };

    use rustferry_core::{DirectoryFilesystemIdentity, RetainedDirectoryIdentity};
    use same_file::Handle as FileIdentityHandle;
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    use crate::git_process::{
        GitNetworkPolicy, GitProcessContext, GitProcessPolicyError, GitProcessSpec,
        WindowsGitToolchain, external_path,
    };

    const BARE_DIRECTORY_NAME: &str = "repository.git";
    const HOME_DIRECTORY_NAME: &str = "home";
    const XDG_DIRECTORY_NAME: &str = "xdg";
    const TEMP_DIRECTORY_NAME: &str = "tmp";
    const TEMPLATE_DIRECTORY_NAME: &str = "empty-template";
    const SSH_DIRECTORY_NAME: &str = ".ssh";
    const MAX_CONTROL_FILE_BYTES: usize = 64 * 1024;
    const UNBORN_HEAD: &[u8] = b"ref: refs/heads/rustferry-unborn\n";

    /// Pinned GitHub.com host keys published by GitHub for noninteractive SSH verification.
    pub const GITHUB_KNOWN_HOSTS_V1: &str = concat!(
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=\n",
        "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=\n",
    );

    const SSH_CONFIG_V1_TEMPLATE: &str = concat!(
        "Host *\n",
        "    BatchMode yes\n",
        "    StrictHostKeyChecking yes\n",
        "    UserKnownHostsFile @RUSTFERRY_KNOWN_HOSTS@\n",
        "    GlobalKnownHostsFile none\n",
        "    HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256\n",
        "    PreferredAuthentications publickey\n",
        "    IdentityFile none\n",
        "    PasswordAuthentication no\n",
        "    KbdInteractiveAuthentication no\n",
        "    ProxyCommand none\n",
        "    ProxyJump none\n",
        "    PermitLocalCommand no\n",
        "    ForwardAgent no\n",
        "    ClearAllForwardings yes\n",
        "    RequestTTY no\n",
        "    AddKeysToAgent no\n",
        "    UpdateHostKeys no\n",
        "    VerifyHostKeyDNS no\n",
        "    CheckHostIP no\n",
        "    CanonicalizeHostname no\n",
        "    ConnectionAttempts 1\n",
        "    ConnectTimeout 30\n",
        "    LogLevel ERROR\n",
        "Host github.com\n",
        "    HostName github.com\n",
        "    HostKeyAlias github.com\n",
        "    User git\n",
        "    Port 22\n",
    );

    fn ssh_config_v1(known_hosts: &Path) -> Result<Vec<u8>, PrivateGitRepositoryError> {
        let external = external_path(known_hosts);
        let value = external
            .to_str()
            .ok_or(PrivateGitRepositoryError::InvalidControlFile)?
            .replace('\\', "/");
        if !known_hosts.is_absolute()
            || value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'%' | b'$' | b'"'))
        {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        let rendered =
            SSH_CONFIG_V1_TEMPLATE.replace("@RUSTFERRY_KNOWN_HOSTS@", &format!("\"{value}\""));
        if rendered.len() > MAX_CONTROL_FILE_BYTES {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        Ok(rendered.into_bytes())
    }

    /// Canonical paths inside one private Git isolation root.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PrivateGitRepositoryPaths {
        root: PathBuf,
        bare: PathBuf,
        home: PathBuf,
        xdg: PathBuf,
        temp: PathBuf,
        template: PathBuf,
        ssh: PathBuf,
        ssh_config: PathBuf,
        known_hosts: PathBuf,
    }

    impl PrivateGitRepositoryPaths {
        fn new(root: PathBuf) -> Self {
            let bare = root.join(BARE_DIRECTORY_NAME);
            let home = root.join(HOME_DIRECTORY_NAME);
            let xdg = root.join(XDG_DIRECTORY_NAME);
            let temp = root.join(TEMP_DIRECTORY_NAME);
            let template = root.join(TEMPLATE_DIRECTORY_NAME);
            let ssh = home.join(SSH_DIRECTORY_NAME);
            let ssh_config = ssh.join("config");
            let known_hosts = ssh.join("known_hosts");
            Self {
                root,
                bare,
                home,
                xdg,
                temp,
                template,
                ssh,
                ssh_config,
                known_hosts,
            }
        }

        /// Private isolation root.
        pub fn root(&self) -> &Path {
            &self.root
        }

        /// Private bare repository directory.
        pub fn bare(&self) -> &Path {
            &self.bare
        }

        /// Empty private home used for Git, GCM, and OpenSSH.
        pub fn home(&self) -> &Path {
            &self.home
        }

        /// Private XDG configuration root.
        pub fn xdg(&self) -> &Path {
            &self.xdg
        }

        /// Private process temporary directory.
        pub fn temp(&self) -> &Path {
            &self.temp
        }

        /// Empty template directory used only by `git init`.
        pub fn template(&self) -> &Path {
            &self.template
        }

        /// Pinned private OpenSSH configuration file.
        pub fn ssh_config(&self) -> &Path {
            &self.ssh_config
        }

        /// Pinned private GitHub known-hosts file.
        pub fn known_hosts(&self) -> &Path {
            &self.known_hosts
        }
    }

    struct PrivateDirectoryGuard {
        path: PathBuf,
        identity: DirectoryFilesystemIdentity,
        retained: RetainedDirectoryIdentity,
        private_handle: Option<File>,
    }

    impl PrivateDirectoryGuard {
        fn open(path: &Path) -> Result<Self, PrivateGitRepositoryError> {
            let path = canonical_private_directory(path)?;
            let private_handle =
                rustferry_core::windows_private_directory::open_private_directory_read_guard(&path)
                    .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
            let retained = RetainedDirectoryIdentity::open(&path)
                .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
            let identity = retained.identity().clone();
            Ok(Self {
                path,
                identity,
                retained,
                private_handle: Some(private_handle),
            })
        }

        fn open_git_generated(path: &Path) -> Result<Self, PrivateGitRepositoryError> {
            let path = canonical_directory(path)?;
            let retained = RetainedDirectoryIdentity::open(&path)
                .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
            let identity = retained.identity().clone();
            Ok(Self {
                path,
                identity,
                retained,
                private_handle: None,
            })
        }

        fn verify(&self) -> Result<(), PrivateGitRepositoryError> {
            if let Some(private_handle) = &self.private_handle {
                rustferry_core::windows_private_directory::verify_private_directory_handle(
                    private_handle.as_handle(),
                )
                .map_err(|_| PrivateGitRepositoryError::DirectoryIdentityChanged)?;
            }
            self.retained
                .verify_path(&self.path)
                .map_err(|_| PrivateGitRepositoryError::DirectoryIdentityChanged)?;
            if self.retained.identity() != &self.identity {
                return Err(PrivateGitRepositoryError::DirectoryIdentityChanged);
            }
            Ok(())
        }
    }

    impl fmt::Debug for PrivateDirectoryGuard {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("PrivateDirectoryGuard")
                .field("name", &self.path.file_name())
                .field("identity", &self.identity)
                .finish_non_exhaustive()
        }
    }

    struct ExactPrivateFileGuard {
        path: PathBuf,
        identity: FileIdentityHandle,
        sha256: String,
        expected: Vec<u8>,
        file: File,
        require_private_acl: bool,
    }

    impl ExactPrivateFileGuard {
        fn open(path: &Path, expected: &[u8]) -> Result<Self, PrivateGitRepositoryError> {
            if expected.len() > MAX_CONTROL_FILE_BYTES {
                return Err(PrivateGitRepositoryError::InvalidControlFile);
            }
            let file = rustferry_core::windows_private_directory::open_private_file(path)
                .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
            let identity = FileIdentityHandle::from_file(
                file.try_clone()
                    .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?,
            )
            .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
            if FileIdentityHandle::from_path(path)
                .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?
                != identity
            {
                return Err(PrivateGitRepositoryError::ControlFileIdentityChanged);
            }
            let actual = read_bounded_file(&file)?;
            if actual != expected {
                return Err(PrivateGitRepositoryError::InvalidControlFile);
            }
            Ok(Self {
                path: path.to_owned(),
                identity,
                sha256: hex::encode(Sha256::digest(expected)),
                expected: expected.to_vec(),
                file,
                require_private_acl: true,
            })
        }

        fn open_git_generated(
            path: &Path,
            expected: &[u8],
        ) -> Result<Self, PrivateGitRepositoryError> {
            if expected.len() > MAX_CONTROL_FILE_BYTES {
                return Err(PrivateGitRepositoryError::InvalidControlFile);
            }
            let file = open_retained_generated_file(path)?;
            let identity = FileIdentityHandle::from_file(
                file.try_clone()
                    .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?,
            )
            .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
            if FileIdentityHandle::from_path(path)
                .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?
                != identity
            {
                return Err(PrivateGitRepositoryError::ControlFileIdentityChanged);
            }
            let actual = read_bounded_file(&file)?;
            if actual != expected {
                return Err(PrivateGitRepositoryError::InvalidControlFile);
            }
            Ok(Self {
                path: path.to_owned(),
                identity,
                sha256: hex::encode(Sha256::digest(expected)),
                expected: expected.to_vec(),
                file,
                require_private_acl: false,
            })
        }

        fn verify(&self) -> Result<(), PrivateGitRepositoryError> {
            if self.require_private_acl {
                rustferry_core::windows_private_directory::verify_private_file_handle(
                    self.file.as_handle(),
                )
                .map_err(|_| PrivateGitRepositoryError::ControlFileIdentityChanged)?;
            }
            if FileIdentityHandle::from_path(&self.path)
                .map_err(|_| PrivateGitRepositoryError::ControlFileIdentityChanged)?
                != self.identity
                || read_bounded_file(&self.file)? != self.expected
                || hex::encode(Sha256::digest(&self.expected)) != self.sha256
            {
                return Err(PrivateGitRepositoryError::ControlFileIdentityChanged);
            }
            Ok(())
        }
    }

    impl fmt::Debug for ExactPrivateFileGuard {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ExactPrivateFileGuard")
                .field("name", &self.path.file_name())
                .field("sha256", &self.sha256)
                .finish_non_exhaustive()
        }
    }

    /// Fresh or already initialized private layout retained across `git init`.
    #[derive(Debug)]
    pub struct PrivateGitRepositoryPreparation {
        paths: PrivateGitRepositoryPaths,
        directories: Vec<PrivateDirectoryGuard>,
        ssh_config: ExactPrivateFileGuard,
        known_hosts: ExactPrivateFileGuard,
        needs_initialization: bool,
    }

    impl PrivateGitRepositoryPreparation {
        /// Create or reopen fixed private directories and pinned SSH policy files.
        ///
        /// The isolation root must already satisfy `RustFerry`'s strict Windows private-directory
        /// policy. A partially initialized bare repository fails closed and is never reinitialized.
        ///
        /// # Errors
        ///
        /// Rejects unsafe ACLs, reparse points, path replacement, unexpected files, or partial Git
        /// initialization state.
        pub fn prepare(root: impl AsRef<Path>) -> Result<Self, PrivateGitRepositoryError> {
            let root = canonical_private_directory(root.as_ref())?;
            let paths = PrivateGitRepositoryPaths::new(root);
            let mut directories = vec![PrivateDirectoryGuard::open(&paths.root)?];
            for directory in [
                &paths.bare,
                &paths.home,
                &paths.xdg,
                &paths.temp,
                &paths.template,
                &paths.ssh,
            ] {
                create_or_open_private_directory(directory)?;
                directories.push(PrivateDirectoryGuard::open(directory)?);
            }
            ensure_directory_empty(&paths.template)?;
            let expected_ssh_config = ssh_config_v1(&paths.known_hosts)?;
            ensure_exact_private_file(&paths.ssh_config, &expected_ssh_config)?;
            ensure_exact_private_file(&paths.known_hosts, GITHUB_KNOWN_HOSTS_V1.as_bytes())?;
            let ssh_config = ExactPrivateFileGuard::open(&paths.ssh_config, &expected_ssh_config)?;
            let known_hosts =
                ExactPrivateFileGuard::open(&paths.known_hosts, GITHUB_KNOWN_HOSTS_V1.as_bytes())?;

            let config_exists = paths.bare.join("config").try_exists().unwrap_or(false);
            let head_exists = paths.bare.join("HEAD").try_exists().unwrap_or(false);
            let needs_initialization = match (config_exists, head_exists) {
                (false, false) => {
                    ensure_directory_empty(&paths.bare)?;
                    true
                }
                (true, true) => false,
                (true, false) | (false, true) => {
                    return Err(PrivateGitRepositoryError::PartialInitialization);
                }
            };
            let preparation = Self {
                paths,
                directories,
                ssh_config,
                known_hosts,
                needs_initialization,
            };
            preparation.verify_preparation()?;
            Ok(preparation)
        }

        /// Whether the caller must execute [`Self::initialization_spec`] before sealing.
        pub const fn needs_initialization(&self) -> bool {
            self.needs_initialization
        }

        /// Exact offline `git init --bare` process specification for this retained layout.
        ///
        /// # Errors
        ///
        /// Rejects an already initialized repository or changed tool/directory identity.
        pub fn initialization_spec<'a>(
            &self,
            toolchain: &'a WindowsGitToolchain,
        ) -> Result<GitProcessSpec<'a>, PrivateGitRepositoryError> {
            if !self.needs_initialization {
                return Err(PrivateGitRepositoryError::AlreadyInitialized);
            }
            self.verify_preparation()?;
            let context = GitProcessContext::new(
                &self.paths.root,
                None,
                &self.paths.home,
                &self.paths.xdg,
                &self.paths.temp,
            )?;
            toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::Offline,
                    [
                        OsString::from("-c"),
                        OsString::from("init.defaultBranch=rustferry-unborn"),
                        OsString::from("init"),
                        OsString::from("--bare"),
                        OsString::from(format!(
                            "--template={}",
                            self.paths.template.to_string_lossy()
                        )),
                        self.paths.bare.as_os_str().to_owned(),
                    ],
                )
                .map_err(Into::into)
        }

        /// Validate and retain an initialized bare repository.
        ///
        /// # Errors
        ///
        /// Rejects missing/malformed Git state, unsafe inherited ACLs, unexpected config keys,
        /// alternates, path replacement, or any changed pinned policy file.
        pub fn finish(self) -> Result<PrivateBareGitRepository, PrivateGitRepositoryError> {
            self.verify_preparation()?;
            let config_path = self.paths.bare.join("config");
            let head_path = self.paths.bare.join("HEAD");
            let config_bytes = read_private_control_path(&config_path)?;
            validate_generated_git_config(&config_bytes)?;
            let config = ExactPrivateFileGuard::open_git_generated(&config_path, &config_bytes)?;
            let head = ExactPrivateFileGuard::open_git_generated(&head_path, UNBORN_HEAD)?;

            let mut directories = self.directories;
            for directory in [
                self.paths.bare.join("objects"),
                self.paths.bare.join("objects/info"),
                self.paths.bare.join("objects/pack"),
                self.paths.bare.join("refs"),
                self.paths.bare.join("refs/heads"),
                self.paths.bare.join("refs/tags"),
            ] {
                directories.push(PrivateDirectoryGuard::open_git_generated(&directory)?);
            }
            let alternates_path = self.paths.bare.join("objects/info/alternates");
            let http_alternates_path = self.paths.bare.join("objects/info/http-alternates");
            ensure_exact_private_file(&alternates_path, b"")?;
            ensure_exact_private_file(&http_alternates_path, b"")?;
            let alternates = ExactPrivateFileGuard::open(&alternates_path, b"")?;
            let http_alternates = ExactPrivateFileGuard::open(&http_alternates_path, b"")?;
            let repository = PrivateBareGitRepository {
                paths: self.paths,
                directories,
                config,
                head,
                alternates,
                http_alternates,
                ssh_config: self.ssh_config,
                known_hosts: self.known_hosts,
            };
            repository.verify()?;
            Ok(repository)
        }

        fn verify_preparation(&self) -> Result<(), PrivateGitRepositoryError> {
            for directory in &self.directories {
                directory.verify()?;
            }
            self.ssh_config.verify()?;
            self.known_hosts.verify()?;
            ensure_directory_empty(&self.paths.template)
        }
    }

    /// Sealed private bare repository and policy files retained for publisher lifetime.
    #[derive(Debug)]
    pub struct PrivateBareGitRepository {
        paths: PrivateGitRepositoryPaths,
        directories: Vec<PrivateDirectoryGuard>,
        config: ExactPrivateFileGuard,
        head: ExactPrivateFileGuard,
        alternates: ExactPrivateFileGuard,
        http_alternates: ExactPrivateFileGuard,
        ssh_config: ExactPrivateFileGuard,
        known_hosts: ExactPrivateFileGuard,
    }

    impl PrivateBareGitRepository {
        /// Reopen an already initialized private repository without running Git.
        ///
        /// # Errors
        ///
        /// Rejects absent, partial, changed, or unsafe layouts.
        pub fn open(root: impl AsRef<Path>) -> Result<Self, PrivateGitRepositoryError> {
            let preparation = PrivateGitRepositoryPreparation::prepare(root)?;
            if preparation.needs_initialization() {
                return Err(PrivateGitRepositoryError::InitializationRequired);
            }
            preparation.finish()
        }

        /// Canonical retained layout paths.
        pub const fn paths(&self) -> &PrivateGitRepositoryPaths {
            &self.paths
        }

        /// Process context that binds every Git command to this bare object database.
        ///
        /// # Errors
        ///
        /// Rejects any path that changed after sealing.
        pub fn process_context(&self) -> Result<GitProcessContext, PrivateGitRepositoryError> {
            self.verify()?;
            GitProcessContext::new(
                &self.paths.root,
                Some(&self.paths.bare),
                &self.paths.home,
                &self.paths.xdg,
                &self.paths.temp,
            )
            .map_err(Into::into)
        }

        /// Revalidate all retained directories and exact policy/control files.
        ///
        /// # Errors
        ///
        /// Fails closed on identity, byte, ACL, template, config, or alternates drift.
        pub fn verify(&self) -> Result<(), PrivateGitRepositoryError> {
            for directory in &self.directories {
                directory.verify()?;
            }
            for file in [
                &self.config,
                &self.head,
                &self.alternates,
                &self.http_alternates,
                &self.ssh_config,
                &self.known_hosts,
            ] {
                file.verify()?;
            }
            validate_generated_git_config(&self.config.expected)?;
            ensure_directory_empty(&self.paths.template)
        }
    }

    /// Stable, path-free private Git repository failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PrivateGitRepositoryError {
        /// Root or child directory has an invalid path, type, ACL, or reparse state.
        UnsafeDirectory,
        /// Retained directory path no longer identifies the same object.
        DirectoryIdentityChanged,
        /// A fixed control file has an invalid ACL, type, or reparse state.
        UnsafeControlFile,
        /// Fixed control file contents are malformed or differ from policy.
        InvalidControlFile,
        /// Retained control file path or contents changed.
        ControlFileIdentityChanged,
        /// Directory expected to be empty contains unexpected state.
        UnexpectedDirectoryEntry,
        /// Bare repository contains only part of Git's initialization state.
        PartialInitialization,
        /// Initialization was requested for an existing repository.
        AlreadyInitialized,
        /// Existing-only open found an uninitialized repository.
        InitializationRequired,
        /// Git-generated local config contains an unexpected or unsafe key/value.
        InvalidGitConfig,
        /// Fixed process-policy construction failed.
        ProcessPolicy(GitProcessPolicyError),
        /// Bounded control-file I/O failed.
        ControlFileIo,
    }

    impl fmt::Display for PrivateGitRepositoryError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnsafeDirectory => formatter.write_str("private Git directory is unsafe"),
                Self::DirectoryIdentityChanged => {
                    formatter.write_str("private Git directory identity changed")
                }
                Self::UnsafeControlFile => {
                    formatter.write_str("private Git control file is unsafe")
                }
                Self::InvalidControlFile => {
                    formatter.write_str("private Git control file is invalid")
                }
                Self::ControlFileIdentityChanged => {
                    formatter.write_str("private Git control file identity changed")
                }
                Self::UnexpectedDirectoryEntry => {
                    formatter.write_str("private Git directory contains unexpected state")
                }
                Self::PartialInitialization => {
                    formatter.write_str("private bare Git initialization is incomplete")
                }
                Self::AlreadyInitialized => {
                    formatter.write_str("private bare Git repository is already initialized")
                }
                Self::InitializationRequired => {
                    formatter.write_str("private bare Git repository requires initialization")
                }
                Self::InvalidGitConfig => formatter.write_str("private bare Git config is invalid"),
                Self::ProcessPolicy(error) => {
                    write!(formatter, "Git process policy failed: {error}")
                }
                Self::ControlFileIo => formatter.write_str("private Git control-file I/O failed"),
            }
        }
    }

    impl Error for PrivateGitRepositoryError {}

    impl From<GitProcessPolicyError> for PrivateGitRepositoryError {
        fn from(value: GitProcessPolicyError) -> Self {
            Self::ProcessPolicy(value)
        }
    }

    fn create_or_open_private_directory(path: &Path) -> Result<(), PrivateGitRepositoryError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                rustferry_core::windows_private_directory::create_private_directory(path)
                    .map(drop)
                    .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
            }
            Ok(_) | Err(_) => return Err(PrivateGitRepositoryError::UnsafeDirectory),
        }
        PrivateDirectoryGuard::open(path).map(drop)
    }

    fn canonical_private_directory(path: &Path) -> Result<PathBuf, PrivateGitRepositoryError> {
        let canonical = canonical_directory(path)?;
        rustferry_core::windows_private_directory::open_private_directory_read_guard(&canonical)
            .map(drop)
            .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
        Ok(canonical)
    }

    fn canonical_directory(path: &Path) -> Result<PathBuf, PrivateGitRepositoryError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(PrivateGitRepositoryError::UnsafeDirectory);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PrivateGitRepositoryError::UnsafeDirectory);
        }
        fs::canonicalize(path).map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)
    }

    fn ensure_directory_empty(path: &Path) -> Result<(), PrivateGitRepositoryError> {
        let mut entries =
            fs::read_dir(path).map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
        if entries
            .next()
            .transpose()
            .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?
            .is_some()
        {
            return Err(PrivateGitRepositoryError::UnexpectedDirectoryEntry);
        }
        Ok(())
    }

    fn ensure_exact_private_file(
        path: &Path,
        expected: &[u8],
    ) -> Result<(), PrivateGitRepositoryError> {
        match fs::symlink_metadata(path) {
            Ok(_) => ExactPrivateFileGuard::open(path, expected).map(drop),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut file = rustferry_core::windows_private_directory::create_private_file(path)
                    .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
                file.write_all(expected)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
                drop(file);
                ExactPrivateFileGuard::open(path, expected).map(drop)
            }
            Err(_) => Err(PrivateGitRepositoryError::UnsafeControlFile),
        }
    }

    fn read_private_control_path(path: &Path) -> Result<Vec<u8>, PrivateGitRepositoryError> {
        let file = open_retained_generated_file(path)?;
        read_bounded_file(&file)
    }

    fn open_retained_generated_file(path: &Path) -> Result<File, PrivateGitRepositoryError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(PrivateGitRepositoryError::UnsafeControlFile);
        }
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options
            .open(path)
            .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)
    }

    fn read_bounded_file(file: &File) -> Result<Vec<u8>, PrivateGitRepositoryError> {
        let length = usize::try_from(
            file.metadata()
                .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?
                .len(),
        )
        .map_err(|_| PrivateGitRepositoryError::InvalidControlFile)?;
        if length > MAX_CONTROL_FILE_BYTES {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        let mut reader = file
            .try_clone()
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
        let mut bytes = Vec::with_capacity(length);
        reader
            .take(
                u64::try_from(MAX_CONTROL_FILE_BYTES)
                    .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?
                    + 1,
            )
            .read_to_end(&mut bytes)
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
        if bytes.len() != length || bytes.len() > MAX_CONTROL_FILE_BYTES {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        Ok(bytes)
    }

    fn validate_generated_git_config(bytes: &[u8]) -> Result<(), PrivateGitRepositoryError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| PrivateGitRepositoryError::InvalidGitConfig)?;
        if text.is_empty()
            || text.len() > MAX_CONTROL_FILE_BYTES
            || text.bytes().any(|byte| {
                byte == 0
                    || byte == b'\r'
                    || byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t')
            })
        {
            return Err(PrivateGitRepositoryError::InvalidGitConfig);
        }
        let mut in_core = false;
        let mut repository_format = false;
        let mut bare = false;
        let mut seen = std::collections::BTreeSet::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "[core]" {
                if in_core {
                    return Err(PrivateGitRepositoryError::InvalidGitConfig);
                }
                in_core = true;
                continue;
            }
            if !in_core || trimmed.starts_with('[') || trimmed.starts_with(['#', ';']) {
                return Err(PrivateGitRepositoryError::InvalidGitConfig);
            }
            let (key, value) = trimmed
                .split_once('=')
                .ok_or(PrivateGitRepositoryError::InvalidGitConfig)?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                return Err(PrivateGitRepositoryError::InvalidGitConfig);
            }
            match (key.as_str(), value.as_str()) {
                ("repositoryformatversion", "0") => repository_format = true,
                ("bare", "true") => bare = true,
                ("filemode" | "symlinks" | "ignorecase", "true" | "false")
                | ("logallrefupdates", "false") => {}
                _ => return Err(PrivateGitRepositoryError::InvalidGitConfig),
            }
        }
        if in_core && repository_format && bare {
            Ok(())
        } else {
            Err(PrivateGitRepositoryError::InvalidGitConfig)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::process::Stdio;

        use super::*;

        fn installed_git() -> Option<PathBuf> {
            let path = PathBuf::from(r"C:\Program Files\Git\cmd\git.exe");
            path.is_file().then_some(path)
        }

        fn private_root(temporary: &tempfile::TempDir) -> PathBuf {
            let root = temporary.path().join("isolation");
            rustferry_core::windows_private_directory::create_private_directory(&root)
                .expect("private isolation root");
            root
        }

        fn initialize(toolchain: &WindowsGitToolchain, root: &Path) -> PrivateBareGitRepository {
            let preparation =
                PrivateGitRepositoryPreparation::prepare(root).expect("private layout");
            assert!(preparation.needs_initialization());
            let spec = preparation
                .initialization_spec(toolchain)
                .expect("initialization spec");
            let status = spec
                .command()
                .expect("initialization command")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("run git init");
            assert!(status.success());
            preparation.finish().expect("sealed bare repository")
        }

        #[test]
        fn private_bare_repository_is_offline_and_ignores_ambient_config() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("toolchain");
            let temporary = tempfile::tempdir().expect("fixture");
            let repository = initialize(&toolchain, &private_root(&temporary));
            repository.verify().expect("private repository");
            let context = repository.process_context().expect("process context");
            let spec = toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::Offline,
                    ["config", "--local", "--no-includes", "--list"],
                )
                .expect("config query");
            let output = spec
                .command()
                .expect("config command")
                .output()
                .expect("config output");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = String::from_utf8(output.stdout).expect("UTF-8 config");
            assert!(output.contains("core.bare=true"));
            for forbidden in [
                "credential.helper",
                "core.sshcommand",
                "url.",
                "http.proxy",
                "http.extraheader",
                "include.path",
            ] {
                assert!(!output.to_ascii_lowercase().contains(forbidden));
            }
            let reopened = PrivateBareGitRepository::open(repository.paths().root())
                .expect("reopened repository");
            reopened.verify().expect("stable reopened repository");
        }

        #[test]
        fn managed_ssh_config_resolves_exact_private_known_hosts() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("toolchain");
            let temporary = tempfile::tempdir().expect("fixture");
            let repository = initialize(&toolchain, &private_root(&temporary));
            let paths = repository.paths();
            let config = String::from_utf8(fs::read(paths.ssh_config()).expect("SSH config"))
                .expect("UTF-8 SSH config");
            assert!(!config.contains('~'));
            assert!(!config.contains(r"\\?\"));
            assert!(!config.contains("//?/"));

            let ambient_home = temporary.path().join("ambient-home");
            let ambient_profile = temporary.path().join("ambient-profile");
            fs::create_dir(&ambient_home).expect("ambient HOME fixture");
            fs::create_dir(&ambient_profile).expect("ambient profile fixture");
            let system_root = external_path(toolchain.system_root());
            let command_interpreter =
                external_path(&toolchain.system_root().join("System32").join("cmd.exe"));
            let ambient_xdg = temporary.path().join("ambient-xdg");
            fs::create_dir(&ambient_xdg).expect("ambient XDG fixture");
            let output = std::process::Command::new(toolchain.ssh().path())
                .args(["-G", "-F"])
                .arg(external_path(paths.ssh_config()))
                .arg("github.com")
                .env_clear()
                .env("COMSPEC", command_interpreter)
                .env("HOME", &ambient_home)
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .env("PATH", toolchain.fixed_path())
                .env("PATHEXT", ".COM;.EXE;.BAT;.CMD")
                .env("SystemRoot", &system_root)
                .env("TEMP", temporary.path())
                .env("TMP", temporary.path())
                .env("USERPROFILE", &ambient_profile)
                .env("WINDIR", system_root)
                .env("XDG_CONFIG_HOME", ambient_xdg)
                .env("PROGRAMDATA", &ambient_home)
                .output()
                .expect("ssh -G");
            assert!(
                output.status.success(),
                "status={:?}; {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
            let resolved = String::from_utf8(output.stdout).expect("UTF-8 ssh -G output");
            let values = resolved
                .lines()
                .filter_map(|line| line.split_once(' '))
                .filter(|(key, _)| key.eq_ignore_ascii_case("userknownhostsfile"))
                .map(|(_, value)| value.trim().replace('\\', "/"))
                .collect::<Vec<_>>();
            assert_eq!(values.len(), 1);
            let expected = external_path(paths.known_hosts())
                .to_string_lossy()
                .replace('\\', "/");
            assert!(values[0].eq_ignore_ascii_case(&expected));
            assert!(!values[0].contains("//?/"));
        }

        #[test]
        fn malicious_local_config_is_rejected_before_use() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("toolchain");
            let temporary = tempfile::tempdir().expect("fixture");
            let root = private_root(&temporary);
            let preparation = PrivateGitRepositoryPreparation::prepare(&root).expect("preparation");
            let spec = preparation
                .initialization_spec(&toolchain)
                .expect("initialization spec");
            assert!(
                spec.command()
                    .expect("command")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("git init")
                    .success()
            );
            fs::OpenOptions::new()
                .append(true)
                .open(root.join(BARE_DIRECTORY_NAME).join("config"))
                .and_then(|mut file| {
                    file.write_all(b"[credential]\nhelper = !cmd /c echo compromised > canary\n")
                })
                .expect("inject malicious local config fixture");
            assert!(matches!(
                preparation.finish(),
                Err(PrivateGitRepositoryError::InvalidGitConfig)
            ));
            assert!(!root.join("canary").exists());
        }

        #[test]
        fn sealed_control_files_block_replacement() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("toolchain");
            let temporary = tempfile::tempdir().expect("fixture");
            let repository = initialize(&toolchain, &private_root(&temporary));
            let config = repository.paths().bare().join("config");
            let displaced = repository.paths().bare().join("config-old");
            assert!(fs::rename(&config, displaced).is_err());
            assert!(fs::OpenOptions::new().write(true).open(config).is_err());
            repository.verify().expect("stable repository");
        }
    }
}

#[cfg(windows)]
pub use windows::{
    GITHUB_KNOWN_HOSTS_V1, PrivateBareGitRepository, PrivateGitRepositoryError,
    PrivateGitRepositoryPaths, PrivateGitRepositoryPreparation,
};

#[cfg(unix)]
#[allow(missing_docs, clippy::missing_errors_doc)]
mod unix {
    use std::{
        collections::BTreeSet,
        error::Error,
        ffi::OsString,
        fmt,
        fs::{self, File},
        io::{Read, Seek, SeekFrom, Write},
        os::unix::fs::{
            DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
        },
        path::{Component, Path, PathBuf},
    };

    use crate::git_process::{
        GitNetworkPolicy, GitProcessContext, GitProcessPolicyError, GitProcessSpec,
        UnixGitToolchain,
    };
    use rustferry_core::{DirectoryFilesystemIdentity, verify_directory_identity};

    const BARE_DIRECTORY_NAME: &str = "repository.git";
    const HOME_DIRECTORY_NAME: &str = "home";
    const XDG_DIRECTORY_NAME: &str = "xdg";
    const TEMP_DIRECTORY_NAME: &str = "tmp";
    const TEMPLATE_DIRECTORY_NAME: &str = "empty-template";
    const SSH_DIRECTORY_NAME: &str = ".ssh";
    const MAX_CONTROL_FILE_BYTES: usize = 64 * 1024;
    const UNBORN_HEAD: &[u8] = b"ref: refs/heads/rustferry-unborn\n";

    pub const GITHUB_KNOWN_HOSTS_V1: &str = concat!(
        "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
        "github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=\n",
        "github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=\n",
    );

    const SSH_CONFIG_V1_TEMPLATE: &str = concat!(
        "Host *\n",
        "    BatchMode yes\n",
        "    StrictHostKeyChecking yes\n",
        "    UserKnownHostsFile @RUSTFERRY_KNOWN_HOSTS@\n",
        "    GlobalKnownHostsFile none\n",
        "    HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256\n",
        "    PreferredAuthentications publickey\n",
        "    IdentityFile none\n",
        "    PasswordAuthentication no\n",
        "    KbdInteractiveAuthentication no\n",
        "    ProxyCommand none\n",
        "    ProxyJump none\n",
        "    PermitLocalCommand no\n",
        "    ForwardAgent no\n",
        "    ClearAllForwardings yes\n",
        "    RequestTTY no\n",
        "    AddKeysToAgent no\n",
        "    UpdateHostKeys no\n",
        "    VerifyHostKeyDNS no\n",
        "    CheckHostIP no\n",
        "    CanonicalizeHostname no\n",
        "    ConnectionAttempts 1\n",
        "    ConnectTimeout 30\n",
        "    LogLevel ERROR\n",
        "Host github.com\n",
        "    HostName github.com\n",
        "    HostKeyAlias github.com\n",
        "    User git\n",
        "    Port 22\n",
    );

    fn ssh_config_v1(known_hosts: &Path) -> Result<Vec<u8>, PrivateGitRepositoryError> {
        let value = known_hosts
            .to_str()
            .ok_or(PrivateGitRepositoryError::InvalidControlFile)?;
        if !known_hosts.is_absolute()
            || value.is_empty()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'%' | b'$' | b'"' | b'\\'))
        {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        let rendered =
            SSH_CONFIG_V1_TEMPLATE.replace("@RUSTFERRY_KNOWN_HOSTS@", &format!("\"{value}\""));
        if rendered.len() > MAX_CONTROL_FILE_BYTES {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        Ok(rendered.into_bytes())
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct PrivateGitRepositoryPaths {
        root: PathBuf,
        bare: PathBuf,
        home: PathBuf,
        xdg: PathBuf,
        temp: PathBuf,
        template: PathBuf,
        ssh: PathBuf,
        ssh_config: PathBuf,
        known_hosts: PathBuf,
    }

    impl PrivateGitRepositoryPaths {
        fn new(root: PathBuf) -> Self {
            let bare = root.join(BARE_DIRECTORY_NAME);
            let home = root.join(HOME_DIRECTORY_NAME);
            let xdg = root.join(XDG_DIRECTORY_NAME);
            let temp = root.join(TEMP_DIRECTORY_NAME);
            let template = root.join(TEMPLATE_DIRECTORY_NAME);
            let ssh = home.join(SSH_DIRECTORY_NAME);
            let ssh_config = ssh.join("config");
            let known_hosts = ssh.join("known_hosts");
            Self {
                root,
                bare,
                home,
                xdg,
                temp,
                template,
                ssh,
                ssh_config,
                known_hosts,
            }
        }

        pub fn root(&self) -> &Path {
            &self.root
        }

        pub fn bare(&self) -> &Path {
            &self.bare
        }

        pub fn home(&self) -> &Path {
            &self.home
        }

        pub fn xdg(&self) -> &Path {
            &self.xdg
        }

        pub fn temp(&self) -> &Path {
            &self.temp
        }

        pub fn template(&self) -> &Path {
            &self.template
        }

        pub fn ssh_config(&self) -> &Path {
            &self.ssh_config
        }

        pub fn known_hosts(&self) -> &Path {
            &self.known_hosts
        }
    }

    #[derive(Debug)]
    struct ExactPrivateFile {
        path: PathBuf,
        device: u64,
        inode: u64,
        expected: Vec<u8>,
        _file: File,
    }

    impl ExactPrivateFile {
        fn open(path: &Path, expected: &[u8]) -> Result<Self, PrivateGitRepositoryError> {
            if expected.len() > MAX_CONTROL_FILE_BYTES {
                return Err(PrivateGitRepositoryError::InvalidControlFile);
            }
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != private_parent_owner(path)?
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err(PrivateGitRepositoryError::UnsafeControlFile);
            }
            let file =
                File::open(path).map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
            let opened = file
                .metadata()
                .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
            if opened.dev() != metadata.dev()
                || opened.ino() != metadata.ino()
                || read_bounded_file(&file)? != expected
            {
                return Err(PrivateGitRepositoryError::InvalidControlFile);
            }
            Ok(Self {
                path: path.to_owned(),
                device: opened.dev(),
                inode: opened.ino(),
                expected: expected.to_vec(),
                _file: file,
            })
        }

        fn verify(&self) -> Result<(), PrivateGitRepositoryError> {
            let metadata = fs::symlink_metadata(&self.path)
                .map_err(|_| PrivateGitRepositoryError::ControlFileIdentityChanged)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != private_parent_owner(&self.path)?
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.nlink() != 1
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
            {
                return Err(PrivateGitRepositoryError::ControlFileIdentityChanged);
            }
            let file = File::open(&self.path)
                .map_err(|_| PrivateGitRepositoryError::ControlFileIdentityChanged)?;
            if read_bounded_file(&file)? != self.expected {
                return Err(PrivateGitRepositoryError::ControlFileIdentityChanged);
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct PrivateGitRepositoryPreparation {
        paths: PrivateGitRepositoryPaths,
        root_identity: DirectoryFilesystemIdentity,
        owner_uid: u32,
        ssh_config: ExactPrivateFile,
        known_hosts: ExactPrivateFile,
        needs_initialization: bool,
    }

    impl PrivateGitRepositoryPreparation {
        pub fn prepare(root: impl AsRef<Path>) -> Result<Self, PrivateGitRepositoryError> {
            let root = canonical_private_directory(root.as_ref())?;
            let owner_uid = directory_owner(&root)?;
            let paths = PrivateGitRepositoryPaths::new(root.clone());
            for directory in [
                &paths.bare,
                &paths.home,
                &paths.xdg,
                &paths.temp,
                &paths.template,
                &paths.ssh,
            ] {
                create_or_open_private_directory(directory)?;
            }
            ensure_directory_empty(&paths.template)?;
            let expected_ssh_config = ssh_config_v1(&paths.known_hosts)?;
            ensure_exact_private_file(&paths.ssh_config, &expected_ssh_config)?;
            ensure_exact_private_file(&paths.known_hosts, GITHUB_KNOWN_HOSTS_V1.as_bytes())?;
            let ssh_config = ExactPrivateFile::open(&paths.ssh_config, &expected_ssh_config)?;
            let known_hosts =
                ExactPrivateFile::open(&paths.known_hosts, GITHUB_KNOWN_HOSTS_V1.as_bytes())?;
            let config_exists = paths.bare.join("config").try_exists().unwrap_or(false);
            let head_exists = paths.bare.join("HEAD").try_exists().unwrap_or(false);
            let needs_initialization = match (config_exists, head_exists) {
                (false, false) => {
                    ensure_directory_empty(&paths.bare)?;
                    true
                }
                (true, true) => false,
                _ => return Err(PrivateGitRepositoryError::PartialInitialization),
            };
            let preparation = Self {
                root_identity: DirectoryFilesystemIdentity::capture(&root)
                    .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?,
                owner_uid,
                paths,
                ssh_config,
                known_hosts,
                needs_initialization,
            };
            preparation.verify_preparation()?;
            Ok(preparation)
        }

        pub const fn needs_initialization(&self) -> bool {
            self.needs_initialization
        }

        pub fn initialization_spec<'a>(
            &self,
            toolchain: &'a UnixGitToolchain,
        ) -> Result<GitProcessSpec<'a>, PrivateGitRepositoryError> {
            if !self.needs_initialization {
                return Err(PrivateGitRepositoryError::AlreadyInitialized);
            }
            self.verify_preparation()?;
            let context = GitProcessContext::new(
                &self.paths.root,
                None,
                &self.paths.home,
                &self.paths.xdg,
                &self.paths.temp,
            )?;
            toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::Offline,
                    [
                        OsString::from("-c"),
                        OsString::from("init.defaultBranch=rustferry-unborn"),
                        OsString::from("init"),
                        OsString::from("--bare"),
                        OsString::from(format!(
                            "--template={}",
                            self.paths.template.to_string_lossy()
                        )),
                        self.paths.bare.as_os_str().to_owned(),
                    ],
                )
                .map_err(Into::into)
        }

        pub fn finish(self) -> Result<PrivateBareGitRepository, PrivateGitRepositoryError> {
            self.verify_preparation()?;
            let config_path = self.paths.bare.join("config");
            let head_path = self.paths.bare.join("HEAD");
            make_private_file(&config_path)?;
            make_private_file(&head_path)?;
            let config_bytes = read_control_path(&config_path)?;
            validate_generated_git_config(&config_bytes)?;
            let config = ExactPrivateFile::open(&config_path, &config_bytes)?;
            let head = ExactPrivateFile::open(&head_path, UNBORN_HEAD)?;
            let alternates_path = self.paths.bare.join("objects/info/alternates");
            let http_alternates_path = self.paths.bare.join("objects/info/http-alternates");
            ensure_exact_private_file(&alternates_path, b"")?;
            ensure_exact_private_file(&http_alternates_path, b"")?;
            let alternates = ExactPrivateFile::open(&alternates_path, b"")?;
            let http_alternates = ExactPrivateFile::open(&http_alternates_path, b"")?;
            let repository = PrivateBareGitRepository {
                paths: self.paths,
                root_identity: self.root_identity,
                owner_uid: self.owner_uid,
                config,
                head,
                alternates,
                http_alternates,
                ssh_config: self.ssh_config,
                known_hosts: self.known_hosts,
            };
            repository.verify()?;
            Ok(repository)
        }

        fn verify_preparation(&self) -> Result<(), PrivateGitRepositoryError> {
            verify_directory_identity(&self.paths.root, &self.root_identity)
                .map_err(|_| PrivateGitRepositoryError::DirectoryIdentityChanged)?;
            for directory in [
                &self.paths.root,
                &self.paths.bare,
                &self.paths.home,
                &self.paths.xdg,
                &self.paths.temp,
                &self.paths.template,
                &self.paths.ssh,
            ] {
                canonical_private_directory(directory)?;
                if directory_owner(directory)? != self.owner_uid {
                    return Err(PrivateGitRepositoryError::UnsafeDirectory);
                }
            }
            self.ssh_config.verify()?;
            self.known_hosts.verify()?;
            ensure_directory_empty(&self.paths.template)
        }
    }

    #[derive(Debug)]
    pub struct PrivateBareGitRepository {
        paths: PrivateGitRepositoryPaths,
        root_identity: DirectoryFilesystemIdentity,
        owner_uid: u32,
        config: ExactPrivateFile,
        head: ExactPrivateFile,
        alternates: ExactPrivateFile,
        http_alternates: ExactPrivateFile,
        ssh_config: ExactPrivateFile,
        known_hosts: ExactPrivateFile,
    }

    impl PrivateBareGitRepository {
        pub fn open(root: impl AsRef<Path>) -> Result<Self, PrivateGitRepositoryError> {
            let preparation = PrivateGitRepositoryPreparation::prepare(root)?;
            if preparation.needs_initialization() {
                return Err(PrivateGitRepositoryError::InitializationRequired);
            }
            preparation.finish()
        }

        pub const fn paths(&self) -> &PrivateGitRepositoryPaths {
            &self.paths
        }

        pub fn process_context(&self) -> Result<GitProcessContext, PrivateGitRepositoryError> {
            self.verify()?;
            GitProcessContext::new(
                &self.paths.root,
                Some(&self.paths.bare),
                &self.paths.home,
                &self.paths.xdg,
                &self.paths.temp,
            )
            .map_err(Into::into)
        }

        pub fn verify(&self) -> Result<(), PrivateGitRepositoryError> {
            verify_directory_identity(&self.paths.root, &self.root_identity)
                .map_err(|_| PrivateGitRepositoryError::DirectoryIdentityChanged)?;
            for directory in [
                &self.paths.root,
                &self.paths.bare,
                &self.paths.home,
                &self.paths.xdg,
                &self.paths.temp,
                &self.paths.template,
                &self.paths.ssh,
            ] {
                canonical_private_directory(directory)?;
                if directory_owner(directory)? != self.owner_uid {
                    return Err(PrivateGitRepositoryError::UnsafeDirectory);
                }
            }
            for file in [
                &self.config,
                &self.head,
                &self.alternates,
                &self.http_alternates,
                &self.ssh_config,
                &self.known_hosts,
            ] {
                file.verify()?;
            }
            validate_generated_git_config(&self.config.expected)?;
            ensure_directory_empty(&self.paths.template)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum PrivateGitRepositoryError {
        UnsafeDirectory,
        DirectoryIdentityChanged,
        UnsafeControlFile,
        InvalidControlFile,
        ControlFileIdentityChanged,
        UnexpectedDirectoryEntry,
        PartialInitialization,
        AlreadyInitialized,
        InitializationRequired,
        InvalidGitConfig,
        ProcessPolicy(GitProcessPolicyError),
        ControlFileIo,
    }

    impl fmt::Display for PrivateGitRepositoryError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::UnsafeDirectory => formatter.write_str("private Git directory is unsafe"),
                Self::DirectoryIdentityChanged => {
                    formatter.write_str("private Git directory identity changed")
                }
                Self::UnsafeControlFile => {
                    formatter.write_str("private Git control file is unsafe")
                }
                Self::InvalidControlFile => {
                    formatter.write_str("private Git control file is invalid")
                }
                Self::ControlFileIdentityChanged => {
                    formatter.write_str("private Git control file identity changed")
                }
                Self::UnexpectedDirectoryEntry => {
                    formatter.write_str("private Git directory contains unexpected state")
                }
                Self::PartialInitialization => {
                    formatter.write_str("private bare Git repository is partially initialized")
                }
                Self::AlreadyInitialized => {
                    formatter.write_str("private Git repository already exists")
                }
                Self::InitializationRequired => {
                    formatter.write_str("private Git repository needs initialization")
                }
                Self::InvalidGitConfig => formatter.write_str("private Git config is invalid"),
                Self::ProcessPolicy(error) => {
                    write!(formatter, "private Git process policy failed: {error}")
                }
                Self::ControlFileIo => formatter.write_str("private Git control-file I/O failed"),
            }
        }
    }

    impl Error for PrivateGitRepositoryError {}

    impl From<GitProcessPolicyError> for PrivateGitRepositoryError {
        fn from(value: GitProcessPolicyError) -> Self {
            Self::ProcessPolicy(value)
        }
    }

    fn create_or_open_private_directory(path: &Path) -> Result<(), PrivateGitRepositoryError> {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                canonical_private_directory(path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                builder
                    .create(path)
                    .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
                canonical_private_directory(path)?;
                sync_parent(path)?;
            }
            Err(_) => return Err(PrivateGitRepositoryError::UnsafeDirectory),
        }
        Ok(())
    }

    fn canonical_private_directory(path: &Path) -> Result<PathBuf, PrivateGitRepositoryError> {
        if !is_absolute_normal(path) {
            return Err(PrivateGitRepositoryError::UnsafeDirectory);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PrivateGitRepositoryError::UnsafeDirectory);
        }
        fs::canonicalize(path).map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)
    }

    fn ensure_directory_empty(path: &Path) -> Result<(), PrivateGitRepositoryError> {
        let mut entries =
            fs::read_dir(path).map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)?;
        if entries.next().is_some() {
            return Err(PrivateGitRepositoryError::UnexpectedDirectoryEntry);
        }
        Ok(())
    }

    fn ensure_exact_private_file(
        path: &Path,
        expected: &[u8],
    ) -> Result<(), PrivateGitRepositoryError> {
        match fs::symlink_metadata(path) {
            Ok(_) => ExactPrivateFile::open(path, expected).map(drop),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut options = fs::OpenOptions::new();
                let mut file = options
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
                file.write_all(expected)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
                sync_parent(path)?;
                ExactPrivateFile::open(path, expected).map(drop)
            }
            Err(_) => Err(PrivateGitRepositoryError::UnsafeControlFile),
        }
    }

    fn make_private_file(path: &Path) -> Result<(), PrivateGitRepositoryError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != private_parent_owner(path)?
            || metadata.nlink() != 1
        {
            return Err(PrivateGitRepositoryError::UnsafeControlFile);
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)
    }

    fn read_control_path(path: &Path) -> Result<Vec<u8>, PrivateGitRepositoryError> {
        let file = File::open(path).map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
        read_bounded_file(&file)
    }

    fn read_bounded_file(file: &File) -> Result<Vec<u8>, PrivateGitRepositoryError> {
        let length = usize::try_from(
            file.metadata()
                .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?
                .len(),
        )
        .map_err(|_| PrivateGitRepositoryError::InvalidControlFile)?;
        if length > MAX_CONTROL_FILE_BYTES {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        let mut reader = file
            .try_clone()
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
        let mut bytes = Vec::with_capacity(length);
        reader
            .take(MAX_CONTROL_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)?;
        if bytes.len() != length || bytes.len() > MAX_CONTROL_FILE_BYTES {
            return Err(PrivateGitRepositoryError::InvalidControlFile);
        }
        Ok(bytes)
    }

    fn validate_generated_git_config(bytes: &[u8]) -> Result<(), PrivateGitRepositoryError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| PrivateGitRepositoryError::InvalidGitConfig)?;
        if text.is_empty()
            || text.len() > MAX_CONTROL_FILE_BYTES
            || text.bytes().any(|byte| {
                byte == 0
                    || byte == b'\r'
                    || byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t')
            })
        {
            return Err(PrivateGitRepositoryError::InvalidGitConfig);
        }
        let mut in_core = false;
        let mut repository_format = false;
        let mut bare = false;
        let mut seen = BTreeSet::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "[core]" {
                if in_core {
                    return Err(PrivateGitRepositoryError::InvalidGitConfig);
                }
                in_core = true;
                continue;
            }
            if !in_core || trimmed.starts_with('[') || trimmed.starts_with(['#', ';']) {
                return Err(PrivateGitRepositoryError::InvalidGitConfig);
            }
            let (key, value) = trimmed
                .split_once('=')
                .ok_or(PrivateGitRepositoryError::InvalidGitConfig)?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            if !seen.insert(key.clone()) {
                return Err(PrivateGitRepositoryError::InvalidGitConfig);
            }
            match (key.as_str(), value.as_str()) {
                ("repositoryformatversion", "0") => repository_format = true,
                ("bare", "true") => bare = true,
                ("filemode" | "symlinks" | "ignorecase", "true" | "false")
                | ("logallrefupdates", "false") => {}
                _ => return Err(PrivateGitRepositoryError::InvalidGitConfig),
            }
        }
        if in_core && repository_format && bare {
            Ok(())
        } else {
            Err(PrivateGitRepositoryError::InvalidGitConfig)
        }
    }

    fn sync_parent(path: &Path) -> Result<(), PrivateGitRepositoryError> {
        let parent = path
            .parent()
            .ok_or(PrivateGitRepositoryError::ControlFileIo)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PrivateGitRepositoryError::ControlFileIo)
    }

    fn directory_owner(path: &Path) -> Result<u32, PrivateGitRepositoryError> {
        fs::metadata(path)
            .map(|metadata| metadata.uid())
            .map_err(|_| PrivateGitRepositoryError::UnsafeDirectory)
    }

    fn private_parent_owner(path: &Path) -> Result<u32, PrivateGitRepositoryError> {
        let parent = path
            .parent()
            .ok_or(PrivateGitRepositoryError::UnsafeControlFile)?;
        let metadata =
            fs::metadata(parent).map_err(|_| PrivateGitRepositoryError::UnsafeControlFile)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(PrivateGitRepositoryError::UnsafeControlFile);
        }
        Ok(metadata.uid())
    }

    fn is_absolute_normal(path: &Path) -> bool {
        path.is_absolute()
            && path
                .components()
                .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
    }

    #[cfg(test)]
    mod tests {
        use std::process::Stdio;

        use super::*;

        fn system_toolchain() -> Option<UnixGitToolchain> {
            match UnixGitToolchain::new("/usr/bin/git") {
                Ok(toolchain) => Some(toolchain),
                Err(GitProcessPolicyError::InvalidToolLayout) => None,
                Err(error) => panic!("system toolchain: {error:?}"),
            }
        }

        #[test]
        fn private_bare_repository_is_offline_and_ignores_ambient_config() {
            if !Path::new("/usr/bin/git").is_file() || !Path::new("/usr/bin/ssh").is_file() {
                return;
            }
            let Some(toolchain) = system_toolchain() else {
                return;
            };
            let temporary = tempfile::tempdir().expect("fixture");
            let root = temporary.path().join("isolation");
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(&root).expect("private root");
            let preparation =
                PrivateGitRepositoryPreparation::prepare(&root).expect("private layout");
            let mut command = preparation
                .initialization_spec(&toolchain)
                .expect("init spec")
                .command()
                .expect("init command");
            assert!(
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("git init")
                    .success()
            );
            let repository = preparation.finish().expect("sealed repository");
            repository.verify().expect("verified repository");
            let context = repository.process_context().expect("process context");
            let output = toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::Offline,
                    ["config", "--local", "--no-includes", "--list"],
                )
                .expect("config spec")
                .command()
                .expect("config command")
                .output()
                .expect("config output");
            assert!(output.status.success());
            let output = String::from_utf8(output.stdout).expect("UTF-8 config");
            assert!(output.contains("core.bare=true"));
            for forbidden in [
                "credential.helper",
                "core.sshcommand",
                "url.",
                "http.proxy",
                "include.path",
            ] {
                assert!(!output.to_ascii_lowercase().contains(forbidden));
            }
            PrivateBareGitRepository::open(repository.paths().root())
                .expect("reopened repository")
                .verify()
                .expect("reopened verification");
        }

        #[test]
        fn managed_ssh_config_resolves_exact_private_known_hosts() {
            if !Path::new("/usr/bin/git").is_file() || !Path::new("/usr/bin/ssh").is_file() {
                return;
            }
            let Some(toolchain) = system_toolchain() else {
                return;
            };
            let temporary = tempfile::tempdir().expect("fixture");
            let root = temporary.path().join("isolation");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .expect("private root");
            let preparation =
                PrivateGitRepositoryPreparation::prepare(&root).expect("private layout");
            let mut command = preparation
                .initialization_spec(&toolchain)
                .expect("init spec")
                .command()
                .expect("init command");
            assert!(
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .expect("git init")
                    .success()
            );
            let repository = preparation.finish().expect("sealed repository");
            let paths = repository.paths();
            let config = String::from_utf8(fs::read(paths.ssh_config()).expect("SSH config"))
                .expect("UTF-8 SSH config");
            assert!(!config.contains('~'));

            let output = std::process::Command::new("/usr/bin/ssh")
                .args(["-G", "-F"])
                .arg(paths.ssh_config())
                .arg("github.com")
                .env_clear()
                .env("HOME", temporary.path().join("ambient-home"))
                .output()
                .expect("ssh -G");
            assert!(output.status.success());
            let resolved = String::from_utf8(output.stdout).expect("UTF-8 ssh -G output");
            let values = resolved
                .lines()
                .filter_map(|line| line.split_once(' '))
                .filter(|(key, _)| key.eq_ignore_ascii_case("userknownhostsfile"))
                .map(|(_, value)| value.trim())
                .collect::<Vec<_>>();
            let expected = paths.known_hosts().to_string_lossy().into_owned();
            assert_eq!(values, [expected]);
        }
    }
}

#[cfg(unix)]
pub use unix::{
    GITHUB_KNOWN_HOSTS_V1, PrivateBareGitRepository, PrivateGitRepositoryError,
    PrivateGitRepositoryPaths, PrivateGitRepositoryPreparation,
};
