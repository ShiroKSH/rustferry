//! Fixed-tool, environment-cleared Git process policy.

use crate::git_endpoint::GithubGitTransport;

/// Network capability granted to one isolated Git invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitNetworkPolicy {
    /// No transport helper may be invoked.
    Offline,
    /// Canonical HTTPS; Windows uses fixed GCM, while Unix disables credential helpers.
    HttpsWithCredentialManager,
    /// Only canonical GitHub SSH with the retained Windows OpenSSH client may be used.
    GithubSsh,
}

impl From<GithubGitTransport> for GitNetworkPolicy {
    fn from(value: GithubGitTransport) -> Self {
        match value {
            GithubGitTransport::Https => Self::HttpsWithCredentialManager,
            GithubGitTransport::Ssh => Self::GithubSsh,
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::{
        collections::BTreeMap,
        error::Error,
        ffi::{OsStr, OsString},
        fmt,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom},
        os::windows::fs::{MetadataExt as _, OpenOptionsExt as _},
        path::{Component, Path, PathBuf},
        process::Command,
    };

    use rustferry_core::windows_system_root;
    use same_file::Handle as FileIdentityHandle;
    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    use super::GitNetworkPolicy;

    const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
    const WINDOWS_GIT_CMD_DIRECTORY: &str = "cmd";
    const WINDOWS_GIT_EXECUTABLE: &str = "git.exe";
    const WINDOWS_GCM_EXECUTABLE: &str = "git-credential-manager.exe";
    const WINDOWS_HTTPS_HELPER: &str = "git-remote-https.exe";
    const WINDOWS_SHELL_EXECUTABLE: &str = "sh.exe";
    const WINDOWS_SSH_EXECUTABLE: &str = "ssh.exe";
    const WINDOWS_COMMAND_INTERPRETER: &str = "cmd.exe";

    /// A retained executable whose path, object identity, and bytes cannot change on Windows.
    pub struct RetainedGitExecutable {
        path: PathBuf,
        identity: FileIdentityHandle,
        sha256: String,
        _file: File,
    }

    impl RetainedGitExecutable {
        fn open(path: &Path, expected_name: &str) -> Result<Self, GitProcessPolicyError> {
            let path = canonical_file(path, expected_name)?;
            let file = open_retained_regular_file(&path)?;
            let identity = FileIdentityHandle::from_file(
                file.try_clone()
                    .map_err(|_| GitProcessPolicyError::InvalidExecutable)?,
            )
            .map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
            if FileIdentityHandle::from_path(&path)
                .map_err(|_| GitProcessPolicyError::InvalidExecutable)?
                != identity
            {
                return Err(GitProcessPolicyError::ExecutableIdentityChanged);
            }
            let sha256 = hash_retained_file(&file)?;
            Ok(Self {
                path,
                identity,
                sha256,
                _file: file,
            })
        }

        /// Canonical executable path retained for process creation.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Stable filesystem identity of the retained executable.
        pub const fn identity(&self) -> &FileIdentityHandle {
            &self.identity
        }

        /// Lowercase SHA-256 of the exact retained executable bytes.
        pub fn sha256(&self) -> &str {
            &self.sha256
        }

        /// Revalidate the named path against the retained handle and byte digest.
        ///
        /// # Errors
        ///
        /// Returns a path-free failure if the executable was replaced or modified.
        pub fn verify(&self) -> Result<(), GitProcessPolicyError> {
            if FileIdentityHandle::from_path(&self.path)
                .map_err(|_| GitProcessPolicyError::ExecutableIdentityChanged)?
                != self.identity
            {
                return Err(GitProcessPolicyError::ExecutableIdentityChanged);
            }
            let current = open_retained_regular_file(&self.path)?;
            if FileIdentityHandle::from_file(
                current
                    .try_clone()
                    .map_err(|_| GitProcessPolicyError::InvalidExecutable)?,
            )
            .map_err(|_| GitProcessPolicyError::InvalidExecutable)?
                != self.identity
                || hash_retained_file(&current)? != self.sha256
            {
                return Err(GitProcessPolicyError::ExecutableIdentityChanged);
            }
            Ok(())
        }
    }

    impl fmt::Debug for RetainedGitExecutable {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("RetainedGitExecutable")
                .field("name", &self.path.file_name())
                .field("identity", &self.identity)
                .field("sha256", &self.sha256)
                .finish_non_exhaustive()
        }
    }

    struct RetainedToolDirectory {
        path: PathBuf,
        identity: FileIdentityHandle,
        _file: File,
    }

    impl RetainedToolDirectory {
        fn open(path: &Path) -> Result<Self, GitProcessPolicyError> {
            let path = canonical_directory(path)?;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
            let file = options
                .open(&path)
                .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
            let identity = FileIdentityHandle::from_file(
                file.try_clone()
                    .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?,
            )
            .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
            if FileIdentityHandle::from_path(&path)
                .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?
                != identity
            {
                return Err(GitProcessPolicyError::ToolLayoutIdentityChanged);
            }
            Ok(Self {
                path,
                identity,
                _file: file,
            })
        }

        fn verify(&self) -> Result<(), GitProcessPolicyError> {
            if FileIdentityHandle::from_path(&self.path)
                .map_err(|_| GitProcessPolicyError::ToolLayoutIdentityChanged)?
                != self.identity
            {
                return Err(GitProcessPolicyError::ToolLayoutIdentityChanged);
            }
            Ok(())
        }
    }

    impl fmt::Debug for RetainedToolDirectory {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("RetainedToolDirectory")
                .field("name", &self.path.file_name())
                .field("identity", &self.identity)
                .finish_non_exhaustive()
        }
    }

    /// Canonical Git-for-Windows, GCM, and operating-system OpenSSH installation.
    ///
    /// Construction accepts only the standard Git-for-Windows `cmd/git.exe` layout. Every
    /// executable and containing directory remains open without delete sharing for the complete
    /// lifetime of this value. OpenSSH and `cmd.exe` are derived from the operating system's
    /// authoritative Windows directory, never from ambient `PATH` or `SystemRoot` values.
    #[derive(Debug)]
    pub struct WindowsGitToolchain {
        git_root: RetainedToolDirectory,
        git_cmd_directory: RetainedToolDirectory,
        git_bin_directory: RetainedToolDirectory,
        git_exec_directory: RetainedToolDirectory,
        git_usr_bin_directory: RetainedToolDirectory,
        system_directory: RetainedToolDirectory,
        openssh_directory: RetainedToolDirectory,
        git: RetainedGitExecutable,
        git_runtime: RetainedGitExecutable,
        git_exec_runtime: RetainedGitExecutable,
        credential_manager: RetainedGitExecutable,
        https_helper: RetainedGitExecutable,
        shell: RetainedGitExecutable,
        ssh: RetainedGitExecutable,
        command_interpreter: RetainedGitExecutable,
        system_root: PathBuf,
        fixed_path: OsString,
        fixed_ssh_command: OsString,
    }

    impl WindowsGitToolchain {
        /// Resolve a strict Git-for-Windows layout from one explicit canonical `git.exe` path.
        ///
        /// # Errors
        ///
        /// Rejects relative, linked, renamed, oversized, missing, nonstandard, or internally
        /// inconsistent Git/GCM/OpenSSH layouts.
        pub fn new(git_executable: impl AsRef<Path>) -> Result<Self, GitProcessPolicyError> {
            let git = RetainedGitExecutable::open(git_executable.as_ref(), WINDOWS_GIT_EXECUTABLE)?;
            let git_cmd_path = git
                .path()
                .parent()
                .ok_or(GitProcessPolicyError::InvalidToolLayout)?;
            if !file_name_eq(git_cmd_path, WINDOWS_GIT_CMD_DIRECTORY) {
                return Err(GitProcessPolicyError::InvalidToolLayout);
            }
            let git_root_path = git_cmd_path
                .parent()
                .ok_or(GitProcessPolicyError::InvalidToolLayout)?;
            let system_root = windows_system_root()
                .map_err(|_| GitProcessPolicyError::InvalidWindowsDirectory)?;
            let system_drive_root = system_root
                .parent()
                .ok_or(GitProcessPolicyError::InvalidWindowsDirectory)?;
            let standard_git_root = fs::canonicalize(system_drive_root.join("Program Files/Git"))
                .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
            if fs::canonicalize(git_root_path)
                .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?
                != standard_git_root
            {
                return Err(GitProcessPolicyError::InvalidToolLayout);
            }
            let git_root = RetainedToolDirectory::open(git_root_path)?;
            let git_cmd_directory = RetainedToolDirectory::open(git_cmd_path)?;
            let git_bin_directory =
                RetainedToolDirectory::open(&git_root.path.join("mingw64/bin"))?;
            let git_exec_directory =
                RetainedToolDirectory::open(&git_root.path.join("mingw64/libexec/git-core"))?;
            let git_usr_bin_directory =
                RetainedToolDirectory::open(&git_root.path.join("usr/bin"))?;
            // `cmd/git.exe` launches the mingw runtime, and GCM may itself run `git config`.
            // Retain both locations that the fixed PATH/GIT_EXEC_PATH make executable.
            let git_runtime = RetainedGitExecutable::open(
                &git_bin_directory.path.join(WINDOWS_GIT_EXECUTABLE),
                WINDOWS_GIT_EXECUTABLE,
            )?;
            let git_exec_runtime = RetainedGitExecutable::open(
                &git_exec_directory.path.join(WINDOWS_GIT_EXECUTABLE),
                WINDOWS_GIT_EXECUTABLE,
            )?;
            let credential_manager = RetainedGitExecutable::open(
                &git_bin_directory.path.join(WINDOWS_GCM_EXECUTABLE),
                WINDOWS_GCM_EXECUTABLE,
            )?;
            let https_helper = RetainedGitExecutable::open(
                &git_exec_directory.path.join(WINDOWS_HTTPS_HELPER),
                WINDOWS_HTTPS_HELPER,
            )?;
            let shell = RetainedGitExecutable::open(
                &git_usr_bin_directory.path.join(WINDOWS_SHELL_EXECUTABLE),
                WINDOWS_SHELL_EXECUTABLE,
            )?;

            let system_directory = RetainedToolDirectory::open(&system_root.join("System32"))?;
            let openssh_directory =
                RetainedToolDirectory::open(&system_directory.path.join("OpenSSH"))?;
            let ssh = RetainedGitExecutable::open(
                &openssh_directory.path.join(WINDOWS_SSH_EXECUTABLE),
                WINDOWS_SSH_EXECUTABLE,
            )?;
            let command_interpreter = RetainedGitExecutable::open(
                &system_directory.path.join(WINDOWS_COMMAND_INTERPRETER),
                WINDOWS_COMMAND_INTERPRETER,
            )?;
            let fixed_path_entries = [
                external_path(&openssh_directory.path),
                external_path(&git_bin_directory.path),
                external_path(&git_usr_bin_directory.path),
                external_path(&system_directory.path),
            ];
            let fixed_path = std::env::join_paths(&fixed_path_entries)
                .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
            let fixed_ssh_command = fixed_windows_ssh_command(ssh.path())?;
            let toolchain = Self {
                git_root,
                git_cmd_directory,
                git_bin_directory,
                git_exec_directory,
                git_usr_bin_directory,
                system_directory,
                openssh_directory,
                git,
                git_runtime,
                git_exec_runtime,
                credential_manager,
                https_helper,
                shell,
                ssh,
                command_interpreter,
                system_root,
                fixed_path,
                fixed_ssh_command,
            };
            toolchain.verify()?;
            Ok(toolchain)
        }

        /// Retained Git executable.
        pub const fn git(&self) -> &RetainedGitExecutable {
            &self.git
        }

        /// Retained Git Credential Manager executable.
        pub const fn credential_manager(&self) -> &RetainedGitExecutable {
            &self.credential_manager
        }

        #[cfg(test)]
        pub(crate) const fn git_runtime(&self) -> &RetainedGitExecutable {
            &self.git_runtime
        }

        #[cfg(test)]
        pub(crate) const fn git_exec_runtime(&self) -> &RetainedGitExecutable {
            &self.git_exec_runtime
        }

        /// Retained Windows OpenSSH executable.
        pub const fn ssh(&self) -> &RetainedGitExecutable {
            &self.ssh
        }

        /// Retained Git HTTPS remote helper.
        pub const fn https_helper(&self) -> &RetainedGitExecutable {
            &self.https_helper
        }

        /// Authoritative Windows directory used for `SystemRoot` and `WINDIR`.
        pub fn system_root(&self) -> &Path {
            &self.system_root
        }

        #[cfg(test)]
        pub(crate) fn fixed_path(&self) -> &OsStr {
            &self.fixed_path
        }

        /// Revalidate every retained executable and containing directory.
        ///
        /// # Errors
        ///
        /// Fails closed if any named path or executable bytes changed.
        pub fn verify(&self) -> Result<(), GitProcessPolicyError> {
            for directory in [
                &self.git_root,
                &self.git_cmd_directory,
                &self.git_bin_directory,
                &self.git_exec_directory,
                &self.git_usr_bin_directory,
                &self.system_directory,
                &self.openssh_directory,
            ] {
                directory.verify()?;
            }
            for executable in [
                &self.git,
                &self.git_runtime,
                &self.git_exec_runtime,
                &self.credential_manager,
                &self.https_helper,
                &self.shell,
                &self.ssh,
                &self.command_interpreter,
            ] {
                executable.verify()?;
            }
            Ok(())
        }

        /// Build one environment-cleared Git command bound to controlled directories.
        ///
        /// # Errors
        ///
        /// Rejects changed tool identities or invalid process directories.
        pub fn process_spec<'a>(
            &'a self,
            context: &GitProcessContext,
            network: GitNetworkPolicy,
            arguments: impl IntoIterator<Item = impl Into<OsString>>,
        ) -> Result<GitProcessSpec<'a>, GitProcessPolicyError> {
            self.verify()?;
            context.verify()?;
            let mut fixed_arguments = fixed_git_arguments(network);
            fixed_arguments.extend(arguments.into_iter().map(Into::into));
            let environment = self.fixed_environment(context, network);
            Ok(GitProcessSpec {
                toolchain: self,
                arguments: fixed_arguments,
                environment,
                current_directory: context.cwd.clone(),
            })
        }

        fn fixed_environment(
            &self,
            context: &GitProcessContext,
            network: GitNetworkPolicy,
        ) -> BTreeMap<OsString, OsString> {
            let allowed_protocol = match network {
                GitNetworkPolicy::Offline => "",
                GitNetworkPolicy::HttpsWithCredentialManager => "https",
                GitNetworkPolicy::GithubSsh => "ssh",
            };
            let mut environment = BTreeMap::from([
                (
                    OsString::from("COMSPEC"),
                    external_path(self.command_interpreter.path()),
                ),
                (OsString::from("GCM_INTERACTIVE"), OsString::from("Never")),
                (OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1")),
                (
                    OsString::from("GIT_ALLOW_PROTOCOL"),
                    OsString::from(allowed_protocol),
                ),
                (OsString::from("GIT_CONFIG_GLOBAL"), OsString::from("NUL")),
                (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
                (OsString::from("GIT_CONFIG_SYSTEM"), OsString::from("NUL")),
                (
                    OsString::from("GIT_EXEC_PATH"),
                    external_path(&self.git_exec_directory.path),
                ),
                (
                    OsString::from("GIT_NO_REPLACE_OBJECTS"),
                    OsString::from("1"),
                ),
                (OsString::from("GIT_NO_LAZY_FETCH"), OsString::from("1")),
                (OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")),
                (OsString::from("GIT_PAGER"), OsString::from("cat")),
                (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
                (OsString::from("HOME"), external_path(&context.home)),
                (OsString::from("LANG"), OsString::from("C")),
                (OsString::from("LC_ALL"), OsString::from("C")),
                (OsString::from("PATH"), self.fixed_path.clone()),
                (
                    OsString::from("PATHEXT"),
                    OsString::from(".COM;.EXE;.BAT;.CMD"),
                ),
                (OsString::from("PROGRAMDATA"), external_path(&context.home)),
                (
                    OsString::from("SystemRoot"),
                    external_path(&self.system_root),
                ),
                (OsString::from("TEMP"), external_path(&context.temp)),
                (OsString::from("TMP"), external_path(&context.temp)),
                (OsString::from("USERPROFILE"), external_path(&context.home)),
                (OsString::from("WINDIR"), external_path(&self.system_root)),
                (
                    OsString::from("XDG_CONFIG_HOME"),
                    external_path(&context.xdg_config),
                ),
            ]);
            if let Some(git_directory) = &context.git_dir {
                environment.insert(OsString::from("GIT_DIR"), external_path(git_directory));
            }
            if network == GitNetworkPolicy::GithubSsh {
                environment.insert(OsString::from("GIT_SSH"), external_path(self.ssh.path()));
                // Git has no argument-array interface for SSH options. This fixed string contains
                // no caller input; `-F` also suppresses ambient user and system OpenSSH config.
                environment.insert(
                    OsString::from("GIT_SSH_COMMAND"),
                    self.fixed_ssh_command.clone(),
                );
                environment.insert(OsString::from("GIT_SSH_VARIANT"), OsString::from("ssh"));
            }
            environment
        }
    }

    /// Resolve the only Git-for-Windows entrypoint accepted by production.
    ///
    /// The path comes from the operating system's authoritative Windows directory, never from
    /// `PATH`, `ProgramFiles`, or another caller-controlled environment variable.
    ///
    /// # Errors
    ///
    /// Rejects an unavailable Windows directory or any missing/nonstandard Git-for-Windows tool.
    pub fn trusted_git_executable() -> Result<PathBuf, GitProcessPolicyError> {
        let system_root =
            windows_system_root().map_err(|_| GitProcessPolicyError::InvalidWindowsDirectory)?;
        let drive_root = system_root
            .parent()
            .ok_or(GitProcessPolicyError::InvalidWindowsDirectory)?;
        let executable = drive_root.join("Program Files/Git/cmd/git.exe");
        WindowsGitToolchain::new(&executable)?;
        Ok(executable)
    }

    /// Canonical private directories supplied to one Git process.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct GitProcessContext {
        cwd: PathBuf,
        git_dir: Option<PathBuf>,
        home: PathBuf,
        xdg_config: PathBuf,
        temp: PathBuf,
    }

    impl GitProcessContext {
        /// Create a canonical process context, optionally binding a private bare Git directory.
        ///
        /// # Errors
        ///
        /// Rejects relative, linked, missing, or non-directory paths.
        pub fn new(
            current_directory: impl AsRef<Path>,
            git_directory: Option<&Path>,
            home_directory: impl AsRef<Path>,
            xdg_config_directory: impl AsRef<Path>,
            temporary_directory: impl AsRef<Path>,
        ) -> Result<Self, GitProcessPolicyError> {
            Ok(Self {
                cwd: canonical_directory(current_directory.as_ref())?,
                git_dir: git_directory.map(canonical_directory).transpose()?,
                home: canonical_directory(home_directory.as_ref())?,
                xdg_config: canonical_directory(xdg_config_directory.as_ref())?,
                temp: canonical_directory(temporary_directory.as_ref())?,
            })
        }

        /// Canonical private bare repository, when the command needs one.
        pub fn git_directory(&self) -> Option<&Path> {
            self.git_dir.as_deref()
        }

        /// Canonical process working directory.
        pub fn current_directory(&self) -> &Path {
            &self.cwd
        }

        fn verify(&self) -> Result<(), GitProcessPolicyError> {
            for path in [
                Some(self.cwd.as_path()),
                self.git_dir.as_deref(),
                Some(self.home.as_path()),
                Some(self.xdg_config.as_path()),
                Some(self.temp.as_path()),
            ]
            .into_iter()
            .flatten()
            {
                if canonical_directory(path)? != path {
                    return Err(GitProcessPolicyError::ProcessDirectoryChanged);
                }
            }
            Ok(())
        }
    }

    /// One exact Git command whose environment starts empty.
    pub struct GitProcessSpec<'a> {
        toolchain: &'a WindowsGitToolchain,
        arguments: Vec<OsString>,
        environment: BTreeMap<OsString, OsString>,
        current_directory: PathBuf,
    }

    impl GitProcessSpec<'_> {
        /// Construct the process after revalidating all retained tool identities.
        ///
        /// # Errors
        ///
        /// Fails if a tool or installation directory changed after planning.
        pub fn command(&self) -> Result<Command, GitProcessPolicyError> {
            self.toolchain.verify()?;
            let mut command = Command::new(self.toolchain.git.path());
            command
                .env_clear()
                .envs(self.environment.iter())
                .args(&self.arguments)
                .current_dir(&self.current_directory);
            Ok(command)
        }

        /// Exact argument vector after `git.exe`.
        pub fn arguments(&self) -> &[OsString] {
            &self.arguments
        }

        /// Exact allowlisted environment. Values contain only controlled local paths and flags.
        pub const fn environment(&self) -> &BTreeMap<OsString, OsString> {
            &self.environment
        }

        /// Exact process working directory.
        pub fn current_directory(&self) -> &Path {
            &self.current_directory
        }
    }

    impl fmt::Debug for GitProcessSpec<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("GitProcessSpec")
                .field("argument_count", &self.arguments.len())
                .field(
                    "environment_names",
                    &self.environment.keys().collect::<Vec<_>>(),
                )
                .field("current_directory_identity", &"private")
                .finish_non_exhaustive()
        }
    }

    /// Stable, path-free process-policy configuration failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GitProcessPolicyError {
        /// Executable path, type, name, size, identity, or contents are invalid.
        InvalidExecutable,
        /// Git-for-Windows installation layout is incomplete or nonstandard.
        InvalidToolLayout,
        /// Operating system did not provide a trustworthy Windows directory.
        InvalidWindowsDirectory,
        /// A retained executable path or byte digest changed.
        ExecutableIdentityChanged,
        /// A retained tool directory path changed.
        ToolLayoutIdentityChanged,
        /// Private process directory is invalid.
        InvalidProcessDirectory,
        /// Private process directory changed after planning.
        ProcessDirectoryChanged,
        /// Executable bytes could not be read safely.
        ExecutableReadFailed,
    }

    impl fmt::Display for GitProcessPolicyError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidExecutable => formatter.write_str("Git executable is invalid"),
                Self::InvalidToolLayout => {
                    formatter.write_str("Git-for-Windows tool layout is invalid")
                }
                Self::InvalidWindowsDirectory => {
                    formatter.write_str("Windows system directory is invalid")
                }
                Self::ExecutableIdentityChanged => {
                    formatter.write_str("retained Git executable identity changed")
                }
                Self::ToolLayoutIdentityChanged => {
                    formatter.write_str("retained Git tool directory identity changed")
                }
                Self::InvalidProcessDirectory => {
                    formatter.write_str("isolated Git process directory is invalid")
                }
                Self::ProcessDirectoryChanged => {
                    formatter.write_str("isolated Git process directory changed")
                }
                Self::ExecutableReadFailed => {
                    formatter.write_str("Git executable could not be read safely")
                }
            }
        }
    }

    impl Error for GitProcessPolicyError {}

    fn fixed_git_arguments(network: GitNetworkPolicy) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--no-optional-locks"),
            OsString::from("--no-replace-objects"),
        ];
        arguments.extend(
            [
                "core.hooksPath=NUL",
                "core.fsmonitor=false",
                "core.attributesFile=NUL",
                "core.excludesFile=NUL",
                "diff.external=",
                "credential.interactive=never",
                "protocol.allow=never",
                "protocol.file.allow=never",
                "maintenance.auto=false",
                "gc.auto=0",
                "fetch.writeCommitGraph=false",
            ]
            .into_iter()
            .flat_map(|configuration| [OsString::from("-c"), OsString::from(configuration)]),
        );
        let network_configuration: &[&str] = match network {
            GitNetworkPolicy::Offline => &["credential.helper="],
            GitNetworkPolicy::HttpsWithCredentialManager => &[
                "protocol.https.allow=always",
                "credential.helper=",
                "credential.helper=manager",
                "credential.useHttpPath=true",
                "http.sslVerify=true",
                "http.sslBackend=schannel",
                "http.proxy=",
            ],
            GitNetworkPolicy::GithubSsh => &["protocol.ssh.allow=always", "credential.helper="],
        };
        arguments.extend(
            network_configuration
                .iter()
                .flat_map(|configuration| [OsString::from("-c"), OsString::from(configuration)]),
        );
        arguments
    }

    fn canonical_file(path: &Path, expected_name: &str) -> Result<PathBuf, GitProcessPolicyError> {
        if !is_absolute_normal(path) {
            return Err(GitProcessPolicyError::InvalidExecutable);
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
            || !path
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
        {
            return Err(GitProcessPolicyError::InvalidExecutable);
        }
        let canonical =
            fs::canonicalize(path).map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
        if !canonical
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(expected_name))
        {
            return Err(GitProcessPolicyError::InvalidExecutable);
        }
        Ok(canonical)
    }

    fn canonical_directory(path: &Path) -> Result<PathBuf, GitProcessPolicyError> {
        if !is_absolute_normal(path) {
            return Err(GitProcessPolicyError::InvalidProcessDirectory);
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| GitProcessPolicyError::InvalidProcessDirectory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(GitProcessPolicyError::InvalidProcessDirectory);
        }
        fs::canonicalize(path).map_err(|_| GitProcessPolicyError::InvalidProcessDirectory)
    }

    fn open_retained_regular_file(path: &Path) -> Result<File, GitProcessPolicyError> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        options
            .open(path)
            .map_err(|_| GitProcessPolicyError::InvalidExecutable)
    }

    fn hash_retained_file(file: &File) -> Result<String, GitProcessPolicyError> {
        let metadata = file
            .metadata()
            .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
            return Err(GitProcessPolicyError::InvalidExecutable);
        }
        let mut reader = file
            .try_clone()
            .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut total = 0_u64;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(
                    u64::try_from(read).map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?,
                )
                .ok_or(GitProcessPolicyError::ExecutableReadFailed)?;
            if total > MAX_EXECUTABLE_BYTES {
                return Err(GitProcessPolicyError::InvalidExecutable);
            }
            digest.update(&buffer[..read]);
        }
        if total != metadata.len() {
            return Err(GitProcessPolicyError::ExecutableReadFailed);
        }
        Ok(hex::encode(digest.finalize()))
    }

    fn file_name_eq(path: &Path, expected: &str) -> bool {
        path.file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
    }

    pub(crate) fn external_path(path: &Path) -> OsString {
        let value = path.as_os_str().to_string_lossy();
        if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
            OsString::from(format!(r"\\{unc}"))
        } else if let Some(normal) = value.strip_prefix(r"\\?\") {
            OsString::from(normal)
        } else {
            path.as_os_str().to_owned()
        }
    }

    fn fixed_windows_ssh_command(path: &Path) -> Result<OsString, GitProcessPolicyError> {
        let external = external_path(path);
        let external = external
            .to_str()
            .ok_or(GitProcessPolicyError::InvalidToolLayout)?
            .replace('\\', "/");
        if !external.is_ascii()
            || external.is_empty()
            || external.chars().any(|character| {
                !character.is_ascii_alphanumeric()
                    && !matches!(character, ':' | '/' | '.' | '_' | '-' | ' ')
            })
        {
            return Err(GitProcessPolicyError::InvalidToolLayout);
        }
        Ok(OsString::from(format!(
            r#""{external}" -F "$HOME/.ssh/config""#
        )))
    }

    fn is_absolute_normal(path: &Path) -> bool {
        path.is_absolute()
            && path
                .components()
                .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn installed_git() -> Option<PathBuf> {
            let path = PathBuf::from(r"C:\Program Files\Git\cmd\git.exe");
            path.is_file().then_some(path)
        }

        #[test]
        fn installed_windows_toolchain_has_retained_exact_companions() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("Git-for-Windows toolchain");
            toolchain.verify().expect("stable toolchain");
            for executable in [
                toolchain.git(),
                toolchain.git_runtime(),
                toolchain.git_exec_runtime(),
                toolchain.credential_manager(),
                toolchain.https_helper(),
                toolchain.ssh(),
            ] {
                assert_eq!(executable.sha256().len(), 64);
                assert!(
                    executable
                        .sha256()
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                );
            }
        }

        #[test]
        #[allow(
            clippy::too_many_lines,
            reason = "one policy matrix proves the complete environment and fixed-argument allowlist"
        )]
        fn process_policy_never_inherits_malicious_environment_names() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("Git-for-Windows toolchain");
            let directory = tempfile::tempdir().expect("private process fixture");
            for name in ["git", "home", "xdg", "tmp"] {
                fs::create_dir(directory.path().join(name)).expect("fixture directory");
            }
            let context = GitProcessContext::new(
                directory.path(),
                Some(&directory.path().join("git")),
                directory.path().join("home"),
                directory.path().join("xdg"),
                directory.path().join("tmp"),
            )
            .expect("process context");
            for network in [
                GitNetworkPolicy::Offline,
                GitNetworkPolicy::HttpsWithCredentialManager,
                GitNetworkPolicy::GithubSsh,
            ] {
                let spec = toolchain
                    .process_spec(&context, network, ["version"])
                    .expect("process spec");
                let environment_names = spec
                    .environment()
                    .keys()
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect::<std::collections::BTreeSet<_>>();
                for forbidden in [
                    "GH_TOKEN",
                    "GITHUB_TOKEN",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "NO_PROXY",
                    "SSH_AUTH_SOCK",
                    "GIT_ASKPASS",
                    "SSH_ASKPASS",
                    "GIT_CONFIG_COUNT",
                    "GIT_CONFIG_PARAMETERS",
                    "GIT_CONFIG_KEY_0",
                    "GIT_CONFIG_VALUE_0",
                    "GIT_OBJECT_DIRECTORY",
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    "GIT_PROXY_COMMAND",
                    "GCM_HTTP_PROXY",
                    "GCM_CREDENTIAL_STORE",
                    "GCM_PROVIDER",
                    "GCM_TRACE",
                ] {
                    assert!(!environment_names.contains(forbidden), "{forbidden}");
                }
                assert_eq!(
                    spec.environment().get(OsStr::new("GIT_ALLOW_PROTOCOL")),
                    Some(&OsString::from(match network {
                        GitNetworkPolicy::Offline => "",
                        GitNetworkPolicy::HttpsWithCredentialManager => "https",
                        GitNetworkPolicy::GithubSsh => "ssh",
                    }))
                );
                assert_eq!(
                    spec.environment().get(OsStr::new("GIT_NO_LAZY_FETCH")),
                    Some(&OsString::from("1"))
                );
                assert_eq!(
                    spec.environment()
                        .get(OsStr::new("GIT_SSH_COMMAND"))
                        .map(OsString::as_os_str),
                    (network == GitNetworkPolicy::GithubSsh)
                        .then_some(toolchain.fixed_ssh_command.as_os_str())
                );
                assert_eq!(
                    spec.environment()
                        .get(OsStr::new("GIT_DIR"))
                        .map(OsString::as_os_str),
                    context.git_directory().map(external_path).as_deref()
                );
                assert!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "protocol.allow=never")
                );
                assert!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "credential.helper=")
                );
                assert_eq!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "http.proxy="),
                    network == GitNetworkPolicy::HttpsWithCredentialManager
                );
                assert_eq!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "credential.helper=manager"),
                    network == GitNetworkPolicy::HttpsWithCredentialManager
                );
            }
        }

        #[test]
        fn git_shell_executes_the_retained_system_openssh_image() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("Git-for-Windows toolchain");
            let directory = tempfile::tempdir().expect("private process fixture");
            for name in ["home", "xdg", "tmp"] {
                fs::create_dir(directory.path().join(name)).expect("fixture directory");
            }
            let context = GitProcessContext::new(
                directory.path(),
                None,
                directory.path().join("home"),
                directory.path().join("xdg"),
                directory.path().join("tmp"),
            )
            .expect("process context");
            let spec = toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::GithubSsh,
                    [
                        "-c",
                        r#"alias.rustferry-ssh-version=!eval "$GIT_SSH_COMMAND -V""#,
                        "rustferry-ssh-version",
                    ],
                )
                .expect("SSH process spec");
            let selected = spec.command().expect("sealed Git command").output().expect(
                "Git shell must execute the fixed absolute SSH command without network access",
            );
            let retained = Command::new(toolchain.ssh().path())
                .arg("-V")
                .output()
                .expect("retained OpenSSH version");
            let bundled = Command::new(toolchain.git_usr_bin_directory.path.join("ssh.exe"))
                .arg("-V")
                .output()
                .expect("bundled OpenSSH version");
            assert!(selected.status.success());
            assert_eq!(selected.stderr, retained.stderr);
            assert_ne!(selected.stderr, bundled.stderr);
        }

        #[test]
        fn offline_policy_denies_ext_after_a_later_config_override() {
            let Some(git) = installed_git() else {
                return;
            };
            let toolchain = WindowsGitToolchain::new(git).expect("Git-for-Windows toolchain");
            let directory = tempfile::tempdir().expect("private process fixture");
            for name in ["home", "xdg", "tmp"] {
                fs::create_dir(directory.path().join(name)).expect("fixture directory");
            }
            let context = GitProcessContext::new(
                directory.path(),
                None,
                directory.path().join("home"),
                directory.path().join("xdg"),
                directory.path().join("tmp"),
            )
            .expect("process context");
            let canary = external_path(&directory.path().join("ext-canary"))
                .to_string_lossy()
                .replace('\\', "/");
            let remote = format!("ext::cmd.exe /c echo escaped > {canary}");
            let spec = toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::Offline,
                    [
                        OsString::from("-c"),
                        OsString::from("protocol.ext.allow=always"),
                        OsString::from("ls-remote"),
                        OsString::from(remote),
                    ],
                )
                .expect("offline process spec");
            let output = spec
                .command()
                .expect("sealed Git command")
                .output()
                .expect("bounded local policy probe");
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("transport 'ext' not allowed")
            );
            assert!(!directory.path().join("ext-canary").exists());
        }

        #[test]
        fn retained_helper_chain_executables_block_post_plan_replacement() {
            let Some(git) = installed_git() else {
                return;
            };
            let directory = tempfile::tempdir().expect("fixture");
            for location in ["path-runtime", "exec-path-runtime"] {
                let runtime = directory.path().join(location);
                fs::create_dir(&runtime).expect("runtime fixture");
                let executable = runtime.join("git.exe");
                let displaced = runtime.join("old-git.exe");
                fs::copy(&git, &executable).expect("copy fixture executable");
                let retained = RetainedGitExecutable::open(&executable, "git.exe")
                    .expect("retained executable");

                // This occurs after planning and immediately before the modeled helper spawn.
                assert!(fs::rename(&executable, &displaced).is_err());
                assert!(OpenOptions::new().write(true).open(&executable).is_err());
                retained.verify().expect("unchanged retained executable");
            }
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::external_path;
#[cfg(windows)]
pub use windows::{
    GitProcessContext, GitProcessPolicyError, GitProcessSpec, RetainedGitExecutable,
    WindowsGitToolchain, trusted_git_executable,
};

#[cfg(unix)]
#[allow(missing_docs, clippy::missing_errors_doc)]
mod unix {
    use std::{
        collections::BTreeMap,
        error::Error,
        ffi::OsString,
        fmt,
        fs::{self, File},
        io::{Read, Seek, SeekFrom},
        os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
        path::{Component, Path, PathBuf},
        process::Command,
    };

    use sha2::{Digest, Sha256};

    use super::GitNetworkPolicy;

    const TRUSTED_GIT: &str = "/usr/bin/git";
    const TRUSTED_SSH: &str = "/usr/bin/ssh";
    const TRUSTED_SHELL: &str = "/bin/sh";
    const FIXED_SSH_COMMAND: &str = r#"/usr/bin/ssh -F "$HOME/.ssh/config""#;
    const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
    const MAX_EXEC_PATH_BYTES: usize = 4096;

    #[derive(Debug)]
    struct RetainedUnixExecutable {
        path: PathBuf,
        device: u64,
        inode: u64,
        length: u64,
        sha256: String,
        _file: File,
    }

    impl RetainedUnixExecutable {
        fn open(path: &Path, expected_path: &Path) -> Result<Self, GitProcessPolicyError> {
            if path != expected_path || !is_absolute_normal(path) {
                return Err(GitProcessPolicyError::InvalidExecutable);
            }
            validate_trusted_directory(
                path.parent()
                    .ok_or(GitProcessPolicyError::InvalidExecutable)?,
            )?;
            let canonical_target =
                fs::canonicalize(path).map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
            validate_trusted_directory(
                canonical_target
                    .parent()
                    .ok_or(GitProcessPolicyError::InvalidExecutable)?,
            )?;
            let link_metadata =
                fs::symlink_metadata(path).map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
            let is_symlink = link_metadata.file_type().is_symlink();
            if !(link_metadata.is_file() || is_symlink)
                || link_metadata.uid() != 0
                || (!is_symlink && link_metadata.permissions().mode() & 0o022 != 0)
            {
                return Err(GitProcessPolicyError::InvalidExecutable);
            }
            let file = File::open(path).map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
            let metadata = file
                .metadata()
                .map_err(|_| GitProcessPolicyError::InvalidExecutable)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.len() == 0
                || metadata.len() > MAX_EXECUTABLE_BYTES
            {
                return Err(GitProcessPolicyError::InvalidExecutable);
            }
            let sha256 = hash_retained_file(&file)?;
            Ok(Self {
                path: path.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                sha256,
                _file: file,
            })
        }

        fn verify(&self) -> Result<(), GitProcessPolicyError> {
            let file = File::open(&self.path)
                .map_err(|_| GitProcessPolicyError::ExecutableIdentityChanged)?;
            let metadata = file
                .metadata()
                .map_err(|_| GitProcessPolicyError::ExecutableIdentityChanged)?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.len() != self.length
                || hash_retained_file(&file)? != self.sha256
            {
                return Err(GitProcessPolicyError::ExecutableIdentityChanged);
            }
            Ok(())
        }
    }

    /// Root-owned system Git/OpenSSH policy for Unix clients.
    #[derive(Debug)]
    pub struct UnixGitToolchain {
        git: RetainedUnixExecutable,
        ssh: RetainedUnixExecutable,
        shell: RetainedUnixExecutable,
        git_exec_path: PathBuf,
        ssh_auth_sock: Option<PathBuf>,
    }

    impl UnixGitToolchain {
        /// Require the root-owned `/usr/bin/git` and `/usr/bin/ssh` entrypoints.
        pub fn new(git_executable: impl AsRef<Path>) -> Result<Self, GitProcessPolicyError> {
            let git =
                RetainedUnixExecutable::open(git_executable.as_ref(), Path::new(TRUSTED_GIT))?;
            let ssh = RetainedUnixExecutable::open(Path::new(TRUSTED_SSH), Path::new(TRUSTED_SSH))?;
            let shell =
                RetainedUnixExecutable::open(Path::new(TRUSTED_SHELL), Path::new(TRUSTED_SHELL))?;
            let git_exec_path = discover_git_exec_path(&git)?;
            let ssh_auth_sock = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
            let toolchain = Self {
                git,
                ssh,
                shell,
                git_exec_path,
                ssh_auth_sock,
            };
            toolchain.verify()?;
            Ok(toolchain)
        }

        fn verify(&self) -> Result<(), GitProcessPolicyError> {
            self.git.verify()?;
            self.ssh.verify()?;
            self.shell.verify()?;
            validate_trusted_directory(&self.git_exec_path)?;
            Ok(())
        }

        /// Build one environment-cleared Git command bound to controlled directories.
        pub fn process_spec<'a>(
            &'a self,
            context: &GitProcessContext,
            network: GitNetworkPolicy,
            arguments: impl IntoIterator<Item = impl Into<OsString>>,
        ) -> Result<GitProcessSpec<'a>, GitProcessPolicyError> {
            self.verify()?;
            context.verify()?;
            let ssh_auth_sock = (network == GitNetworkPolicy::GithubSsh)
                .then(|| {
                    self.ssh_auth_sock
                        .clone()
                        .ok_or(GitProcessPolicyError::InvalidSshAgent)
                        .and_then(validate_ssh_auth_socket)
                })
                .transpose()?;
            let mut fixed_arguments = fixed_git_arguments(network);
            fixed_arguments.extend(arguments.into_iter().map(Into::into));
            let allowed_protocol = match network {
                GitNetworkPolicy::Offline => "",
                GitNetworkPolicy::HttpsWithCredentialManager => "https",
                GitNetworkPolicy::GithubSsh => "ssh",
            };
            let mut environment = BTreeMap::from([
                (OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1")),
                (
                    OsString::from("GIT_ALLOW_PROTOCOL"),
                    OsString::from(allowed_protocol),
                ),
                (
                    OsString::from("GIT_CONFIG_GLOBAL"),
                    OsString::from("/dev/null"),
                ),
                (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
                (
                    OsString::from("GIT_CONFIG_SYSTEM"),
                    OsString::from("/dev/null"),
                ),
                (
                    OsString::from("GIT_EXEC_PATH"),
                    self.git_exec_path.as_os_str().to_owned(),
                ),
                (
                    OsString::from("GIT_NO_REPLACE_OBJECTS"),
                    OsString::from("1"),
                ),
                (OsString::from("GIT_NO_LAZY_FETCH"), OsString::from("1")),
                (OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")),
                (OsString::from("GIT_PAGER"), OsString::from("cat")),
                (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
                (OsString::from("HOME"), context.home.as_os_str().to_owned()),
                (OsString::from("LANG"), OsString::from("C")),
                (OsString::from("LC_ALL"), OsString::from("C")),
                (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                (
                    OsString::from("TMPDIR"),
                    context.temp.as_os_str().to_owned(),
                ),
                (
                    OsString::from("XDG_CONFIG_HOME"),
                    context.xdg_config.as_os_str().to_owned(),
                ),
            ]);
            if let Some(git_directory) = &context.git_dir {
                environment.insert(
                    OsString::from("GIT_DIR"),
                    git_directory.as_os_str().to_owned(),
                );
            }
            if network == GitNetworkPolicy::GithubSsh {
                environment.insert(
                    OsString::from("GIT_SSH"),
                    self.ssh.path.as_os_str().to_owned(),
                );
                // Git has no argument-array interface for SSH options. This fixed string contains
                // no caller input; `-F` also suppresses ambient user and system OpenSSH config.
                environment.insert(
                    OsString::from("GIT_SSH_COMMAND"),
                    OsString::from(FIXED_SSH_COMMAND),
                );
                environment.insert(OsString::from("GIT_SSH_VARIANT"), OsString::from("ssh"));
                environment.insert(
                    OsString::from("SSH_AUTH_SOCK"),
                    ssh_auth_sock
                        .as_ref()
                        .ok_or(GitProcessPolicyError::InvalidSshAgent)?
                        .as_os_str()
                        .to_owned(),
                );
            }
            Ok(GitProcessSpec {
                toolchain: self,
                arguments: fixed_arguments,
                environment,
                current_directory: context.cwd.clone(),
            })
        }
    }

    /// Resolve and validate the fixed root-owned Git entrypoint accepted on Unix.
    ///
    /// # Errors
    ///
    /// Rejects a missing, mutable, non-root-owned, or otherwise unsafe system toolchain.
    pub fn trusted_git_executable() -> Result<PathBuf, GitProcessPolicyError> {
        let executable = PathBuf::from(TRUSTED_GIT);
        UnixGitToolchain::new(&executable)?;
        Ok(executable)
    }

    /// Canonical private directories supplied to one Unix Git process.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct GitProcessContext {
        cwd: PathBuf,
        git_dir: Option<PathBuf>,
        home: PathBuf,
        xdg_config: PathBuf,
        temp: PathBuf,
        private_owner: u32,
    }

    impl GitProcessContext {
        pub fn new(
            current_directory: impl AsRef<Path>,
            git_directory: Option<&Path>,
            home_directory: impl AsRef<Path>,
            xdg_config_directory: impl AsRef<Path>,
            temporary_directory: impl AsRef<Path>,
        ) -> Result<Self, GitProcessPolicyError> {
            let cwd = canonical_directory(current_directory.as_ref())?;
            let git_dir = git_directory.map(canonical_private_directory).transpose()?;
            let home = canonical_private_directory(home_directory.as_ref())?;
            let xdg_config = canonical_private_directory(xdg_config_directory.as_ref())?;
            let temp = canonical_private_directory(temporary_directory.as_ref())?;
            let private_owner = private_directory_owner(&home)?;
            if [
                git_dir.as_deref(),
                Some(xdg_config.as_path()),
                Some(temp.as_path()),
            ]
            .into_iter()
            .flatten()
            .any(|path| private_directory_owner(path) != Ok(private_owner))
            {
                return Err(GitProcessPolicyError::InvalidProcessDirectory);
            }
            Ok(Self {
                cwd,
                git_dir,
                home,
                xdg_config,
                temp,
                private_owner,
            })
        }

        fn verify(&self) -> Result<(), GitProcessPolicyError> {
            if canonical_directory(&self.cwd)? != self.cwd
                || self
                    .git_dir
                    .as_deref()
                    .map(canonical_private_directory)
                    .transpose()?
                    .as_ref()
                    != self.git_dir.as_ref()
                || canonical_private_directory(&self.home)? != self.home
                || canonical_private_directory(&self.xdg_config)? != self.xdg_config
                || canonical_private_directory(&self.temp)? != self.temp
                || [
                    self.git_dir.as_deref(),
                    Some(self.home.as_path()),
                    Some(self.xdg_config.as_path()),
                    Some(self.temp.as_path()),
                ]
                .into_iter()
                .flatten()
                .any(|path| private_directory_owner(path) != Ok(self.private_owner))
            {
                return Err(GitProcessPolicyError::ProcessDirectoryChanged);
            }
            Ok(())
        }
    }

    /// One exact Unix Git command whose environment starts empty.
    pub struct GitProcessSpec<'a> {
        toolchain: &'a UnixGitToolchain,
        arguments: Vec<OsString>,
        environment: BTreeMap<OsString, OsString>,
        current_directory: PathBuf,
    }

    impl GitProcessSpec<'_> {
        pub fn command(&self) -> Result<Command, GitProcessPolicyError> {
            self.toolchain.verify()?;
            let mut command = Command::new(&self.toolchain.git.path);
            command
                .env_clear()
                .envs(self.environment.iter())
                .args(&self.arguments)
                .current_dir(&self.current_directory);
            Ok(command)
        }

        pub fn arguments(&self) -> &[OsString] {
            &self.arguments
        }

        pub const fn environment(&self) -> &BTreeMap<OsString, OsString> {
            &self.environment
        }
    }

    impl fmt::Debug for GitProcessSpec<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("GitProcessSpec")
                .field("argument_count", &self.arguments.len())
                .field(
                    "environment_names",
                    &self.environment.keys().collect::<Vec<_>>(),
                )
                .finish_non_exhaustive()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum GitProcessPolicyError {
        InvalidExecutable,
        InvalidToolLayout,
        ExecutableIdentityChanged,
        InvalidProcessDirectory,
        ProcessDirectoryChanged,
        ExecutableReadFailed,
        InvalidSshAgent,
    }

    impl fmt::Display for GitProcessPolicyError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InvalidExecutable => formatter.write_str("Git executable is invalid"),
                Self::InvalidToolLayout => formatter.write_str("system Git tool layout is invalid"),
                Self::ExecutableIdentityChanged => {
                    formatter.write_str("retained Git executable identity changed")
                }
                Self::InvalidProcessDirectory => {
                    formatter.write_str("isolated Git process directory is invalid")
                }
                Self::ProcessDirectoryChanged => {
                    formatter.write_str("isolated Git process directory changed")
                }
                Self::ExecutableReadFailed => {
                    formatter.write_str("Git executable could not be read safely")
                }
                Self::InvalidSshAgent => {
                    formatter.write_str("SSH agent socket is unavailable or unsafe")
                }
            }
        }
    }

    impl Error for GitProcessPolicyError {}

    fn fixed_git_arguments(network: GitNetworkPolicy) -> Vec<OsString> {
        let mut arguments = vec![
            OsString::from("--no-optional-locks"),
            OsString::from("--no-replace-objects"),
        ];
        arguments.extend(
            [
                "core.hooksPath=/dev/null",
                "core.fsmonitor=false",
                "core.attributesFile=/dev/null",
                "core.excludesFile=/dev/null",
                "diff.external=",
                "credential.interactive=never",
                "protocol.allow=never",
                "protocol.file.allow=never",
                "maintenance.auto=false",
                "gc.auto=0",
                "fetch.writeCommitGraph=false",
            ]
            .into_iter()
            .flat_map(|configuration| [OsString::from("-c"), OsString::from(configuration)]),
        );
        let network_configuration: &[&str] = match network {
            GitNetworkPolicy::Offline => &["credential.helper="],
            GitNetworkPolicy::HttpsWithCredentialManager => &[
                "protocol.https.allow=always",
                "credential.helper=",
                "credential.useHttpPath=true",
                "http.sslVerify=true",
                "http.proxy=",
            ],
            GitNetworkPolicy::GithubSsh => &["protocol.ssh.allow=always", "credential.helper="],
        };
        arguments.extend(
            network_configuration
                .iter()
                .flat_map(|configuration| [OsString::from("-c"), OsString::from(configuration)]),
        );
        arguments
    }

    fn discover_git_exec_path(
        git: &RetainedUnixExecutable,
    ) -> Result<PathBuf, GitProcessPolicyError> {
        git.verify()?;
        let output = Command::new(&git.path)
            .env_clear()
            .env("HOME", "/dev/null")
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .arg("--exec-path")
            .output()
            .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
        if !output.status.success()
            || output.stdout.is_empty()
            || output.stdout.len() > MAX_EXEC_PATH_BYTES
            || !output.stderr.is_empty()
        {
            return Err(GitProcessPolicyError::InvalidToolLayout);
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
        let path = PathBuf::from(text.trim_end_matches(['\r', '\n']));
        let path = fs::canonicalize(path).map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
        validate_trusted_directory(&path)?;
        let https = path.join("git-remote-https");
        let metadata = fs::metadata(https).map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(GitProcessPolicyError::InvalidToolLayout);
        }
        Ok(path)
    }

    fn validate_trusted_directory(path: &Path) -> Result<(), GitProcessPolicyError> {
        let canonical =
            fs::canonicalize(path).map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
        let mut current = canonical.as_path();
        loop {
            let metadata =
                fs::metadata(current).map_err(|_| GitProcessPolicyError::InvalidToolLayout)?;
            if !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(GitProcessPolicyError::InvalidToolLayout);
            }
            let Some(parent) = current.parent() else {
                break;
            };
            if parent == current {
                break;
            }
            current = parent;
        }
        Ok(())
    }

    fn validate_ssh_auth_socket(path: PathBuf) -> Result<PathBuf, GitProcessPolicyError> {
        if !is_absolute_normal(&path) {
            return Err(GitProcessPolicyError::InvalidSshAgent);
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| GitProcessPolicyError::InvalidSshAgent)?;
        let parent = path
            .parent()
            .ok_or(GitProcessPolicyError::InvalidSshAgent)?;
        let parent_metadata =
            fs::metadata(parent).map_err(|_| GitProcessPolicyError::InvalidSshAgent)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != parent_metadata.uid()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o077 != 0
        {
            return Err(GitProcessPolicyError::InvalidSshAgent);
        }
        Ok(path)
    }

    fn canonical_directory(path: &Path) -> Result<PathBuf, GitProcessPolicyError> {
        if !is_absolute_normal(path) {
            return Err(GitProcessPolicyError::InvalidProcessDirectory);
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|_| GitProcessPolicyError::InvalidProcessDirectory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(GitProcessPolicyError::InvalidProcessDirectory);
        }
        fs::canonicalize(path).map_err(|_| GitProcessPolicyError::InvalidProcessDirectory)
    }

    fn canonical_private_directory(path: &Path) -> Result<PathBuf, GitProcessPolicyError> {
        let path = canonical_directory(path)?;
        let metadata =
            fs::metadata(&path).map_err(|_| GitProcessPolicyError::InvalidProcessDirectory)?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(GitProcessPolicyError::InvalidProcessDirectory);
        }
        Ok(path)
    }

    fn private_directory_owner(path: &Path) -> Result<u32, GitProcessPolicyError> {
        fs::metadata(path)
            .map(|metadata| metadata.uid())
            .map_err(|_| GitProcessPolicyError::InvalidProcessDirectory)
    }

    fn hash_retained_file(file: &File) -> Result<String, GitProcessPolicyError> {
        let metadata = file
            .metadata()
            .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
        if metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
            return Err(GitProcessPolicyError::InvalidExecutable);
        }
        let mut reader = file
            .try_clone()
            .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut total = 0_u64;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(
                    u64::try_from(read).map_err(|_| GitProcessPolicyError::ExecutableReadFailed)?,
                )
                .ok_or(GitProcessPolicyError::ExecutableReadFailed)?;
            if total > MAX_EXECUTABLE_BYTES {
                return Err(GitProcessPolicyError::InvalidExecutable);
            }
            digest.update(&buffer[..read]);
        }
        if total != metadata.len() {
            return Err(GitProcessPolicyError::ExecutableReadFailed);
        }
        Ok(hex::encode(digest.finalize()))
    }

    fn is_absolute_normal(path: &Path) -> bool {
        path.is_absolute()
            && path
                .components()
                .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::OsStr;
        use std::os::unix::fs::DirBuilderExt as _;
        use std::os::unix::net::UnixListener;

        use super::*;

        fn system_toolchain() -> Option<UnixGitToolchain> {
            match UnixGitToolchain::new(TRUSTED_GIT) {
                Ok(toolchain) => Some(toolchain),
                Err(GitProcessPolicyError::InvalidToolLayout) => None,
                Err(error) => panic!("system toolchain: {error:?}"),
            }
        }

        fn process_context(root: &Path) -> GitProcessContext {
            for name in ["home", "xdg", "tmp"] {
                let mut builder = fs::DirBuilder::new();
                builder
                    .mode(0o700)
                    .create(root.join(name))
                    .expect("private directory");
            }
            GitProcessContext::new(
                root,
                None,
                root.join("home"),
                root.join("xdg"),
                root.join("tmp"),
            )
            .expect("process context")
        }

        #[test]
        fn process_policy_clears_ambient_git_proxy_credential_and_ssh_settings() {
            if !Path::new(TRUSTED_GIT).is_file() || !Path::new(TRUSTED_SSH).is_file() {
                return;
            }
            let Some(toolchain) = system_toolchain() else {
                return;
            };
            let temporary = tempfile::tempdir().expect("fixture");
            for name in ["home", "xdg", "tmp"] {
                let mut builder = fs::DirBuilder::new();
                builder
                    .mode(0o700)
                    .create(temporary.path().join(name))
                    .expect("private directory");
            }
            let context = GitProcessContext::new(
                temporary.path(),
                None,
                temporary.path().join("home"),
                temporary.path().join("xdg"),
                temporary.path().join("tmp"),
            )
            .expect("process context");
            for network in [
                GitNetworkPolicy::Offline,
                GitNetworkPolicy::HttpsWithCredentialManager,
            ] {
                let spec = toolchain
                    .process_spec(&context, network, ["version"])
                    .expect("process spec");
                for forbidden in [
                    "HOME_FROM_CALLER",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "NO_PROXY",
                    "SSH_AUTH_SOCK",
                    "GIT_SSH_COMMAND",
                    "GIT_ASKPASS",
                    "SSH_ASKPASS",
                    "GIT_CONFIG_COUNT",
                    "GIT_CONFIG_PARAMETERS",
                    "GIT_OBJECT_DIRECTORY",
                    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                    "GIT_PROXY_COMMAND",
                    "GCM_HTTP_PROXY",
                    "GCM_CREDENTIAL_STORE",
                    "GCM_PROVIDER",
                    "GCM_TRACE",
                ] {
                    assert!(!spec.environment().contains_key(OsStr::new(forbidden)));
                }
                assert_eq!(
                    spec.environment().get(OsStr::new("PATH")),
                    Some(&OsString::from("/usr/bin:/bin"))
                );
                assert_eq!(
                    spec.environment().get(OsStr::new("GIT_ALLOW_PROTOCOL")),
                    Some(&OsString::from(match network {
                        GitNetworkPolicy::Offline => "",
                        GitNetworkPolicy::HttpsWithCredentialManager => "https",
                        GitNetworkPolicy::GithubSsh => "ssh",
                    }))
                );
                assert_eq!(
                    spec.environment().get(OsStr::new("GIT_NO_LAZY_FETCH")),
                    Some(&OsString::from("1"))
                );
                assert!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "protocol.allow=never")
                );
                assert!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "credential.helper=")
                );
                assert_eq!(
                    spec.arguments()
                        .iter()
                        .any(|argument| argument == "http.proxy="),
                    network == GitNetworkPolicy::HttpsWithCredentialManager
                );
            }
        }

        #[test]
        fn git_ssh_command_uses_the_retained_unix_image() {
            if !Path::new(TRUSTED_GIT).is_file()
                || !Path::new(TRUSTED_SSH).is_file()
                || !Path::new(TRUSTED_SHELL).exists()
            {
                return;
            }
            let temporary = tempfile::tempdir().expect("fixture");
            let agent_directory = temporary.path().join("agent");
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&agent_directory)
                .expect("private agent directory");
            let agent_path = agent_directory.join("agent.sock");
            let _agent = UnixListener::bind(&agent_path).expect("fixture agent socket");
            let Some(mut toolchain) = system_toolchain() else {
                return;
            };
            toolchain.ssh_auth_sock = Some(agent_path);
            let context = process_context(temporary.path());

            let ssh_spec = toolchain
                .process_spec(
                    &context,
                    GitNetworkPolicy::GithubSsh,
                    [
                        "-c",
                        r#"alias.rustferry-ssh-version=!eval "$GIT_SSH_COMMAND -V""#,
                        "rustferry-ssh-version",
                    ],
                )
                .expect("SSH process spec");
            let selected_ssh = ssh_spec
                .command()
                .expect("sealed Git command")
                .output()
                .expect("Git shell SSH version");
            let retained_ssh = Command::new(TRUSTED_SSH)
                .arg("-V")
                .output()
                .expect("retained SSH version");
            assert!(selected_ssh.status.success());
            assert_eq!(selected_ssh.stderr, retained_ssh.stderr);
            toolchain.verify().expect("unchanged retained Unix chain");
        }

        #[test]
        fn git_shell_command_uses_the_retained_unix_image() {
            if !Path::new(TRUSTED_GIT).is_file()
                || !Path::new(TRUSTED_SSH).is_file()
                || !Path::new(TRUSTED_SHELL).exists()
            {
                return;
            }
            let temporary = tempfile::tempdir().expect("fixture");
            let Some(toolchain) = system_toolchain() else {
                return;
            };
            let context = process_context(temporary.path());

            #[cfg(target_os = "linux")]
            {
                let shell_spec = toolchain
                    .process_spec(
                        &context,
                        GitNetworkPolicy::Offline,
                        [
                            "-c",
                            r"alias.rustferry-shell=!readlink /proc/$$/exe",
                            "rustferry-shell",
                        ],
                    )
                    .expect("shell process spec");
                let selected_shell = shell_spec
                    .command()
                    .expect("sealed Git command")
                    .output()
                    .expect("Git shell image");
                assert!(selected_shell.status.success());
                assert_eq!(
                    Path::new(
                        std::str::from_utf8(&selected_shell.stdout)
                            .expect("shell path UTF-8")
                            .trim()
                    ),
                    fs::canonicalize(TRUSTED_SHELL)
                        .expect("canonical retained shell")
                        .as_path()
                );
            }
            #[cfg(target_os = "macos")]
            {
                let shell_spec = toolchain
                    .process_spec(
                        &context,
                        GitNetworkPolicy::Offline,
                        [
                            "-c",
                            r#"alias.rustferry-shell=!observed=$(/bin/ps -p $$ -o command=); printf '%s\n' "$observed""#,
                            "rustferry-shell",
                        ],
                    )
                    .expect("shell process spec");
                let selected_shell = shell_spec
                    .command()
                    .expect("sealed Git command")
                    .output()
                    .expect("Git shell image");
                assert!(selected_shell.status.success());
                let observed = std::str::from_utf8(&selected_shell.stdout)
                    .expect("shell name UTF-8")
                    .split_whitespace()
                    .next()
                    .expect("shell command path");
                assert_eq!(Path::new(observed), Path::new(TRUSTED_SHELL));
            }
            toolchain.verify().expect("unchanged retained Unix chain");
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn fixed_bin_sh_entry_is_accepted_when_it_is_a_root_owned_symlink() {
            let metadata = fs::symlink_metadata(TRUSTED_SHELL).expect("fixed shell entry");
            assert_eq!(
                metadata.uid(),
                0,
                "fixed shell entry must remain root-owned"
            );
            let retained =
                RetainedUnixExecutable::open(Path::new(TRUSTED_SHELL), Path::new(TRUSTED_SHELL))
                    .expect("fixed root-owned shell entry");
            retained.verify().expect("unchanged retained shell target");
        }
    }
}

#[cfg(unix)]
pub use unix::{
    GitProcessContext, GitProcessPolicyError, GitProcessSpec, UnixGitToolchain,
    trusted_git_executable,
};
