//! Canonical GitHub Git endpoints and one-shot local remote discovery.

use std::{error::Error, ffi::OsString, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::transport::Repository;

const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_DISCOVERY_BYTES: usize = 16 * 1024;

/// Git transport selected by a validated GitHub endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GithubGitTransport {
    /// Credential-free HTTPS URL authenticated separately by Git Credential Manager.
    Https,
    /// Canonical `git@github.com` SSH transport.
    Ssh,
}

/// A canonical, credential-free GitHub.com Git endpoint.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GithubGitEndpoint {
    repository: Repository,
    transport: GithubGitTransport,
    canonical_url: String,
}

impl GithubGitEndpoint {
    /// Parse a conservative GitHub.com HTTPS or SSH endpoint.
    ///
    /// # Errors
    ///
    /// Rejects credentials, non-GitHub hosts, ports, percent escapes, query/fragment syntax,
    /// extra path components, Unicode, and malformed repository identities.
    pub fn parse(value: &str) -> Result<Self, GithubGitEndpointError> {
        if value.is_empty()
            || value.len() > MAX_ENDPOINT_BYTES
            || !value.is_ascii()
            || value.trim() != value
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b'?' | b'#' | b'%' | b'\\'))
        {
            return Err(GithubGitEndpointError::InvalidSyntax);
        }

        let (transport, path) = if let Some(path) = value.strip_prefix("https://github.com/") {
            (GithubGitTransport::Https, path)
        } else if let Some(path) = value.strip_prefix("git@github.com:") {
            (GithubGitTransport::Ssh, path)
        } else if let Some(path) = value.strip_prefix("ssh://git@github.com/") {
            (GithubGitTransport::Ssh, path)
        } else {
            return Err(GithubGitEndpointError::UnsupportedTransport);
        };

        let path = path.strip_suffix('/').unwrap_or(path);
        if path.ends_with('/') {
            return Err(GithubGitEndpointError::InvalidSyntax);
        }
        let path = path.strip_suffix(".git").unwrap_or(path);
        let (owner, name) = path
            .split_once('/')
            .ok_or(GithubGitEndpointError::InvalidRepository)?;
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(GithubGitEndpointError::InvalidRepository);
        }
        let owner = owner.to_ascii_lowercase();
        let name = name.to_ascii_lowercase();
        let repository = Repository::new(owner.clone(), name.clone())
            .map_err(|_| GithubGitEndpointError::InvalidRepository)?;
        let canonical_url = match transport {
            GithubGitTransport::Https => format!("https://github.com/{owner}/{name}"),
            GithubGitTransport::Ssh => format!("git@github.com:{owner}/{name}"),
        };
        Ok(Self {
            repository,
            transport,
            canonical_url,
        })
    }

    /// Exact normalized GitHub repository identity.
    pub const fn repository(&self) -> &Repository {
        &self.repository
    }

    /// Selected network transport.
    pub const fn transport(&self) -> GithubGitTransport {
        self.transport
    }

    /// Canonical credential-free URL rendered by `RustFerry` rather than copied from Git config.
    pub fn canonical_url(&self) -> &str {
        &self.canonical_url
    }

    /// Canonical lowercase `owner/repository` slug.
    pub fn repository_slug(&self) -> String {
        format!("{}/{}", self.repository.owner(), self.repository.name())
    }
}

impl fmt::Display for GithubGitEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.canonical_url())
    }
}

impl Serialize for GithubGitEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.canonical_url())
    }
}

impl<'de> Deserialize<'de> for GithubGitEndpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let endpoint = Self::parse(&value).map_err(D::Error::custom)?;
        if endpoint.canonical_url() != value {
            return Err(D::Error::custom("GitHub Git endpoint is not canonical"));
        }
        Ok(endpoint)
    }
}

/// Stable GitHub endpoint validation failure without echoing untrusted URL text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubGitEndpointError {
    /// Endpoint syntax or byte repertoire is unsafe.
    InvalidSyntax,
    /// Scheme, host, user, or SSH form is unsupported.
    UnsupportedTransport,
    /// Owner/repository path is malformed.
    InvalidRepository,
}

impl fmt::Display for GithubGitEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSyntax => formatter.write_str("GitHub Git endpoint syntax is invalid"),
            Self::UnsupportedTransport => {
                formatter.write_str("GitHub Git endpoint transport is unsupported")
            }
            Self::InvalidRepository => {
                formatter.write_str("GitHub Git endpoint repository is invalid")
            }
        }
    }
}

impl Error for GithubGitEndpointError {}

/// Conservative local Git remote name used only during one-shot discovery.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GitRemoteName(String);

impl GitRemoteName {
    /// Validate a local remote name that can be embedded in an anchored Git-config key regex.
    ///
    /// # Errors
    ///
    /// Rejects empty, option-like, long, control, regex, ref, and path syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, GitRemoteDiscoveryError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || value.starts_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(GitRemoteDiscoveryError::InvalidRemoteName);
        }
        Ok(Self(value))
    }

    /// Validated name as configured locally.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Fixed argument vector for a single local, no-include config snapshot.
    pub fn discovery_arguments(&self) -> Vec<OsString> {
        let escaped = self.0.replace('.', "\\.");
        vec![
            OsString::from("config"),
            OsString::from("--local"),
            OsString::from("--no-includes"),
            OsString::from("-z"),
            OsString::from("--get-regexp"),
            OsString::from(format!("^remote\\.{escaped}\\.(url|pushurl)$")),
        ]
    }
}

/// Frozen effective fetch/push endpoints from one local remote-config read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubRemoteSnapshot {
    fetch: GithubGitEndpoint,
    push: GithubGitEndpoint,
}

impl GithubRemoteSnapshot {
    /// Bind already parsed canonical fetch and push endpoints.
    ///
    /// # Errors
    ///
    /// Rejects endpoints that identify different GitHub repositories.
    pub fn new(
        fetch: GithubGitEndpoint,
        push: GithubGitEndpoint,
    ) -> Result<Self, GitRemoteDiscoveryError> {
        if fetch.repository() != push.repository() {
            return Err(GitRemoteDiscoveryError::RepositoryMismatch);
        }
        Ok(Self { fetch, push })
    }

    /// Parse one `git config --local --no-includes -z --get-regexp` response.
    ///
    /// Git emits each matching key and value as `key\nvalue\0`. Exactly one URL is required;
    /// zero or one push URL is accepted, with an absent push URL inheriting the fetch URL.
    /// Multiple values fail closed instead of using Git's URL selection rules.
    ///
    /// # Errors
    ///
    /// Rejects oversized/malformed output, missing or duplicate values, unexpected keys, unsafe
    /// endpoints, or differing fetch/push repository identities.
    pub fn from_local_config_output(
        remote: &GitRemoteName,
        output: &[u8],
    ) -> Result<Self, GitRemoteDiscoveryError> {
        if output.is_empty() || output.len() > MAX_DISCOVERY_BYTES || !output.ends_with(&[0]) {
            return Err(GitRemoteDiscoveryError::MalformedOutput);
        }
        let fetch_key = format!("remote.{}.url", remote.as_str());
        let push_key = format!("remote.{}.pushurl", remote.as_str());
        let mut fetch_value = None;
        let mut push_value = None;
        let mut records = 0_u8;
        for record in output[..output.len() - 1].split(|byte| *byte == 0) {
            records = records
                .checked_add(1)
                .ok_or(GitRemoteDiscoveryError::MalformedOutput)?;
            if records > 2 || record.is_empty() {
                return Err(GitRemoteDiscoveryError::DuplicateValue);
            }
            let split = record
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or(GitRemoteDiscoveryError::MalformedOutput)?;
            let key = std::str::from_utf8(&record[..split])
                .map_err(|_| GitRemoteDiscoveryError::MalformedOutput)?;
            let value = std::str::from_utf8(&record[split + 1..])
                .map_err(|_| GitRemoteDiscoveryError::MalformedOutput)?;
            if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(GitRemoteDiscoveryError::MalformedOutput);
            }
            if key == fetch_key {
                set_once(&mut fetch_value, value)?;
            } else if key == push_key {
                set_once(&mut push_value, value)?;
            } else {
                return Err(GitRemoteDiscoveryError::UnexpectedKey);
            }
        }
        let fetch =
            GithubGitEndpoint::parse(fetch_value.ok_or(GitRemoteDiscoveryError::MissingFetchUrl)?)
                .map_err(GitRemoteDiscoveryError::Endpoint)?;
        let push = push_value.map_or_else(
            || Ok(fetch.clone()),
            |value| GithubGitEndpoint::parse(value).map_err(GitRemoteDiscoveryError::Endpoint),
        )?;
        Self::new(fetch, push)
    }

    /// Frozen canonical fetch endpoint.
    pub const fn fetch(&self) -> &GithubGitEndpoint {
        &self.fetch
    }

    /// Frozen canonical push endpoint.
    pub const fn push(&self) -> &GithubGitEndpoint {
        &self.push
    }
}

fn set_once<'a>(slot: &mut Option<&'a str>, value: &'a str) -> Result<(), GitRemoteDiscoveryError> {
    if slot.replace(value).is_some() {
        Err(GitRemoteDiscoveryError::DuplicateValue)
    } else {
        Ok(())
    }
}

/// Stable one-shot Git remote-discovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitRemoteDiscoveryError {
    /// Local remote name is unsafe.
    InvalidRemoteName,
    /// Git output framing, size, encoding, or value bytes are invalid.
    MalformedOutput,
    /// Output contained a key outside the exact selected remote.
    UnexpectedKey,
    /// Effective fetch URL is absent.
    MissingFetchUrl,
    /// URL or push URL occurs more than once.
    DuplicateValue,
    /// Endpoint itself is invalid.
    Endpoint(GithubGitEndpointError),
    /// Fetch and push endpoints identify different repositories.
    RepositoryMismatch,
}

impl fmt::Display for GitRemoteDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRemoteName => formatter.write_str("Git remote name is invalid"),
            Self::MalformedOutput => formatter.write_str("Git remote output is malformed"),
            Self::UnexpectedKey => formatter.write_str("Git returned an unexpected remote key"),
            Self::MissingFetchUrl => formatter.write_str("Git remote has no fetch URL"),
            Self::DuplicateValue => formatter.write_str("Git remote has duplicate URL values"),
            Self::Endpoint(error) => write!(formatter, "Git remote endpoint is invalid: {error}"),
            Self::RepositoryMismatch => {
                formatter.write_str("Git remote fetch and push repositories differ")
            }
        }
    }
}

impl Error for GitRemoteDiscoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_accepts_only_canonical_github_transports() {
        for (value, transport, canonical) in [
            (
                "https://github.com/ShiroKSH/RustFerry.git",
                GithubGitTransport::Https,
                "https://github.com/shiroksh/rustferry",
            ),
            (
                "git@github.com:ShiroKSH/RustFerry.git",
                GithubGitTransport::Ssh,
                "git@github.com:shiroksh/rustferry",
            ),
            (
                "ssh://git@github.com/ShiroKSH/RustFerry/",
                GithubGitTransport::Ssh,
                "git@github.com:shiroksh/rustferry",
            ),
        ] {
            let endpoint = GithubGitEndpoint::parse(value).expect("valid endpoint");
            assert_eq!(endpoint.transport(), transport);
            assert_eq!(endpoint.canonical_url(), canonical);
            assert_eq!(endpoint.repository_slug(), "shiroksh/rustferry");
        }
    }

    #[test]
    fn endpoint_serde_accepts_only_its_canonical_string_form() {
        let endpoint = GithubGitEndpoint::parse("git@github.com:owner/repo").expect("endpoint");
        assert_eq!(
            serde_json::to_string(&endpoint).expect("endpoint JSON"),
            r#""git@github.com:owner/repo""#
        );
        assert_eq!(
            serde_json::from_str::<GithubGitEndpoint>(r#""git@github.com:owner/repo""#)
                .expect("canonical endpoint"),
            endpoint
        );
        assert!(
            serde_json::from_str::<GithubGitEndpoint>(r#""ssh://git@github.com/Owner/Repo.git""#)
                .is_err()
        );
    }

    #[test]
    fn endpoint_parser_rejects_credentials_rewrites_and_lookalikes() {
        for value in [
            "http://github.com/owner/repo",
            "https://token@github.com/owner/repo",
            "https://github.example/owner/repo",
            "https://github.com.evil/owner/repo",
            "https://github.com:443/owner/repo",
            "https://github.com/owner/repo/extra",
            "https://github.com/owner/repo?token=value",
            "https://github.com/owner/re%70o",
            "git@github.com:owner/repo -oProxyCommand=evil",
            "git@github.com:owner\\repo",
            "ssh://other@github.com/owner/repo",
            "ssh://git@github.com:22/owner/repo",
            "HTTPS://github.com/owner/repo",
            " https://github.com/owner/repo",
            "https://github.com/owner/répo",
        ] {
            assert!(GithubGitEndpoint::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn discovery_freezes_one_fetch_and_optional_push_url() {
        let remote = GitRemoteName::new("origin").expect("remote");
        let output = b"remote.origin.url\nhttps://github.com/Owner/Repo.git\0remote.origin.pushurl\ngit@github.com:owner/repo.git\0";
        let snapshot = GithubRemoteSnapshot::from_local_config_output(&remote, output)
            .expect("remote snapshot");
        assert_eq!(snapshot.fetch().transport(), GithubGitTransport::Https);
        assert_eq!(snapshot.push().transport(), GithubGitTransport::Ssh);
        assert_eq!(snapshot.fetch().repository(), snapshot.push().repository());

        let inherited = GithubRemoteSnapshot::from_local_config_output(
            &remote,
            b"remote.origin.url\nhttps://github.com/owner/repo\0",
        )
        .expect("inherited push URL");
        assert_eq!(inherited.fetch(), inherited.push());
    }

    #[test]
    fn discovery_rejects_duplicate_and_cross_repository_values() {
        let remote = GitRemoteName::new("origin").expect("remote");
        for (output, expected) in [
            (
                b"remote.origin.url\nhttps://github.com/owner/repo\0remote.origin.url\nhttps://github.com/owner/repo\0"
                    .as_slice(),
                GitRemoteDiscoveryError::DuplicateValue,
            ),
            (
                b"remote.origin.url\nhttps://github.com/owner/repo\0remote.origin.pushurl\nhttps://github.com/attacker/repo\0"
                    .as_slice(),
                GitRemoteDiscoveryError::RepositoryMismatch,
            ),
            (
                b"remote.origin.url\nhttps://github.com/owner/repo\0remote.other.pushurl\nhttps://github.com/owner/repo\0"
                    .as_slice(),
                GitRemoteDiscoveryError::UnexpectedKey,
            ),
        ] {
            assert_eq!(
                GithubRemoteSnapshot::from_local_config_output(&remote, output),
                Err(expected)
            );
        }
    }

    #[test]
    fn discovery_arguments_disable_includes_in_one_local_read() {
        let remote = GitRemoteName::new("safe.remote").expect("remote");
        let arguments = remote.discovery_arguments();
        assert_eq!(
            arguments,
            [
                "config",
                "--local",
                "--no-includes",
                "-z",
                "--get-regexp",
                "^remote\\.safe\\.remote\\.(url|pushurl)$",
            ]
            .map(OsString::from)
        );
    }
}
