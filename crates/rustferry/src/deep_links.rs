//! Parsing, allowlisting, and delivery of deep links.

use crate::app_events::{self, Subscription};
use crate::runtime::current_runtime;
use crate::{Error, Operation, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use url::Url;

/// A validated absolute deep-link URL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeepLink(Url);

impl DeepLink {
    /// Parse an absolute URL with a non-empty scheme.
    pub fn parse(value: impl AsRef<str>) -> Result<Self> {
        let url = Url::parse(value.as_ref())
            .map_err(|error| Error::invalid("deep link", error.to_string()))?;
        if url.scheme().is_empty() {
            return Err(Error::invalid(
                "deep link",
                "an absolute scheme is required",
            ));
        }
        Ok(Self(url))
    }

    /// Borrow the parsed URL.
    pub const fn url(&self) -> &Url {
        &self.0
    }

    /// URL scheme.
    pub fn scheme(&self) -> &str {
        self.0.scheme()
    }

    /// Optional host.
    pub fn host(&self) -> Option<&str> {
        self.0.host_str()
    }

    /// First non-empty path segment, commonly used as an action.
    pub fn action(&self) -> Option<&str> {
        self.0.path_segments()?.find(|segment| !segment.is_empty())
    }
}

impl fmt::Display for DeepLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Explicit allowlist applied before application routing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeepLinkPolicy {
    schemes: BTreeSet<String>,
    hosts: BTreeSet<String>,
    actions: BTreeSet<String>,
}

impl DeepLinkPolicy {
    /// Create an empty policy. An empty category does not restrict that category.
    pub const fn new() -> Self {
        Self {
            schemes: BTreeSet::new(),
            hosts: BTreeSet::new(),
            actions: BTreeSet::new(),
        }
    }

    /// Allow a URL scheme, compared case-insensitively.
    pub fn allow_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.schemes.insert(scheme.into().to_ascii_lowercase());
        self
    }

    /// Allow a host, compared case-insensitively.
    pub fn allow_host(mut self, host: impl Into<String>) -> Self {
        self.hosts.insert(host.into().to_ascii_lowercase());
        self
    }

    /// Allow a first path segment.
    pub fn allow_action(mut self, action: impl Into<String>) -> Self {
        self.actions.insert(action.into());
        self
    }

    /// Validate a link against every configured category.
    pub fn validate(&self, link: &DeepLink) -> Result<()> {
        if !self.schemes.is_empty() && !self.schemes.contains(link.scheme()) {
            return Err(Error::invalid(
                "deep link scheme",
                "scheme is not allowlisted",
            ));
        }
        if !self.hosts.is_empty()
            && !link
                .host()
                .is_some_and(|host| self.hosts.contains(&host.to_ascii_lowercase()))
        {
            return Err(Error::invalid("deep link host", "host is not allowlisted"));
        }
        if !self.actions.is_empty()
            && !link
                .action()
                .is_some_and(|action| self.actions.contains(action))
        {
            return Err(Error::invalid(
                "deep link action",
                "action is not allowlisted",
            ));
        }
        Ok(())
    }
}

/// Whether cold-start deep-link retrieval is available.
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::DeepLinkInitial)
}

/// Return the link that launched the application, if one was supplied.
pub fn initial() -> Result<Option<DeepLink>> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::DeepLinkInitial)?;
    runtime.backend().deep_link_initial()
}

/// Subscribe to links received while the Rust runtime is alive.
pub fn subscribe(callback: impl Fn(DeepLink) + Send + Sync + 'static) -> Subscription {
    app_events::on_deep_link(callback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_checks_all_configured_components() {
        let policy = DeepLinkPolicy::new()
            .allow_scheme("weather")
            .allow_host("forecast")
            .allow_action("today");
        assert!(
            policy
                .validate(&DeepLink::parse("weather://forecast/today").unwrap())
                .is_ok()
        );
        assert!(
            policy
                .validate(&DeepLink::parse("weather://forecast/admin").unwrap())
                .is_err()
        );
    }
}
