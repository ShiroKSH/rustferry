//! Native system share-sheet requests.

use crate::runtime::current_runtime;
use crate::{Error, Operation, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

/// Content passed to the platform share sheet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "content")]
pub enum ShareRequest {
    /// Plain text.
    Text(String),
    /// One absolute URL.
    Url(Url),
    /// Files selected by the application.
    Files(Vec<PathBuf>),
}

/// Whether the active backend implements a share sheet.
///
/// # Examples
///
/// ```
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// assert!(rustferry::share::is_supported());
/// ```
pub fn is_supported() -> bool {
    current_runtime().supports(Operation::Share)
}

/// Share plain text.
///
/// # Examples
///
/// ```
/// use rustferry::share::{self, ShareRequest};
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// share::text("Meet me at noon")?;
/// assert_eq!(
///     runtime.share_requests(),
///     [ShareRequest::Text("Meet me at noon".into())]
/// );
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn text(text: impl Into<String>) -> Result<()> {
    dispatch(ShareRequest::Text(text.into()))
}

/// Share an absolute URL.
///
/// # Examples
///
/// ```
/// use rustferry::share::{self, ShareRequest};
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// share::url("https://example.com/guide")?;
/// assert!(matches!(
///     runtime.share_requests().as_slice(),
///     [ShareRequest::Url(url)] if url.as_str() == "https://example.com/guide"
/// ));
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn url(url: impl AsRef<str>) -> Result<()> {
    let url =
        Url::parse(url.as_ref()).map_err(|error| Error::invalid("share URL", error.to_string()))?;
    dispatch(ShareRequest::Url(url))
}

/// Share one or more file paths.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use rustferry::share::{self, ShareRequest};
///
/// # let runtime = rustferry::testing::TestRuntime::new();
/// # let _runtime = runtime.enter();
/// let report = PathBuf::from("report.txt");
/// share::files([report.clone()])?;
/// assert_eq!(runtime.share_requests(), [ShareRequest::Files(vec![report])]);
/// # Ok::<(), rustferry::Error>(())
/// ```
pub fn files(files: impl IntoIterator<Item = PathBuf>) -> Result<()> {
    let files = files.into_iter().collect::<Vec<_>>();
    if files.is_empty() {
        return Err(Error::invalid(
            "share files",
            "at least one file is required",
        ));
    }
    dispatch(ShareRequest::Files(files))
}

fn dispatch(request: ShareRequest) -> Result<()> {
    let runtime = current_runtime();
    runtime.ensure_supported(Operation::Share)?;
    runtime.backend().share(request)
}
