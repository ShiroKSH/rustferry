use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;

use crate::cli::{CleanArgs, CleanScope};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

#[derive(Debug, Serialize)]
struct CleanResult {
    project: String,
    removed: Vec<String>,
    absent: Vec<String>,
    dry_run: bool,
}

pub fn run(arguments: &CleanArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let ferry_root = root.join("target/ferry");
    let targets = clean_targets(&ferry_root, arguments.scope, arguments.all);
    let mut removed = Vec::new();
    let mut absent = Vec::new();
    for target in targets {
        if !target.exists() {
            absent.push(target.to_string());
            continue;
        }
        validate_clean_target(&ferry_root, &target)?;
        if !dry_run {
            fs::remove_dir_all(&target).map_err(|source| CliError::Io {
                action: "remove generated output",
                path: target.clone(),
                source,
            })?;
        }
        removed.push(target.to_string());
    }
    let result = CleanResult {
        project: root.to_string(),
        removed,
        absent,
        dry_run,
    };
    reporter.success(
        "clean",
        &result,
        || {
            if result.removed.is_empty() {
                "✓ No matching generated output exists".to_owned()
            } else if dry_run {
                format!("Clean plan:\n  {}", result.removed.join("\n  "))
            } else {
                format!(
                    "✓ Removed generated output\n\n  {}",
                    result.removed.join("\n  ")
                )
            }
        },
        &[],
    );
    Ok(())
}

fn clean_targets(root: &Utf8Path, scope: Option<CleanScope>, all: bool) -> Vec<Utf8PathBuf> {
    if all {
        return vec![root.to_owned()];
    }
    match scope {
        Some(CleanScope::Android) => vec![root.join("android")],
        Some(CleanScope::Ios) => vec![root.join("ios")],
        Some(CleanScope::Generated) => vec![
            root.join("android/debug/generated"),
            root.join("android/release/generated"),
            root.join("ios/generated"),
            root.join("generated"),
        ],
        None => vec![
            root.join("android"),
            root.join("ios"),
            root.join("generated"),
        ],
    }
}

fn validate_clean_target(root: &Utf8Path, target: &Utf8Path) -> Result<(), CliError> {
    if !root.ends_with("target/ferry") || target == root.parent().unwrap_or(root) {
        return Err(CliError::UnsafeCleanPath {
            path: target.to_owned(),
        });
    }
    for boundary in [root.parent().unwrap_or(root), root] {
        let metadata = fs::symlink_metadata(boundary).map_err(|source| CliError::Io {
            action: "inspect generated-output boundary",
            path: boundary.to_owned(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CliError::UnsafeCleanPath {
                path: boundary.to_owned(),
            });
        }
    }
    let canonical_root = root.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve generated-output root",
        path: root.to_owned(),
        source,
    })?;
    let canonical_target = target.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve clean target",
        path: target.to_owned(),
        source,
    })?;
    if !canonical_target.starts_with(&canonical_root) {
        return Err(CliError::UnsafeCleanPath {
            path: target.to_owned(),
        });
    }
    Ok(())
}
