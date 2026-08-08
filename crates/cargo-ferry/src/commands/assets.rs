use camino::{Utf8Path, Utf8PathBuf};
use serde::Serialize;

use crate::cli::{AssetsArgs, AssetsCommand, GenerateAssetsArgs};
use crate::error::CliError;
use crate::output::Reporter;
use crate::project::find_project_root;

#[derive(Debug, Serialize)]
struct AssetGenerationPlan {
    project: Utf8PathBuf,
    fingerprint: String,
    expected_root: Utf8PathBuf,
    release_ready: bool,
}

pub fn run(arguments: AssetsArgs, dry_run: bool, reporter: &Reporter) -> Result<(), CliError> {
    match arguments.command {
        AssetsCommand::Check(arguments) => {
            let root = find_project_root(arguments.project_dir.as_deref())?;
            let checked = rustferry_codegen::check_project_assets(&root)?;
            if !checked.release_ready {
                return Err(rustferry_codegen::AssetPipelineError::NotReleaseReady {
                    issues: checked.issues,
                }
                .into());
            }
            reporter.success(
                "assets check",
                &checked,
                || {
                    format!(
                        "✓ Assets are release-ready\n\nIcon:\n  {}x{}, alpha={}\n\nSplash:\n  {}x{}\n\nFingerprint:\n  {}",
                        checked.icon.width,
                        checked.icon.height,
                        checked.icon.has_alpha,
                        checked.splash.width,
                        checked.splash.height,
                        checked.fingerprint,
                    )
                },
                &[],
            );
            Ok(())
        }
        AssetsCommand::Generate(arguments) => generate(arguments, dry_run, reporter),
    }
}

fn generate(
    arguments: GenerateAssetsArgs,
    dry_run: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    let root = find_project_root(arguments.project_dir.as_deref())?;
    let source = arguments.source.map(|source| resolve_source(&root, source));
    if dry_run {
        if source.is_some() {
            return Err(CliError::Unsupported {
                message: "custom asset sources cannot be fully validated without generation"
                    .to_owned(),
                help: "Run `cargo ferry assets generate --source PATH`, or omit --source for a non-mutating plan."
                    .to_owned(),
            });
        }
        let checked = rustferry_codegen::check_project_assets(&root)?;
        if !checked.release_ready {
            return Err(rustferry_codegen::AssetPipelineError::NotReleaseReady {
                issues: checked.issues,
            }
            .into());
        }
        let plan = AssetGenerationPlan {
            expected_root: root.join("target/ferry/assets").join(&checked.fingerprint),
            project: root,
            fingerprint: checked.fingerprint,
            release_ready: true,
        };
        reporter.success(
            "assets generate",
            &plan,
            || {
                format!(
                    "Asset generation plan\n\nExpected root:\n  {}\n\nFingerprint:\n  {}",
                    plan.expected_root, plan.fingerprint
                )
            },
            &[],
        );
        return Ok(());
    }

    let generated = rustferry_codegen::generate_platform_assets(&root, source.as_deref())?;
    reporter.success(
        "assets generate",
        &generated,
        || {
            format!(
                "✓ Generated platform assets\n\nRoot:\n  {}\n\nFiles:\n  {}\n\nCache:\n  {}",
                generated.root,
                generated.files.len(),
                if generated.cache_hit { "hit" } else { "miss" },
            )
        },
        &[],
    );
    Ok(())
}

fn resolve_source(root: &Utf8Path, source: Utf8PathBuf) -> Utf8PathBuf {
    if source.is_absolute() {
        source
    } else {
        root.join(source)
    }
}
