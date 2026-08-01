//! Security and determinism tests for remote source snapshot planning.

use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_remote::source::{
    IgnoreRuleReason, PortablePathReason, SourceBundleRequest, SourceError, SourceLimitKind,
    SourceLimits, SourceManifest, SourceManifestEntry, SourceMode, create_source_bundle_archive,
    plan_source_bundle, validate_source_manifest, verify_materialized_bundle,
    verify_source_bundle_plan, verify_source_manifest,
};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    workspace: Utf8PathBuf,
    project: Utf8PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("temporary directory");
        let workspace =
            Utf8PathBuf::from_path_buf(temp.path().join("workspace")).expect("UTF-8 temp path");
        let project = workspace.join("app");
        fs::create_dir_all(project.join("src")).expect("create project");
        write(&workspace.join("Cargo.toml"), b"[workspace]\n");
        write(&workspace.join("Cargo.lock"), b"");
        write(&project.join("Cargo.toml"), b"[package]\nname = \"app\"\n");
        Self {
            _temp: temp,
            workspace,
            project,
        }
    }

    fn request(&self) -> SourceBundleRequest {
        SourceBundleRequest::new(self.workspace.clone(), self.project.clone())
    }
}

fn write(path: &Utf8Path, contents: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, contents).expect("write fixture");
}

fn paths(manifest: &SourceManifest) -> Vec<&str> {
    manifest
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect()
}

#[test]
fn source_mode_has_canonical_wire_values() {
    assert_eq!(serde_json::to_string(&SourceMode::Git).unwrap(), "\"git\"");
    assert_eq!(
        serde_json::to_string(&SourceMode::Snapshot).unwrap(),
        "\"snapshot\""
    );
    assert!(SourceMode::Git < SourceMode::Snapshot);
}

#[test]
fn manifest_is_sorted_deterministic_and_uses_slash_paths() {
    let fixture = Fixture::new();
    write(&fixture.project.join("zeta.rs"), b"z");
    write(&fixture.project.join("src/alpha.rs"), b"alpha");

    let first = plan_source_bundle(&fixture.request()).unwrap();
    let second = plan_source_bundle(&fixture.request()).unwrap();

    assert_eq!(first.manifest(), second.manifest());
    assert_eq!(
        paths(first.manifest()),
        vec![
            "Cargo.lock",
            "Cargo.toml",
            "app/Cargo.toml",
            "app/src/alpha.rs",
            "app/zeta.rs"
        ]
    );
    assert!(
        first
            .manifest()
            .entries
            .iter()
            .all(|entry| !entry.path.contains('\\'))
    );
    assert_eq!(first.manifest().sha256.len(), 64);
    validate_source_manifest(first.manifest(), SourceLimits::default()).unwrap();
}

#[test]
fn project_and_explicit_workspace_inputs_are_the_only_source_roots() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/main.rs"), b"fn main() {}");
    write(
        &fixture.workspace.join("unrelated/private.txt"),
        b"not selected",
    );
    write(
        &fixture.workspace.join("shared/src/lib.rs"),
        b"pub fn shared() {}",
    );

    let base = plan_source_bundle(&fixture.request()).unwrap();
    assert!(!paths(base.manifest()).contains(&"unrelated/private.txt"));
    assert!(!paths(base.manifest()).contains(&"shared/src/lib.rs"));

    let included = plan_source_bundle(
        &fixture
            .request()
            .include_workspace_path("shared/src/lib.rs"),
    )
    .unwrap();
    assert!(paths(included.manifest()).contains(&"shared/src/lib.rs"));
    assert!(!paths(included.manifest()).contains(&"unrelated/private.txt"));
}

#[test]
fn sensitive_exclusions_are_case_insensitive_and_non_overridable() {
    let fixture = Fixture::new();
    write(&fixture.project.join(".env"), b"TOKEN=secret");
    write(&fixture.project.join("TARGET/cache.bin"), b"cache");
    write(&fixture.project.join("Signing/key.P12"), b"secret");
    write(&fixture.project.join(".cargo/credentials.toml"), b"token");
    write(&fixture.project.join("src/lib.rs"), b"safe");

    let plan = plan_source_bundle(&fixture.request()).unwrap();
    assert!(paths(plan.manifest()).contains(&"app/src/lib.rs"));
    assert!(paths(plan.manifest()).iter().all(|path| {
        !path.to_lowercase().contains("secret")
            && !path.to_lowercase().contains("target")
            && !path.to_lowercase().contains("signing")
            && !path.to_lowercase().contains("credentials")
            && !path
                .split('/')
                .next_back()
                .is_some_and(|name| name.eq_ignore_ascii_case(".env"))
    }));

    write(&fixture.workspace.join(".env"), b"TOKEN=secret");
    let error = plan_source_bundle(&fixture.request().include_workspace_path(".env")).unwrap_err();
    assert!(matches!(error, SourceError::SensitivePath { .. }));
}

#[test]
fn ferryignore_literal_subset_is_scoped_and_deterministic() {
    let fixture = Fixture::new();
    write(
        &fixture.workspace.join(".ferryignore"),
        b"# workspace rule\napp/workspace-ignored.txt\n",
    );
    write(
        &fixture.project.join(".ferryignore"),
        b"ignored.txt\ncache/\r\n",
    );
    write(&fixture.project.join("ignored.txt"), b"ignored");
    write(&fixture.project.join("workspace-ignored.txt"), b"ignored");
    write(&fixture.project.join("cache/nested.bin"), b"ignored");
    write(&fixture.project.join("src/kept.rs"), b"kept");

    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let selected = paths(plan.manifest());
    assert!(selected.contains(&"app/.ferryignore"));
    assert!(selected.contains(&"app/src/kept.rs"));
    assert!(!selected.contains(&"app/ignored.txt"));
    assert!(!selected.contains(&"app/workspace-ignored.txt"));
    assert!(!selected.contains(&"app/cache/nested.bin"));
}

#[test]
fn ferryignore_rejects_ambiguous_or_powerful_syntax() {
    let cases = [
        ("!keep.rs\n", IgnoreRuleReason::Negation),
        ("*.pem\n", IgnoreRuleReason::Glob),
        (" leading\n", IgnoreRuleReason::EdgeWhitespace),
        (
            "../escape\n",
            IgnoreRuleReason::NonPortable(PortablePathReason::DotComponent),
        ),
        (
            "/absolute\n",
            IgnoreRuleReason::NonPortable(PortablePathReason::Absolute),
        ),
    ];

    for (contents, expected_reason) in cases {
        let fixture = Fixture::new();
        write(&fixture.project.join(".ferryignore"), contents.as_bytes());
        let error = plan_source_bundle(&fixture.request()).unwrap_err();
        assert!(
            matches!(
                error,
                SourceError::InvalidIgnoreRule { reason, .. } if reason == expected_reason
            ),
            "{contents:?}: {error:?}"
        );
    }
}

#[test]
fn explicit_inputs_reject_cross_platform_escape_forms() {
    let cases = [
        ("/absolute", PortablePathReason::Absolute),
        ("C:/Windows/System32", PortablePathReason::DrivePrefix),
        ("//server/share", PortablePathReason::UncPrefix),
        ("../outside", PortablePathReason::DotComponent),
        ("safe\\outside", PortablePathReason::Backslash),
        ("CON/file", PortablePathReason::ReservedName),
        ("dir/trailing.", PortablePathReason::TrailingDotOrSpace),
        ("safe/\u{202e}hidden", PortablePathReason::InvalidCharacter),
    ];

    for (path, expected_reason) in cases {
        let fixture = Fixture::new();
        let error =
            plan_source_bundle(&fixture.request().include_workspace_path(path)).unwrap_err();
        assert!(
            matches!(
                error,
                SourceError::NonPortablePath { reason, .. } if reason == expected_reason
            ),
            "{path:?}: {error:?}"
        );
    }
}

#[test]
fn manifest_rejects_case_and_unicode_normalization_collisions() {
    for colliding_paths in [
        ["app/Foo.rs", "app/foo.rs"],
        ["app/Caf\u{e9}.rs", "app/Cafe\u{301}.rs"],
        ["app/Foo/one.rs", "app/foo/two.rs"],
    ] {
        let mut entries: Vec<_> = colliding_paths
            .into_iter()
            .map(|path| SourceManifestEntry {
                path: path.to_owned(),
                size: 0,
                sha256: "0".repeat(64),
                executable: false,
            })
            .collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = SourceManifest {
            schema_version: 1,
            project_path: "app".to_owned(),
            entries,
            total_size: 0,
            sha256: "0".repeat(64),
        };
        assert!(matches!(
            validate_source_manifest(&manifest, SourceLimits::default()),
            Err(SourceError::CaseCollision { .. })
        ));
    }
}

#[test]
fn unicode_names_are_retained_in_the_manifest() {
    let fixture = Fixture::new();
    write(
        &fixture.project.join("src/caf\u{e9}.rs"),
        b"pub const CAFE: bool = true;",
    );
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    assert!(paths(plan.manifest()).contains(&"app/src/caf\u{e9}.rs"));
}

#[cfg(unix)]
#[test]
fn symlinks_and_symlinked_explicit_ancestors_are_rejected() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let outside = fixture.workspace.parent().unwrap().join("outside");
    fs::create_dir_all(&outside).unwrap();
    write(&outside.join("secret.txt"), b"outside");
    symlink(&outside, fixture.project.join("escape")).unwrap();
    assert!(matches!(
        plan_source_bundle(&fixture.request()),
        Err(SourceError::Symlink { .. })
    ));

    fs::remove_file(fixture.project.join("escape")).unwrap();
    symlink(&outside, fixture.workspace.join("linked")).unwrap();
    assert!(matches!(
        plan_source_bundle(
            &fixture
                .request()
                .include_workspace_path("linked/secret.txt")
        ),
        Err(SourceError::Symlink { .. })
    ));
}

#[cfg(unix)]
#[test]
fn hard_links_are_rejected() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/one.rs"), b"same inode");
    fs::hard_link(
        fixture.project.join("src/one.rs"),
        fixture.project.join("src/two.rs"),
    )
    .unwrap();
    assert!(matches!(
        plan_source_bundle(&fixture.request()),
        Err(SourceError::HardLink { links: 2, .. })
    ));
}

#[test]
fn file_count_size_total_and_depth_limits_are_enforced() {
    let fixture = Fixture::new();
    write(&fixture.project.join("big.bin"), b"1234");
    let limits = SourceLimits {
        max_file_size: 3,
        ..SourceLimits::default()
    };
    let error = plan_source_bundle(&fixture.request().with_limits(limits)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::FileSize,
            ..
        }
    ));

    let fixture = Fixture::new();
    write(&fixture.project.join("one"), b"12");
    write(&fixture.project.join("two"), b"34");
    let limits = SourceLimits {
        max_total_size: 3,
        ..SourceLimits::default()
    };
    let error = plan_source_bundle(&fixture.request().with_limits(limits)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::TotalSize,
            ..
        }
    ));

    let fixture = Fixture::new();
    let limits = SourceLimits {
        max_file_count: 1,
        ..SourceLimits::default()
    };
    let error = plan_source_bundle(&fixture.request().with_limits(limits)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::FileCount,
            ..
        }
    ));

    let fixture = Fixture::new();
    write(&fixture.project.join("src/deep/file.rs"), b"deep");
    let limits = SourceLimits {
        max_depth: 3,
        ..SourceLimits::default()
    };
    let error = plan_source_bundle(&fixture.request().with_limits(limits)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::Depth,
            ..
        }
    ));
}

#[test]
fn exact_verification_detects_add_change_and_delete() {
    let fixture = Fixture::new();
    let source = fixture.project.join("src/lib.rs");
    write(&source, b"original");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    verify_source_bundle_plan(&plan).unwrap();

    write(&fixture.project.join("src/added.rs"), b"added");
    assert!(matches!(
        verify_source_bundle_plan(&plan),
        Err(SourceError::ManifestMismatch)
    ));
    fs::remove_file(fixture.project.join("src/added.rs")).unwrap();

    write(&source, b"changed!");
    assert!(matches!(
        verify_source_manifest(&fixture.request(), plan.manifest()),
        Err(SourceError::ManifestMismatch)
    ));

    fs::remove_file(&source).unwrap();
    assert!(matches!(
        verify_source_manifest(&fixture.request(), plan.manifest()),
        Err(SourceError::ManifestMismatch)
    ));
}

#[cfg(unix)]
#[test]
fn executable_bit_is_manifested_and_verified() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let script = fixture.project.join("build.sh");
    write(&script, b"#!/bin/sh\n");
    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).unwrap();
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let entry = plan
        .manifest()
        .entries
        .iter()
        .find(|entry| entry.path == "app/build.sh")
        .unwrap();
    assert!(entry.executable);

    let mut permissions = fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&script, permissions).unwrap();
    assert!(matches!(
        verify_source_bundle_plan(&plan),
        Err(SourceError::ManifestMismatch)
    ));
}

#[test]
fn materialized_bundle_verification_is_exact() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/lib.rs"), b"source");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let bundle = fixture.workspace.parent().unwrap().join("bundle");
    fs::create_dir_all(&bundle).unwrap();
    for file in plan.files() {
        let destination = bundle.join(file.bundle_path());
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(file.source_path(), &destination).unwrap();
    }
    verify_materialized_bundle(&bundle, plan.manifest(), SourceLimits::default()).unwrap();

    fs::create_dir_all(bundle.join("extra/empty")).unwrap();
    assert!(matches!(
        verify_materialized_bundle(&bundle, plan.manifest(), SourceLimits::default()),
        Err(SourceError::ManifestMismatch)
    ));
}

#[test]
fn archive_creation_is_a_typed_no_touch_refusal() {
    let fixture = Fixture::new();
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let output = fixture.workspace.parent().unwrap().join("bundle.tar");
    assert!(matches!(
        create_source_bundle_archive(&plan, &output),
        Err(SourceError::ArchiveCreationUnsupported)
    ));
    assert!(!output.exists());
}
