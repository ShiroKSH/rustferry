//! Security and determinism tests for remote source snapshot planning.

use std::{
    fs::{self, File},
    io::Write,
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_remote::source::{
    IgnoreRuleReason, MAX_SOURCE_TRAVERSAL_ENTRIES, PortablePathReason, SourceArchive,
    SourceArchiveLimits, SourceBundleRequest, SourceError, SourceLimitKind, SourceLimits,
    SourceManifest, SourceManifestEntry, SourceMode, create_source_bundle_archive,
    plan_source_bundle, validate_source_manifest, verify_and_extract_source_bundle,
    verify_materialized_bundle, verify_source_bundle_plan, verify_source_manifest,
};
use rustferry_remote::{
    MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES, SOURCE_BUNDLE_DESCRIPTOR_SCHEMA_VERSION,
    SourceBundleDescriptor, write_source_bundle_descriptor_file,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zip::{CompressionMethod, DateTime, ZipWriter, write::SimpleFileOptions};

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
fn source_bundle_descriptor_binds_and_validates_archive_and_manifest() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/main.rs"), b"fn main() {}\n");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let archive_path = fixture.workspace.join("source.zip");
    let archive =
        create_source_bundle_archive(&plan, &archive_path, SourceArchiveLimits::default()).unwrap();
    let descriptor = SourceBundleDescriptor::new(archive.clone(), plan.manifest().clone());

    assert_eq!(
        descriptor.schema_version,
        SOURCE_BUNDLE_DESCRIPTOR_SCHEMA_VERSION
    );
    assert_eq!(descriptor.archive, archive);
    assert_eq!(&descriptor.manifest, plan.manifest());
    descriptor.validate(SourceArchiveLimits::default()).unwrap();
}

#[test]
fn source_bundle_descriptor_strictly_rejects_invalid_envelope_fields() {
    let fixture = Fixture::new();
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let valid = SourceBundleDescriptor::new(
        SourceArchive {
            size: 1,
            sha256: "a".repeat(64),
        },
        plan.manifest().clone(),
    );

    let mut unsupported = valid.clone();
    unsupported.schema_version += 1;
    assert!(matches!(
        unsupported.validate(SourceArchiveLimits::default()),
        Err(SourceError::InvalidArchive { .. })
    ));

    let mut empty = valid.clone();
    empty.archive.size = 0;
    assert!(matches!(
        empty.validate(SourceArchiveLimits::default()),
        Err(SourceError::InvalidArchive { .. })
    ));

    let mut malformed_digest = valid.clone();
    malformed_digest.archive.sha256 = "A".repeat(64);
    assert!(matches!(
        malformed_digest.validate(SourceArchiveLimits::default()),
        Err(SourceError::InvalidArchive { .. })
    ));

    let limits = SourceArchiveLimits {
        max_archive_size: 0,
        ..SourceArchiveLimits::default()
    };
    assert!(matches!(
        valid.validate(limits),
        Err(SourceError::LimitExceeded {
            kind: SourceLimitKind::ArchiveSize,
            maximum: 0,
            actual: 1,
            ..
        })
    ));

    let mut invalid_manifest = valid;
    invalid_manifest.manifest.total_size += 1;
    assert!(matches!(
        invalid_manifest.validate(SourceArchiveLimits::default()),
        Err(SourceError::InvalidManifest { .. })
    ));
}

#[test]
fn source_bundle_descriptor_json_is_strict_and_round_trips() {
    let fixture = Fixture::new();
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let descriptor = SourceBundleDescriptor::new(
        SourceArchive {
            size: 1,
            sha256: "a".repeat(64),
        },
        plan.manifest().clone(),
    );
    let encoded = serde_json::to_value(&descriptor).unwrap();
    assert_eq!(
        serde_json::from_value::<SourceBundleDescriptor>(encoded.clone()).unwrap(),
        descriptor
    );

    let mut unknown_top_level = encoded.clone();
    unknown_top_level
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<SourceBundleDescriptor>(unknown_top_level).is_err());

    let mut unknown_archive_field = encoded;
    unknown_archive_field["archive"]
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    assert!(serde_json::from_value::<SourceBundleDescriptor>(unknown_archive_field).is_err());
}

#[test]
fn source_bundle_descriptor_file_is_deterministic_and_create_only() {
    let fixture = Fixture::new();
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let descriptor = SourceBundleDescriptor::new(
        SourceArchive {
            size: 1,
            sha256: "a".repeat(64),
        },
        plan.manifest().clone(),
    );
    let root = fixture.workspace.parent().unwrap();
    let first = root.join("first.manifest.json");
    let second = root.join("second.manifest.json");
    let limits = SourceArchiveLimits::default();

    write_source_bundle_descriptor_file(&descriptor, &first, limits).unwrap();
    write_source_bundle_descriptor_file(&descriptor, &second, limits).unwrap();
    let first_bytes = fs::read(&first).unwrap();
    assert_eq!(first_bytes, fs::read(&second).unwrap());
    assert_eq!(first_bytes.last(), Some(&b'\n'));
    assert!(first_bytes.len() as u64 <= MAX_SOURCE_BUNDLE_DESCRIPTOR_BYTES);
    let mut expected = serde_json::to_vec_pretty(&descriptor).unwrap();
    expected.push(b'\n');
    assert_eq!(first_bytes, expected);

    assert!(matches!(
        write_source_bundle_descriptor_file(&descriptor, &first, limits),
        Err(SourceError::OutputExists { .. })
    ));
    assert_eq!(fs::read(&first).unwrap(), expected);
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".rustferry-partial-")
    }));
}

#[cfg(unix)]
#[test]
fn source_bundle_descriptor_file_does_not_replace_a_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let descriptor = SourceBundleDescriptor::new(
        SourceArchive {
            size: 1,
            sha256: "a".repeat(64),
        },
        plan.manifest().clone(),
    );
    let root = fixture.workspace.parent().unwrap();
    let target = root.join("sentinel.json");
    let output = root.join("linked.manifest.json");
    write(&target, b"unchanged");
    symlink(&target, &output).unwrap();

    assert!(matches!(
        write_source_bundle_descriptor_file(&descriptor, &output, SourceArchiveLimits::default()),
        Err(SourceError::OutputExists { .. })
    ));
    assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    assert!(
        fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink()
    );
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
fn workspace_exclusions_are_portable_and_override_selected_roots() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/main.rs"), b"fn main() {}");
    write(&fixture.workspace.join("shared/kept.txt"), b"kept");
    write(
        &fixture.workspace.join("shared/unreachable/private.txt"),
        b"not selected",
    );

    let request = fixture
        .request()
        .include_workspace_path("shared")
        .include_workspace_path("missing-but-excluded")
        .exclude_workspace_path("shared/unreachable/deeper")
        .exclude_workspace_path("shared/unreachable")
        .exclude_workspace_path("missing-but-excluded");
    assert_eq!(
        request.workspace_exclusions(),
        &[
            Utf8PathBuf::from("shared/unreachable/deeper"),
            Utf8PathBuf::from("shared/unreachable"),
            Utf8PathBuf::from("missing-but-excluded"),
        ]
    );

    let plan = plan_source_bundle(&request).unwrap();
    let selected = paths(plan.manifest());
    assert!(selected.contains(&"shared/kept.txt"));
    assert!(!selected.contains(&"shared/unreachable/private.txt"));
}

#[test]
fn workspace_exclusions_reject_the_root_and_non_portable_paths() {
    let cases = [
        (".", PortablePathReason::DotComponent),
        ("/absolute", PortablePathReason::Absolute),
        ("../outside", PortablePathReason::DotComponent),
        ("safe\\outside", PortablePathReason::Backslash),
    ];

    for (path, expected_reason) in cases {
        let fixture = Fixture::new();
        let error =
            plan_source_bundle(&fixture.request().exclude_workspace_path(path)).unwrap_err();
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
fn workspace_exclusions_precede_excluded_ignore_policy_files() {
    let fixture = Fixture::new();
    write(&fixture.workspace.join(".ferryignore"), b"*.pem\n");
    write(&fixture.project.join(".ferryignore"), b"!keep.rs\n");
    write(&fixture.project.join("src/lib.rs"), b"safe");

    let plan = plan_source_bundle(
        &fixture
            .request()
            .exclude_workspace_path(".ferryignore")
            .exclude_workspace_path("app/.ferryignore"),
    )
    .unwrap();
    assert!(paths(plan.manifest()).contains(&"app/src/lib.rs"));
    assert!(!paths(plan.manifest()).contains(&".ferryignore"));
    assert!(!paths(plan.manifest()).contains(&"app/.ferryignore"));
}

#[test]
fn sensitive_exclusions_are_case_insensitive_and_non_overridable() {
    let fixture = Fixture::new();
    write(&fixture.project.join(".env"), b"TOKEN=secret");
    write(&fixture.project.join("TARGET/cache.bin"), b"cache");
    write(&fixture.project.join("Signing/key.P12"), b"secret");
    write(&fixture.project.join(".cargo/credentials.toml"), b"token");
    write(&fixture.project.join(".ssh/deploy"), b"private key");
    write(&fixture.project.join("credentials/token.txt"), b"token");
    write(&fixture.project.join("src/lib.rs"), b"safe");

    let plan = plan_source_bundle(&fixture.request()).unwrap();
    assert!(paths(plan.manifest()).contains(&"app/src/lib.rs"));
    assert!(paths(plan.manifest()).iter().all(|path| {
        !path.to_lowercase().contains("secret")
            && !path.to_lowercase().contains("target")
            && !path.to_lowercase().contains("signing")
            && !path.to_lowercase().contains("credentials")
            && !path.to_lowercase().contains(".ssh")
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
fn sensitive_exclusion_audit_is_sorted_exact_and_does_not_traverse_roots() {
    let fixture = Fixture::new();
    write(&fixture.project.join(".env"), b"TOKEN=secret");
    write(&fixture.project.join(".git-credentials"), b"secret");
    write(
        &fixture.project.join("application_default_credentials.json"),
        b"secret",
    );
    write(&fixture.project.join("credentials.json"), b"secret");
    write(&fixture.project.join("credentials.yaml"), b"secret");
    write(&fixture.project.join("credentials.yml"), b"secret");
    write(
        &fixture.project.join("credentials/nested/private.txt"),
        b"secret",
    );
    write(
        &fixture.project.join("config/credentials.txt"),
        b"ordinary project data",
    );
    write(&fixture.project.join("src/lib.rs"), b"safe");

    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let excluded = plan
        .excluded_sensitive_paths()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        excluded,
        vec![
            "app/.env",
            "app/.git-credentials",
            "app/application_default_credentials.json",
            "app/credentials",
            "app/credentials.json",
            "app/credentials.yaml",
            "app/credentials.yml",
        ]
    );
    assert!(paths(plan.manifest()).contains(&"app/config/credentials.txt"));
    assert!(!excluded.iter().any(|path| path.contains("nested")));
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
        ("COM¹/file", PortablePathReason::ReservedName),
        ("com².txt", PortablePathReason::ReservedName),
        ("COM³", PortablePathReason::ReservedName),
        ("lpt¹/file", PortablePathReason::ReservedName),
        ("LPT².txt", PortablePathReason::ReservedName),
        ("LPT³.log", PortablePathReason::ReservedName),
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
fn traversal_entry_limit_bounds_empty_directory_breadth() {
    let fixture = Fixture::new();
    for index in 0..8 {
        fs::create_dir(fixture.project.join(format!("empty-{index}"))).unwrap();
    }

    let error = plan_source_bundle(&fixture.request().with_max_traversal_entries(4)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::TraversalEntryCount,
            maximum: 4,
            actual: 5,
            ..
        }
    ));

    let error = plan_source_bundle(
        &fixture
            .request()
            .with_max_traversal_entries(MAX_SOURCE_TRAVERSAL_ENTRIES + 1),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::UnsupportedTraversalLimit {
            requested,
            maximum,
        } if requested == MAX_SOURCE_TRAVERSAL_ENTRIES + 1
            && maximum == MAX_SOURCE_TRAVERSAL_ENTRIES
    ));
}

#[test]
fn traversal_entry_limit_combines_enumeration_and_final_manifest_path_nodes() {
    let fixture = Fixture::new();

    let error = plan_source_bundle(&fixture.request().with_max_traversal_entries(5)).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::TraversalEntryCount,
            maximum: 5,
            actual: 6,
            ..
        }
    ));

    let plan = plan_source_bundle(&fixture.request().with_max_traversal_entries(6)).unwrap();
    validate_source_manifest(plan.manifest(), SourceLimits::default()).unwrap();

    let error = plan_source_bundle(
        &fixture
            .request()
            .exclude_workspace_path("missing")
            .exclude_workspace_path("missing")
            .exclude_workspace_path("missing")
            .with_max_traversal_entries(2),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::TraversalEntryCount,
            maximum: 2,
            actual: 3,
            ..
        }
    ));
}

#[test]
fn manifest_path_node_traversal_is_bounded() {
    let prefix = (0..63)
        .map(|index| format!("d{index}"))
        .collect::<Vec<_>>()
        .join("/");
    let entry_count = MAX_SOURCE_TRAVERSAL_ENTRIES / 64 + 1;
    let mut entries = (0..entry_count)
        .map(|index| SourceManifestEntry {
            path: format!("{prefix}/f{index:05}"),
            size: 0,
            sha256: "0".repeat(64),
            executable: false,
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = SourceManifest {
        schema_version: 1,
        project_path: ".".to_owned(),
        entries,
        total_size: 0,
        sha256: "0".repeat(64),
    };

    assert!(matches!(
        validate_source_manifest(&manifest, SourceLimits::default()),
        Err(SourceError::LimitExceeded {
            kind: SourceLimitKind::TraversalEntryCount,
            maximum,
            ..
        }) if maximum == MAX_SOURCE_TRAVERSAL_ENTRIES as u64
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
    let request = fixture
        .request()
        .with_executable_mode("app/build.sh", false);
    let plan = plan_source_bundle(&request).unwrap();
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
fn portable_executable_metadata_is_strict_and_survives_archive_roundtrip() {
    let fixture = Fixture::new();
    let script = fixture.project.join("build.sh");
    write(&script, b"#!/bin/sh\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&script, permissions).unwrap();
    }

    let request = fixture.request().with_executable_mode("app/build.sh", true);
    let plan = plan_source_bundle(&request).unwrap();
    let entry = plan
        .manifest()
        .entries
        .iter()
        .find(|entry| entry.path == "app/build.sh")
        .unwrap();
    assert!(entry.executable);
    verify_source_bundle_plan(&plan).unwrap();

    let archive = fixture
        .workspace
        .parent()
        .unwrap()
        .join("portable-mode.zip");
    let destination = fixture.workspace.parent().unwrap().join("portable-mode");
    let limits = SourceArchiveLimits::default();
    let archive_descriptor = create_source_bundle_archive(&plan, &archive, limits).unwrap();
    verify_and_extract_source_bundle(
        &archive,
        &archive_descriptor,
        plan.manifest(),
        &destination,
        limits,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(
            fs::metadata(destination.join("app/build.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }

    write(&fixture.workspace.join("unselected.sh"), b"#!/bin/sh\n");
    let error = plan_source_bundle(
        &fixture
            .request()
            .with_executable_mode("unselected.sh", true),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::ExecutableModePathNotSelected { ref path }
            if path == "unselected.sh"
    ));

    let error = plan_source_bundle(
        &fixture
            .request()
            .with_executable_mode("app/build.sh", true)
            .with_executable_mode("app/build.sh", true),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SourceError::DuplicateExecutableMode { ref path } if path == "app/build.sh"
    ));

    let error = plan_source_bundle(&fixture.request().with_executable_mode("C:/build.sh", true))
        .unwrap_err();
    assert!(matches!(
        error,
        SourceError::NonPortablePath {
            reason: PortablePathReason::DrivePrefix,
            ..
        }
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

fn descriptor(path: &Utf8Path) -> SourceArchive {
    let bytes = fs::read(path).unwrap();
    let digest = Sha256::digest(&bytes);
    let mut sha256 = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut sha256, "{byte:02x}").unwrap();
    }
    SourceArchive {
        size: bytes.len() as u64,
        sha256,
    }
}

fn fixed_options(executable: bool) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .compression_level(None)
        .last_modified_time(DateTime::default())
        .unix_permissions(if executable { 0o755 } else { 0o644 })
        .large_file(false)
}

enum CraftedEntry<'a> {
    File(&'a str, &'a [u8], bool),
    FileMode(&'a str, &'a [u8], u32),
    Deflated(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
}

fn craft_zip(path: &Utf8Path, entries: &[CraftedEntry<'_>]) -> SourceArchive {
    let file = File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    for entry in entries {
        match entry {
            CraftedEntry::File(name, contents, executable) => {
                writer.start_file(name, fixed_options(*executable)).unwrap();
                writer.write_all(contents).unwrap();
            }
            CraftedEntry::FileMode(name, contents, mode) => {
                writer
                    .start_file(name, fixed_options(false).unix_permissions(*mode))
                    .unwrap();
                writer.write_all(contents).unwrap();
            }
            CraftedEntry::Deflated(name, contents) => {
                let options = fixed_options(false)
                    .compression_method(CompressionMethod::Deflated)
                    .compression_level(Some(9));
                writer.start_file(name, options).unwrap();
                writer.write_all(contents).unwrap();
            }
            CraftedEntry::Symlink(name, target) => {
                writer
                    .add_symlink(name, target, fixed_options(false))
                    .unwrap();
            }
        }
    }
    writer.finish().unwrap().sync_all().unwrap();
    descriptor(path)
}

#[test]
fn source_zip_is_byte_deterministic_and_no_clobber() {
    let fixture = Fixture::new();
    write(
        &fixture.project.join("src/lib.rs"),
        b"pub fn deterministic() {}",
    );
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let first = fixture.workspace.parent().unwrap().join("first.zip");
    let second = fixture.workspace.parent().unwrap().join("second.zip");
    let limits = SourceArchiveLimits::default();
    let first_descriptor = create_source_bundle_archive(&plan, &first, limits).unwrap();
    let second_descriptor = create_source_bundle_archive(&plan, &second, limits).unwrap();
    assert_eq!(first_descriptor, second_descriptor);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

    let original = fs::read(&first).unwrap();
    assert!(matches!(
        create_source_bundle_archive(&plan, &first, limits),
        Err(SourceError::OutputExists { .. })
    ));
    assert_eq!(fs::read(&first).unwrap(), original);
    let partial_prefix = ".first.zip.rustferry-partial-";
    assert!(fs::read_dir(first.parent().unwrap()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(partial_prefix)
    }));
}

#[test]
fn source_zip_roundtrip_is_exact() {
    let fixture = Fixture::new();
    write(
        &fixture.project.join("src/lib.rs"),
        b"pub fn roundtrip() {}",
    );
    write(&fixture.project.join("assets/data.bin"), &[0, 1, 2, 3, 255]);
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let archive = fixture.workspace.parent().unwrap().join("source.zip");
    let destination = fixture.workspace.parent().unwrap().join("extracted");
    let limits = SourceArchiveLimits::default();
    let expected_archive = create_source_bundle_archive(&plan, &archive, limits).unwrap();
    let actual_archive = verify_and_extract_source_bundle(
        &archive,
        &expected_archive,
        plan.manifest(),
        &destination,
        limits,
    )
    .unwrap();
    assert_eq!(actual_archive, expected_archive);
    verify_materialized_bundle(&destination, plan.manifest(), limits.source).unwrap();
    assert_eq!(
        fs::read(destination.join("app/src/lib.rs")).unwrap(),
        b"pub fn roundtrip() {}"
    );
}

#[test]
fn extraction_destination_is_never_overwritten() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/lib.rs"), b"source");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let archive = fixture.workspace.parent().unwrap().join("source.zip");
    let destination = fixture.workspace.parent().unwrap().join("existing");
    fs::create_dir(&destination).unwrap();
    write(&destination.join("sentinel"), b"keep");
    let limits = SourceArchiveLimits::default();
    let archive_descriptor = create_source_bundle_archive(&plan, &archive, limits).unwrap();
    assert!(matches!(
        verify_and_extract_source_bundle(
            &archive,
            &archive_descriptor,
            plan.manifest(),
            &destination,
            limits
        ),
        Err(SourceError::DestinationExists { .. })
    ));
    assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep");
}

#[test]
fn changed_source_aborts_archive_without_output() {
    let fixture = Fixture::new();
    let source = fixture.project.join("src/lib.rs");
    write(&source, b"before");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    write(&source, b"after!");
    let archive = fixture.workspace.parent().unwrap().join("changed.zip");
    assert!(matches!(
        create_source_bundle_archive(&plan, &archive, SourceArchiveLimits::default()),
        Err(SourceError::ManifestMismatch)
    ));
    assert!(!archive.exists());
}

#[test]
fn archive_size_limit_stops_writes_before_the_complete_zip_is_materialized() {
    let fixture = Fixture::new();
    let source_size = 1024 * 1024;
    write(
        &fixture.project.join("src/large.bin"),
        &vec![0x5a; source_size],
    );
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let archive = fixture.workspace.parent().unwrap().join("bounded.zip");
    let maximum = 128 * 1024;
    let limits = SourceArchiveLimits {
        max_archive_size: maximum,
        ..SourceArchiveLimits::default()
    };

    let error = create_source_bundle_archive(&plan, &archive, limits).unwrap_err();
    assert!(matches!(
        error,
        SourceError::LimitExceeded {
            kind: SourceLimitKind::ArchiveSize,
            maximum: observed_maximum,
            actual,
            ..
        } if observed_maximum == maximum && actual > maximum && actual < source_size as u64
    ));
    assert!(!archive.exists());
    let partial_prefix = ".bounded.zip.rustferry-partial-";
    assert!(
        fs::read_dir(archive.parent().unwrap())
            .unwrap()
            .all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(partial_prefix)
            })
    );
}

#[test]
fn corrupt_archive_and_wrong_manifest_leave_no_destination() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/lib.rs"), b"AAAA");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let archive = fixture.workspace.parent().unwrap().join("source.zip");
    let limits = SourceArchiveLimits::default();
    let expected_archive = create_source_bundle_archive(&plan, &archive, limits).unwrap();
    let mut bytes = fs::read(&archive).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x55;
    fs::write(&archive, bytes).unwrap();
    let corrupt_destination = fixture.workspace.parent().unwrap().join("corrupt");
    assert!(matches!(
        verify_and_extract_source_bundle(
            &archive,
            &expected_archive,
            plan.manifest(),
            &corrupt_destination,
            limits
        ),
        Err(SourceError::ArchiveIntegrityMismatch { .. })
    ));
    assert!(!corrupt_destination.exists());

    let second = Fixture::new();
    write(&second.project.join("src/lib.rs"), b"BBBB");
    let wrong_plan = plan_source_bundle(&second.request()).unwrap();
    let fresh_archive = fixture.workspace.parent().unwrap().join("fresh.zip");
    let fresh_descriptor = create_source_bundle_archive(&plan, &fresh_archive, limits).unwrap();
    let wrong_destination = fixture.workspace.parent().unwrap().join("wrong");
    assert!(matches!(
        verify_and_extract_source_bundle(
            &fresh_archive,
            &fresh_descriptor,
            wrong_plan.manifest(),
            &wrong_destination,
            limits
        ),
        Err(SourceError::ManifestMismatch)
    ));
    assert!(!wrong_destination.exists());
}

#[test]
fn malicious_zip_paths_links_and_collisions_are_rejected_pre_extraction() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/lib.rs"), b"safe");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let limits = SourceArchiveLimits::default();

    let attacks = [
        vec![CraftedEntry::File("../escape", b"bad", false)],
        vec![CraftedEntry::File("C:/escape", b"bad", false)],
        vec![CraftedEntry::File("app\\escape", b"bad", false)],
        vec![CraftedEntry::Symlink("app/src/lib.rs", "../../escape")],
        vec![CraftedEntry::FileMode("app/src/lib.rs", b"safe", 0o777)],
        vec![
            CraftedEntry::File("app/Foo.rs", b"a", false),
            CraftedEntry::File("app/foo.rs", b"b", false),
        ],
        vec![
            CraftedEntry::File("app/Caf\u{e9}.rs", b"a", false),
            CraftedEntry::File("app/Cafe\u{301}.rs", b"b", false),
        ],
    ];

    for (index, entries) in attacks.iter().enumerate() {
        let archive = fixture
            .workspace
            .parent()
            .unwrap()
            .join(format!("attack-{index}.zip"));
        let archive_descriptor = craft_zip(&archive, entries);
        let destination = fixture
            .workspace
            .parent()
            .unwrap()
            .join(format!("attack-{index}"));
        assert!(
            verify_and_extract_source_bundle(
                &archive,
                &archive_descriptor,
                plan.manifest(),
                &destination,
                limits
            )
            .is_err()
        );
        assert!(!destination.exists());
        assert!(!fixture.workspace.parent().unwrap().join("escape").exists());
    }
}

#[test]
fn zip_bomb_ratio_and_missing_or_extra_entries_are_rejected() {
    let fixture = Fixture::new();
    write(&fixture.project.join("src/lib.rs"), b"safe");
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let root = fixture.workspace.parent().unwrap();

    let bomb = root.join("bomb.zip");
    let bomb_bytes = vec![0_u8; 64 * 1024];
    let bomb_descriptor = craft_zip(
        &bomb,
        &[CraftedEntry::Deflated("app/src/lib.rs", &bomb_bytes)],
    );
    let limits = SourceArchiveLimits {
        max_compression_ratio: 2,
        ..SourceArchiveLimits::default()
    };
    assert!(matches!(
        verify_and_extract_source_bundle(
            &bomb,
            &bomb_descriptor,
            plan.manifest(),
            &root.join("bomb"),
            limits
        ),
        Err(SourceError::LimitExceeded {
            kind: SourceLimitKind::CompressionRatio,
            ..
        })
    ));

    for (name, entries) in [
        ("missing", Vec::new()),
        (
            "extra",
            vec![CraftedEntry::File("other/safe.rs", b"safe", false)],
        ),
    ] {
        let archive = root.join(format!("{name}.zip"));
        let archive_descriptor = craft_zip(&archive, &entries);
        let destination = root.join(name);
        assert!(matches!(
            verify_and_extract_source_bundle(
                &archive,
                &archive_descriptor,
                plan.manifest(),
                &destination,
                SourceArchiveLimits::default()
            ),
            Err(SourceError::ManifestMismatch)
        ));
        assert!(!destination.exists());
    }
}

#[cfg(unix)]
#[test]
fn extraction_ancestor_swap_never_writes_through_attacker_symlink() {
    use std::{os::unix::fs::symlink, thread, time::Instant};

    let fixture = Fixture::new();
    write(
        &fixture.project.join("src/large.bin"),
        &vec![0x5a; 32 * 1024 * 1024],
    );
    write(
        &fixture.project.join("zz-after.txt"),
        b"must stay contained",
    );
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let root = fixture.workspace.parent().unwrap();
    let archive = root.join("ancestor-swap.zip");
    let destination = root.join("ancestor-swap");
    let outside = root.join("outside");
    fs::create_dir(&outside).unwrap();
    write(&outside.join("sentinel"), b"unchanged");
    let limits = SourceArchiveLimits::default();
    let archive_descriptor = create_source_bundle_archive(&plan, &archive, limits).unwrap();

    let watched_file = destination.join("app/src/large.bin");
    let displaced = destination.join("app-owned");
    let destination_for_attacker = destination.clone();
    let outside_for_attacker = outside.clone();
    let attacker = thread::spawn(move || {
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while !watched_file.exists() {
            assert!(
                Instant::now() < deadline,
                "extraction did not reach watched file"
            );
            thread::yield_now();
        }
        fs::rename(destination_for_attacker.join("app"), &displaced).unwrap();
        symlink(&outside_for_attacker, destination_for_attacker.join("app")).unwrap();
    });

    let result = verify_and_extract_source_bundle(
        &archive,
        &archive_descriptor,
        plan.manifest(),
        &destination,
        limits,
    );
    attacker.join().unwrap();

    assert!(result.is_err());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
    assert!(!outside.join("zz-after.txt").exists());
    assert!(!destination.exists());
}

#[cfg(unix)]
#[test]
fn archive_parent_swap_never_publishes_into_replacement_directory() {
    use std::{sync::mpsc, thread, time::Instant};

    let fixture = Fixture::new();
    write(
        &fixture.project.join("src/large.bin"),
        &vec![0xa5; 32 * 1024 * 1024],
    );
    let plan = plan_source_bundle(&fixture.request()).unwrap();
    let root = fixture.workspace.parent().unwrap();
    let output_parent = root.join("publish-parent");
    let moved_parent = root.join("publish-parent-owned");
    fs::create_dir(&output_parent).unwrap();
    let output = output_parent.join("source.zip");

    let watched_parent = output_parent.clone();
    let replacement_parent = output_parent.clone();
    let moved_parent_for_attacker = moved_parent.clone();
    let (ready_sender, ready_receiver) = mpsc::sync_channel(0);
    let attacker = thread::spawn(move || {
        ready_sender.send(()).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let partial_exists = fs::read_dir(&watched_parent).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".source.zip.rustferry-partial-")
            });
            if partial_exists {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "archive creation did not expose its private temporary file"
            );
            thread::yield_now();
        }
        fs::rename(&watched_parent, &moved_parent_for_attacker).unwrap();
        fs::create_dir(&replacement_parent).unwrap();
        write(&replacement_parent.join("sentinel"), b"unchanged");
    });

    ready_receiver.recv().unwrap();
    let result = create_source_bundle_archive(&plan, &output, SourceArchiveLimits::default());
    attacker.join().unwrap();

    assert!(result.is_err());
    assert_eq!(
        fs::read(output_parent.join("sentinel")).unwrap(),
        b"unchanged"
    );
    assert!(!output.exists());
    assert!(fs::read_dir(&moved_parent).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".source.zip.rustferry-partial-")
    }));
}
