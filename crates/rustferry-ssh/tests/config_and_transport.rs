//! Security and argument-array regression tests for the SSH transport.

use std::{ffi::OsString, fs};

#[cfg(unix)]
use std::{process::Command, sync::mpsc, thread, time::Duration};

use base64::{Engine as _, engine::general_purpose};
use camino::Utf8PathBuf;
use rustferry_remote::CancellationToken;
use rustferry_ssh::{
    MAX_SSH_REQUEST_BYTES, ProcessSshRunner, SSH_OPERATION_TIMEOUT, SSH_SNAPSHOT_SESSION_TIMEOUT,
    SshConfigError, SshEndpointConfig, SshHost, SshHostKeySha256, SshRemoteName, SshRunner,
    SshTransportError, SshUser, build_ssh_invocation, build_ssh_session_invocation,
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

struct EndpointFixture {
    _directory: TempDir,
    config: SshEndpointConfig,
    private_marker: &'static str,
}

fn endpoint_fixture() -> EndpointFixture {
    let directory = tempfile::tempdir().expect("temp directory");
    let known_hosts = directory.path().join("known_hosts");
    let identity = directory.path().join("identity");
    let private_marker = "PRIVATE-KEY-CONTENT-MUST-NOT-LEAK";
    let mut key_blob = Vec::new();
    key_blob.extend_from_slice(&11_u32.to_be_bytes());
    key_blob.extend_from_slice(b"ssh-ed25519");
    key_blob.extend_from_slice(&32_u32.to_be_bytes());
    key_blob.extend_from_slice(&[7_u8; 32]);
    let encoded_key = general_purpose::STANDARD.encode(&key_blob);
    let fingerprint = format!(
        "SHA256:{}",
        general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&key_blob))
    );
    fs::write(
        &known_hosts,
        format!("[mac.example.test]:2222 ssh-ed25519 {encoded_key}\n"),
    )
    .expect("known hosts");
    fs::write(&identity, private_marker).expect("identity reference");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))
            .expect("private identity permissions");
    }
    let config = SshEndpointConfig::new(
        SshRemoteName::new("office-mac").expect("remote name"),
        SshHost::new("mac.example.test").expect("host"),
        SshUser::new("ferry_worker").expect("user"),
        2222,
        Utf8PathBuf::from_path_buf(known_hosts).expect("UTF-8 known-hosts path"),
        SshHostKeySha256::new(fingerprint).expect("host-key fingerprint"),
        Some(Utf8PathBuf::from_path_buf(identity).expect("UTF-8 identity path")),
    )
    .expect("endpoint config");
    EndpointFixture {
        _directory: directory,
        config,
        private_marker,
    }
}

#[test]
fn command_injection_fields_are_rejected() {
    for value in [
        "-proxy",
        "office mac",
        "office;touch",
        "office\nmac",
        "o/mac",
    ] {
        assert!(
            SshRemoteName::new(value).is_err(),
            "accepted name {value:?}"
        );
    }
    for value in [
        "-oProxyCommand=bad",
        "mac;touch",
        "mac example",
        "mac\nexample",
    ] {
        assert!(SshHost::new(value).is_err(), "accepted host {value:?}");
    }
    for value in ["-root", "root@evil", "root;touch", "root example", "root\n"] {
        assert!(SshUser::new(value).is_err(), "accepted user {value:?}");
    }
}

#[test]
fn invocation_is_exact_and_contains_no_shell_escape_hatch() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let arguments = invocation.arguments();
    assert_eq!(invocation.program(), "ssh");
    assert_eq!(invocation.timeout(), SSH_OPERATION_TIMEOUT);
    assert!(arguments.windows(2).any(|pair| pair == ["-F", "none"]));
    for required in [
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "GlobalKnownHostsFile=none",
        "ForwardAgent=no",
        "ClearAllForwardings=yes",
        "RequestTTY=no",
        "PermitLocalCommand=no",
        "ConnectionAttempts=1",
        "ConnectTimeout=15",
        "ServerAliveInterval=10",
        "ServerAliveCountMax=2",
        "IdentitiesOnly=yes",
    ] {
        assert!(
            arguments.iter().any(|argument| argument == required),
            "missing {required}"
        );
    }
    assert_eq!(
        &arguments[arguments.len() - 8..],
        [
            OsString::from("-p"),
            OsString::from("2222"),
            OsString::from("-l"),
            OsString::from("ferry_worker"),
            OsString::from("mac.example.test"),
            OsString::from("ferry-worker-macos"),
            OsString::from("serve"),
            OsString::from("--stdio"),
        ]
    );
    assert!(
        !arguments
            .iter()
            .any(|argument| argument == "sh" || argument == "-c")
    );
}

#[test]
fn snapshot_session_invocation_has_one_fixed_remote_command() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_session_invocation(&fixture.config).expect("session invocation");
    let arguments = invocation.arguments();
    assert_eq!(invocation.timeout(), SSH_SNAPSHOT_SESSION_TIMEOUT);
    assert_eq!(
        &arguments[arguments.len() - 3..],
        [
            OsString::from("ferry-worker-macos"),
            OsString::from("serve"),
            OsString::from("--stdio-session-v1"),
        ]
    );
    assert!(!arguments.iter().any(|argument| argument == "--stdio"));
}

#[test]
fn identity_remains_a_path_reference_and_never_key_content() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let rendered = format!("{invocation:?} {:?}", fixture.config);
    assert!(!rendered.contains(fixture.private_marker));
    assert!(invocation.arguments().iter().any(|argument| {
        argument
            == std::ffi::OsStr::new(
                fixture
                    .config
                    .identity_file()
                    .expect("identity path")
                    .as_str(),
            )
    }));
    assert!(
        !fs::read(invocation.known_hosts_snapshot_path())
            .expect("trust snapshot")
            .windows(fixture.private_marker.len())
            .any(|window| window == fixture.private_marker.as_bytes())
    );
}

#[test]
fn invocation_uses_stable_private_snapshot_instead_of_mutable_trust_path() {
    let fixture = endpoint_fixture();
    let original_path = fixture.config.known_hosts_file().to_owned();
    let original_bytes = fs::read(&original_path).expect("original trust bytes");
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let snapshot_path = invocation.known_hosts_snapshot_path().to_owned();
    let snapshot_directory = snapshot_path.parent().expect("snapshot parent").to_owned();
    let escaped_snapshot_path = snapshot_path
        .to_str()
        .expect("OpenSSH path is UTF-8")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let expected_option = OsString::from(format!("UserKnownHostsFile=\"{escaped_snapshot_path}\""));

    assert_ne!(snapshot_path, original_path.as_std_path());
    assert!(
        invocation
            .arguments()
            .iter()
            .any(|argument| argument == &expected_option)
    );
    assert!(!invocation.arguments().iter().any(|argument| {
        argument == &OsString::from(format!("UserKnownHostsFile={original_path}"))
    }));
    assert_eq!(
        fs::read(&snapshot_path).expect("snapshot bytes"),
        original_bytes
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&snapshot_path)
            .expect("snapshot metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        let directory_mode = fs::metadata(&snapshot_directory)
            .expect("snapshot directory metadata")
            .permissions()
            .mode();
        assert_eq!(directory_mode & 0o077, 0);
    }

    fs::write(
        &original_path,
        "[mac.example.test]:2222 ssh-ed25519 AAAAATTACKER\n",
    )
    .expect("replace mutable original");
    assert_eq!(
        fs::read(&snapshot_path).expect("stable snapshot bytes"),
        original_bytes
    );
    assert!(snapshot_path.exists());
    drop(invocation);
    assert!(!snapshot_path.exists());
    assert!(!snapshot_directory.exists());
}

#[cfg(any(unix, windows))]
#[test]
fn retained_trust_snapshot_detects_path_replacement_before_spawn() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let snapshot_path = invocation.known_hosts_snapshot_path().to_owned();
    fs::remove_file(&snapshot_path).expect("unlink retained trust snapshot path");
    fs::write(
        &snapshot_path,
        "[mac.example.test]:2222 ssh-ed25519 AAAAATTACKER\n",
    )
    .expect("replace trust snapshot path");

    assert_eq!(
        ProcessSshRunner.exchange(&invocation, b"{}\n", &CancellationToken::new()),
        Err(SshTransportError::TrustSnapshotChanged)
    );
}

#[cfg(windows)]
#[test]
fn retained_private_trust_directory_blocks_replacement_on_windows() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let directory = invocation
        .known_hosts_snapshot_path()
        .parent()
        .expect("snapshot parent")
        .to_owned();
    let replacement = directory.with_extension("replacement");

    assert!(fs::rename(&directory, &replacement).is_err());
    drop(invocation);
    assert!(!directory.exists());
    assert!(!replacement.exists());
}

#[test]
fn openssh_path_expansion_syntax_is_rejected() {
    let fixture = endpoint_fixture();
    let known_hosts_with_token = fixture
        .config
        .known_hosts_file()
        .with_file_name("known_hosts-%h");
    fs::write(
        &known_hosts_with_token,
        fs::read(fixture.config.known_hosts_file()).expect("known-hosts bytes"),
    )
    .expect("known-hosts token fixture");
    let known_hosts_result = SshEndpointConfig::new(
        fixture.config.remote_name().clone(),
        fixture.config.host().clone(),
        fixture.config.user().clone(),
        fixture.config.port(),
        known_hosts_with_token,
        fixture.config.host_key_sha256().clone(),
        fixture.config.identity_file().map(ToOwned::to_owned),
    );
    assert_eq!(
        known_hosts_result,
        Err(SshConfigError::UnsafePath {
            field: "known_hosts_file"
        })
    );

    let identity_with_expansion = fixture
        .config
        .identity_file()
        .expect("identity path")
        .with_file_name("identity-${HOME}");
    fs::write(&identity_with_expansion, "private marker").expect("identity token fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&identity_with_expansion, fs::Permissions::from_mode(0o600))
            .expect("identity token permissions");
    }
    let identity_result = SshEndpointConfig::new(
        fixture.config.remote_name().clone(),
        fixture.config.host().clone(),
        fixture.config.user().clone(),
        fixture.config.port(),
        fixture.config.known_hosts_file().to_owned(),
        fixture.config.host_key_sha256().clone(),
        Some(identity_with_expansion),
    );
    assert_eq!(
        identity_result,
        Err(SshConfigError::UnsafePath {
            field: "identity_file"
        })
    );
}

#[test]
fn trust_file_must_be_absolute_nonempty_and_regular() {
    let fixture = endpoint_fixture();
    let result = SshEndpointConfig::new(
        SshRemoteName::new("office-mac").expect("name"),
        SshHost::new("mac.example.test").expect("host"),
        SshUser::new("worker").expect("user"),
        22,
        Utf8PathBuf::from("relative-known-hosts"),
        fixture.config.host_key_sha256().clone(),
        None,
    );
    assert_eq!(
        result,
        Err(SshConfigError::PathNotAbsolute {
            field: "known_hosts_file"
        })
    );
    assert!(fixture.config.validate_files().is_ok());
}

#[cfg(unix)]
#[test]
fn fifo_trust_and_identity_paths_are_rejected_without_blocking() {
    let fixture = endpoint_fixture();
    let trust_fifo = fixture
        .config
        .known_hosts_file()
        .with_file_name("known-hosts-fifo");
    let identity_fifo = fixture
        .config
        .known_hosts_file()
        .with_file_name("identity-fifo");
    for path in [&trust_fifo, &identity_fifo] {
        assert!(
            Command::new("mkfifo")
                .arg(path)
                .status()
                .expect("run mkfifo")
                .success()
        );
    }

    let trust_config = fixture.config.clone();
    let (trust_sender, trust_receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = SshEndpointConfig::new(
            trust_config.remote_name().clone(),
            trust_config.host().clone(),
            trust_config.user().clone(),
            trust_config.port(),
            trust_fifo,
            trust_config.host_key_sha256().clone(),
            None,
        );
        let _ = trust_sender.send(result);
    });
    assert_eq!(
        trust_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("trust FIFO rejection must be bounded"),
        Err(SshConfigError::PathNotRegularFile {
            field: "known_hosts_file"
        })
    );

    let identity_config = fixture.config.clone();
    let (identity_sender, identity_receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = SshEndpointConfig::new(
            identity_config.remote_name().clone(),
            identity_config.host().clone(),
            identity_config.user().clone(),
            identity_config.port(),
            identity_config.known_hosts_file().to_owned(),
            identity_config.host_key_sha256().clone(),
            Some(identity_fifo),
        );
        let _ = identity_sender.send(result);
    });
    assert_eq!(
        identity_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("identity FIFO rejection must be bounded"),
        Err(SshConfigError::PathNotRegularFile {
            field: "identity_file"
        })
    );
}

#[test]
fn pinned_fingerprint_and_exact_single_host_entry_are_required() {
    let fixture = endpoint_fixture();
    let mismatched = format!(
        "SHA256:{}",
        general_purpose::STANDARD_NO_PAD.encode([0_u8; 32])
    );
    let config = SshEndpointConfig::new(
        fixture.config.remote_name().clone(),
        fixture.config.host().clone(),
        fixture.config.user().clone(),
        fixture.config.port(),
        fixture.config.known_hosts_file().to_owned(),
        SshHostKeySha256::new(mismatched).expect("canonical mismatch"),
        fixture.config.identity_file().map(ToOwned::to_owned),
    );
    assert_eq!(config, Err(SshConfigError::InvalidKnownHosts));

    let original = fs::read_to_string(fixture.config.known_hosts_file()).expect("known hosts");
    fs::write(
        fixture.config.known_hosts_file(),
        format!("{original}{original}"),
    )
    .expect("extra host entry");
    assert_eq!(
        fixture.config.validate_files(),
        Err(SshConfigError::InvalidKnownHosts)
    );
}

#[test]
fn hashed_host_tokens_and_noncanonical_fingerprints_are_rejected() {
    assert!(SshHostKeySha256::new("MD5:00:11").is_err());
    assert!(
        SshHostKeySha256::new(format!(
            "SHA256:{}=",
            general_purpose::STANDARD_NO_PAD.encode([1_u8; 32])
        ))
        .is_err()
    );

    let fixture = endpoint_fixture();
    let original = fs::read_to_string(fixture.config.known_hosts_file()).expect("known hosts");
    let (_, suffix) = original.split_once(' ').expect("host token separator");
    fs::write(
        fixture.config.known_hosts_file(),
        format!("|1|salt|hash {suffix}"),
    )
    .expect("hashed host entry");
    assert_eq!(
        fixture.config.validate_files(),
        Err(SshConfigError::InvalidKnownHosts)
    );
}

#[cfg(unix)]
#[test]
fn identity_permissions_reject_group_or_other_access() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = endpoint_fixture();
    let identity = fixture.config.identity_file().expect("identity path");
    fs::set_permissions(identity, fs::Permissions::from_mode(0o644)).expect("weaken permissions");
    assert_eq!(
        fixture.config.validate_files(),
        Err(SshConfigError::IdentityFilePermissions)
    );
}

#[cfg(unix)]
#[test]
fn identity_file_rejects_alternate_hardlink() {
    let fixture = endpoint_fixture();
    let identity = fixture.config.identity_file().expect("identity path");
    fs::hard_link(identity, identity.with_file_name("identity-alternate-link"))
        .expect("identity hardlink");
    assert_eq!(
        fixture.config.validate_files(),
        Err(SshConfigError::IdentityPathPermissions)
    );
}

#[cfg(unix)]
#[test]
fn identity_file_rejects_symlink_path() {
    use std::os::unix::fs::symlink;

    let fixture = endpoint_fixture();
    let identity = fixture.config.identity_file().expect("identity path");
    let identity_symlink = identity.with_file_name("identity-symlink");
    symlink(identity, &identity_symlink).expect("identity symlink");
    let result = SshEndpointConfig::new(
        fixture.config.remote_name().clone(),
        fixture.config.host().clone(),
        fixture.config.user().clone(),
        fixture.config.port(),
        fixture.config.known_hosts_file().to_owned(),
        fixture.config.host_key_sha256().clone(),
        Some(identity_symlink),
    );
    assert!(matches!(
        result,
        Err(SshConfigError::PathUnreadable {
            field: "identity_file"
        } | SshConfigError::PathNotRegularFile {
            field: "identity_file"
        })
    ));
}

#[cfg(unix)]
#[test]
fn identity_path_rejects_replaceable_parent_and_allows_sticky_parent() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = endpoint_fixture();
    let replaceable_parent = fixture
        .config
        .identity_file()
        .expect("identity path")
        .with_file_name("replaceable");
    fs::create_dir(&replaceable_parent).expect("replaceable parent");
    fs::set_permissions(&replaceable_parent, fs::Permissions::from_mode(0o777))
        .expect("replaceable parent permissions");
    let replaceable_identity = replaceable_parent.join("identity");
    fs::write(&replaceable_identity, "private marker").expect("replaceable identity");
    fs::set_permissions(&replaceable_identity, fs::Permissions::from_mode(0o600))
        .expect("replaceable identity permissions");
    let replaceable_result = SshEndpointConfig::new(
        fixture.config.remote_name().clone(),
        fixture.config.host().clone(),
        fixture.config.user().clone(),
        fixture.config.port(),
        fixture.config.known_hosts_file().to_owned(),
        fixture.config.host_key_sha256().clone(),
        Some(replaceable_identity),
    );
    assert_eq!(
        replaceable_result,
        Err(SshConfigError::IdentityPathPermissions)
    );

    let sticky_parent = replaceable_parent.with_file_name("sticky");
    fs::create_dir(&sticky_parent).expect("sticky parent");
    fs::set_permissions(&sticky_parent, fs::Permissions::from_mode(0o1777))
        .expect("sticky parent permissions");
    let sticky_identity = sticky_parent.join("identity");
    fs::write(&sticky_identity, "private marker").expect("sticky identity");
    fs::set_permissions(&sticky_identity, fs::Permissions::from_mode(0o600))
        .expect("sticky identity permissions");
    assert!(
        SshEndpointConfig::new(
            fixture.config.remote_name().clone(),
            fixture.config.host().clone(),
            fixture.config.user().clone(),
            fixture.config.port(),
            fixture.config.known_hosts_file().to_owned(),
            fixture.config.host_key_sha256().clone(),
            Some(sticky_identity),
        )
        .is_ok()
    );
}

#[cfg(unix)]
#[test]
fn retained_identity_handle_detects_replacement_before_spawn() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = endpoint_fixture();
    let identity = fixture
        .config
        .identity_file()
        .expect("identity path")
        .to_owned();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    fs::remove_file(&identity).expect("remove guarded identity path");
    fs::write(&identity, "replacement private marker").expect("replacement identity");
    fs::set_permissions(&identity, fs::Permissions::from_mode(0o600))
        .expect("replacement identity permissions");
    assert_eq!(
        ProcessSshRunner.exchange(&invocation, b"{}\n", &CancellationToken::new()),
        Err(SshTransportError::IdentityFileChanged)
    );
}

#[cfg(windows)]
#[test]
fn retained_identity_handle_blocks_replacement_on_windows() {
    let fixture = endpoint_fixture();
    let identity = fixture
        .config
        .identity_file()
        .expect("identity path")
        .to_owned();
    let _invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    assert!(fs::remove_file(&identity).is_err());
    assert!(fs::write(&identity, "replacement private marker").is_err());
}

#[cfg(unix)]
#[test]
fn known_hosts_permissions_reject_group_or_other_writes() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = endpoint_fixture();
    fs::set_permissions(
        fixture.config.known_hosts_file(),
        fs::Permissions::from_mode(0o666),
    )
    .expect("weaken trust-file permissions");
    assert_eq!(
        fixture.config.validate_files(),
        Err(SshConfigError::KnownHostsFilePermissions)
    );
}

#[cfg(unix)]
#[test]
fn no_follow_read_rejects_trust_path_replaced_by_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = endpoint_fixture();
    let original = fixture.config.known_hosts_file();
    let replacement = original.with_file_name("replacement-known-hosts");
    fs::write(&replacement, fs::read(original).expect("original bytes")).expect("replacement file");
    fs::remove_file(original).expect("remove original path");
    symlink(&replacement, original).expect("replace with symlink");
    assert!(matches!(
        build_ssh_invocation(&fixture.config),
        Err(SshConfigError::PathUnreadable {
            field: "known_hosts_file"
        } | SshConfigError::PathNotRegularFile {
            field: "known_hosts_file"
        })
    ));
}

#[test]
fn process_runner_honors_pre_requested_cancellation_without_spawning() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let cancellation = CancellationToken::new();
    assert!(cancellation.cancel());
    assert_eq!(
        ProcessSshRunner.exchange(&invocation, b"{}\n", &cancellation),
        Err(SshTransportError::Cancelled)
    );
}

#[test]
fn process_runner_rejects_oversized_request_before_spawning() {
    let fixture = endpoint_fixture();
    let invocation = build_ssh_invocation(&fixture.config).expect("fixed invocation");
    let request = vec![b'x'; MAX_SSH_REQUEST_BYTES + 1];
    assert_eq!(
        ProcessSshRunner.exchange(&invocation, &request, &CancellationToken::new()),
        Err(SshTransportError::RequestTooLarge {
            bytes: request.len(),
            maximum: MAX_SSH_REQUEST_BYTES,
        })
    );
}
