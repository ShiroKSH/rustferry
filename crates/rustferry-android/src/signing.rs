use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

use camino::{Utf8Path, Utf8PathBuf};
use directories::BaseDirs;
use fs2::FileExt;
use uuid::Uuid;

use crate::command::external_tool_path_arg;
use crate::{AndroidError, AndroidToolchain, CommandSpec, error::io_error, run_command};

/// Alias used only by the machine-local debug certificate.
pub const DEBUG_KEY_ALIAS: &str = "rustferrydebugkey";

/// Non-inline password source accepted by Android signing tools.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SigningPasswordSource {
    /// Read one password line from a file.
    File(Utf8PathBuf),
    /// Read a password from a named environment variable.
    Environment(String),
}

impl SigningPasswordSource {
    fn apksigner_argument(&self) -> Result<String, AndroidError> {
        match self {
            Self::File(path) => Ok(format!("file:{}", external_tool_path_arg(path)?)),
            Self::Environment(name)
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_') =>
            {
                Ok(format!("env:{name}"))
            }
            Self::Environment(name) => Err(AndroidError::InvalidRequest(format!(
                "signing password environment variable `{name}` is not a safe variable name"
            ))),
        }
    }
}

/// APK signing selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AndroidSigningConfig {
    /// Persistent machine-local certificate, created on first non-dry build.
    Debug {
        /// Override cargo-ferry's OS configuration directory.
        config_dir: Option<Utf8PathBuf>,
    },
    /// User-supplied release or development key store.
    Keystore {
        /// Key store path outside generated output.
        keystore: Utf8PathBuf,
        /// Private-key alias.
        key_alias: String,
        /// Store password source.
        store_password: SigningPasswordSource,
        /// Optional distinct private-key password source.
        key_password: Option<SigningPasswordSource>,
    },
}

impl Default for AndroidSigningConfig {
    fn default() -> Self {
        Self::Debug { config_dir: None }
    }
}

/// Machine-local files backing the persistent debug signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DebugSigningPaths {
    /// PKCS#12 key store.
    pub keystore: Utf8PathBuf,
    /// Owner-readable password file.
    pub password_file: Utf8PathBuf,
    /// Coordination lock for concurrent first builds.
    pub lock_file: Utf8PathBuf,
}

/// Fully resolved signing parameters; password values are never stored here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedSigningConfig {
    /// Key store path.
    pub keystore: Utf8PathBuf,
    /// Private-key alias.
    pub key_alias: String,
    /// Store password source.
    pub store_password: SigningPasswordSource,
    /// Optional distinct private-key password source.
    pub key_password: Option<SigningPasswordSource>,
}

/// Resolve paths in cargo-ferry's OS configuration directory without creating files.
///
/// # Errors
///
/// Returns an error when the host configuration directory is unavailable or non-UTF-8.
pub fn default_debug_signing_paths(
    config_dir: Option<&Utf8Path>,
) -> Result<DebugSigningPaths, AndroidError> {
    let root = if let Some(root) = config_dir {
        root.to_owned()
    } else {
        let base = BaseDirs::new().ok_or_else(|| {
            AndroidError::InvalidRequest(
                "the operating-system configuration directory could not be resolved".to_owned(),
            )
        })?;
        Utf8PathBuf::from_path_buf(base.config_dir().to_owned())
            .map_err(AndroidError::NonUtf8Path)?
            .join("cargo-ferry")
    };
    let android = root.join("android");
    Ok(DebugSigningPaths {
        keystore: android.join("debug.keystore"),
        password_file: android.join("debug-keystore.pass"),
        lock_file: android.join("debug-keystore.lock"),
    })
}

/// Resolve a signing configuration, creating and validating the debug key when needed.
///
/// # Errors
///
/// Returns an error for missing explicit signing files, invalid password references, key-tool
/// failures, or machine-local filesystem failures.
pub fn resolve_signing_config(
    signing: &AndroidSigningConfig,
    toolchain: &AndroidToolchain,
    log_dir: &Utf8Path,
) -> Result<ResolvedSigningConfig, AndroidError> {
    match signing {
        AndroidSigningConfig::Debug { config_dir } => {
            let paths = default_debug_signing_paths(config_dir.as_deref())?;
            ensure_debug_keystore(&paths, toolchain, log_dir)?;
            Ok(ResolvedSigningConfig {
                keystore: paths.keystore,
                key_alias: DEBUG_KEY_ALIAS.to_owned(),
                store_password: SigningPasswordSource::File(paths.password_file),
                key_password: None,
            })
        }
        AndroidSigningConfig::Keystore {
            keystore,
            key_alias,
            store_password,
            key_password,
        } => {
            if !keystore.is_file() {
                return Err(AndroidError::InvalidRequest(format!(
                    "signing keystore does not exist: {keystore}"
                )));
            }
            if key_alias.trim().is_empty() {
                return Err(AndroidError::InvalidRequest(
                    "signing key alias cannot be empty".to_owned(),
                ));
            }
            validate_password_source(store_password)?;
            if let Some(source) = key_password {
                validate_password_source(source)?;
            }
            Ok(ResolvedSigningConfig {
                keystore: keystore.clone(),
                key_alias: key_alias.clone(),
                store_password: store_password.clone(),
                key_password: key_password.clone(),
            })
        }
    }
}

/// Resolve signing paths and password references without reading or creating signing files.
///
/// # Errors
///
/// Returns an error for an invalid key alias, password reference, or config path.
pub fn preview_signing_config(
    signing: &AndroidSigningConfig,
) -> Result<ResolvedSigningConfig, AndroidError> {
    match signing {
        AndroidSigningConfig::Debug { config_dir } => {
            let paths = default_debug_signing_paths(config_dir.as_deref())?;
            Ok(ResolvedSigningConfig {
                keystore: paths.keystore,
                key_alias: DEBUG_KEY_ALIAS.to_owned(),
                store_password: SigningPasswordSource::File(paths.password_file),
                key_password: None,
            })
        }
        AndroidSigningConfig::Keystore {
            keystore,
            key_alias,
            store_password,
            key_password,
        } => {
            if key_alias.trim().is_empty() {
                return Err(AndroidError::InvalidRequest(
                    "signing key alias cannot be empty".to_owned(),
                ));
            }
            store_password.apksigner_argument()?;
            if let Some(source) = key_password {
                source.apksigner_argument()?;
            }
            Ok(ResolvedSigningConfig {
                keystore: keystore.clone(),
                key_alias: key_alias.clone(),
                store_password: store_password.clone(),
                key_password: key_password.clone(),
            })
        }
    }
}

/// Build the `apksigner sign` command without exposing a password value.
///
/// # Errors
///
/// Returns an error when `apksigner` is absent or a password source is invalid.
pub fn apksigner_sign_command(
    toolchain: &AndroidToolchain,
    signing: &ResolvedSigningConfig,
    input: &Utf8Path,
    output: &Utf8Path,
    current_dir: &Utf8Path,
) -> Result<CommandSpec, AndroidError> {
    let apksigner =
        toolchain
            .build_tools
            .apksigner
            .clone()
            .ok_or_else(|| AndroidError::ToolMissing {
                tool: "apksigner".to_owned(),
                searched: vec![toolchain.build_tools.directory.clone()],
                fix: "Install a complete Android SDK Build Tools revision.".to_owned(),
            })?;
    let mut command = CommandSpec::new(
        "sign APK",
        apksigner,
        Utf8PathBuf::from(external_tool_path_arg(current_dir)?),
    );
    command.args = vec![
        "sign".to_owned(),
        "--ks".to_owned(),
        external_tool_path_arg(&signing.keystore)?,
        "--ks-key-alias".to_owned(),
        signing.key_alias.clone(),
        "--ks-pass".to_owned(),
        signing.store_password.apksigner_argument()?,
    ];
    if let Some(source) = &signing.key_password {
        command.args.push("--key-pass".to_owned());
        command.args.push(source.apksigner_argument()?);
    }
    command.args.extend([
        "--out".to_owned(),
        external_tool_path_arg(output)?,
        external_tool_path_arg(input)?,
    ]);
    Ok(command)
}

/// Build the mandatory signature verification command.
///
/// # Errors
///
/// Returns an error when the selected Build Tools do not contain `apksigner`.
pub fn apksigner_verify_command(
    toolchain: &AndroidToolchain,
    apk: &Utf8Path,
    current_dir: &Utf8Path,
) -> Result<CommandSpec, AndroidError> {
    let apksigner =
        toolchain
            .build_tools
            .apksigner
            .clone()
            .ok_or_else(|| AndroidError::ToolMissing {
                tool: "apksigner".to_owned(),
                searched: vec![toolchain.build_tools.directory.clone()],
                fix: "Install a complete Android SDK Build Tools revision.".to_owned(),
            })?;
    let mut command = CommandSpec::new(
        "verify APK signature",
        apksigner,
        Utf8PathBuf::from(external_tool_path_arg(current_dir)?),
    );
    command.args = vec![
        "verify".to_owned(),
        "--verbose".to_owned(),
        "--print-certs".to_owned(),
        external_tool_path_arg(apk)?,
    ];
    Ok(command)
}

fn ensure_debug_keystore(
    paths: &DebugSigningPaths,
    toolchain: &AndroidToolchain,
    log_dir: &Utf8Path,
) -> Result<(), AndroidError> {
    let parent = paths.keystore.parent().ok_or_else(|| {
        AndroidError::InvalidRequest("debug keystore has no parent directory".to_owned())
    })?;
    fs::create_dir_all(parent)
        .map_err(|source| io_error("create signing configuration directory", parent, source))?;
    #[cfg(unix)]
    secure_directory(parent)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&paths.lock_file)
        .map_err(|source| io_error("open debug keystore lock", &paths.lock_file, source))?;
    lock.lock_exclusive()
        .map_err(|source| io_error("lock debug keystore", &paths.lock_file, source))?;

    if paths.keystore.exists() && !paths.password_file.is_file() {
        return Err(AndroidError::InvalidRequest(format!(
            "debug keystore exists but its password file is missing: {}. Move the keystore aside or restore the password file; cargo-ferry will not overwrite the key.",
            paths.keystore
        )));
    }
    if !paths.password_file.exists() {
        create_password_file(&paths.password_file)?;
    }
    #[cfg(unix)]
    secure_file(&paths.password_file)?;

    if !paths.keystore.exists() {
        let mut command = CommandSpec::new(
            "create persistent debug keystore",
            toolchain.keytool.clone(),
            Utf8PathBuf::from(external_tool_path_arg(parent)?),
        );
        command.args = vec![
            "-genkeypair".to_owned(),
            "-keystore".to_owned(),
            external_tool_path_arg(&paths.keystore)?,
            "-storetype".to_owned(),
            "PKCS12".to_owned(),
            "-storepass:file".to_owned(),
            external_tool_path_arg(&paths.password_file)?,
            "-alias".to_owned(),
            DEBUG_KEY_ALIAS.to_owned(),
            "-keyalg".to_owned(),
            "RSA".to_owned(),
            "-keysize".to_owned(),
            "2048".to_owned(),
            "-validity".to_owned(),
            "10000".to_owned(),
            "-dname".to_owned(),
            "CN=RustFerry Debug,O=RustFerry,C=US".to_owned(),
            "-noprompt".to_owned(),
        ];
        run_command(&command, &log_dir.join("keytool-create.log"))?;
        #[cfg(unix)]
        secure_file(&paths.keystore)?;
    }

    let mut verify = CommandSpec::new(
        "validate persistent debug keystore",
        toolchain.keytool.clone(),
        Utf8PathBuf::from(external_tool_path_arg(parent)?),
    );
    verify.args = vec![
        "-J-Duser.language=en".to_owned(),
        "-J-Duser.country=US".to_owned(),
        "-list".to_owned(),
        "-keystore".to_owned(),
        external_tool_path_arg(&paths.keystore)?,
        "-storetype".to_owned(),
        "PKCS12".to_owned(),
        "-storepass:file".to_owned(),
        external_tool_path_arg(&paths.password_file)?,
        "-alias".to_owned(),
        DEBUG_KEY_ALIAS.to_owned(),
        "-v".to_owned(),
    ];
    let output = run_command(&verify, &log_dir.join("keytool-verify.log"))?;
    let stdout = std::str::from_utf8(&output.stdout).map_err(|error| {
        AndroidError::InvalidRequest(format!(
            "keytool returned non-UTF-8 certificate metadata; inspect keytool-verify.log: {error}"
        ))
    })?;
    validate_debug_certificate_expiry(stdout, utc_today()?)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CalendarDate {
    year: i64,
    month: u8,
    day: u8,
}

fn validate_debug_certificate_expiry(
    keytool_output: &str,
    today: CalendarDate,
) -> Result<(), AndroidError> {
    let expiration = parse_keytool_expiration(keytool_output).ok_or_else(|| {
        AndroidError::InvalidRequest(
            "keytool did not report a parseable debug certificate expiry; inspect keytool-verify.log and recreate the debug key pair deliberately"
                .to_owned(),
        )
    })?;
    if expiration <= today {
        return Err(AndroidError::InvalidRequest(format!(
            "persistent debug certificate expired on {:04}-{:02}-{:02}; move the debug keystore and password file aside together, then rebuild to create a fresh identity",
            expiration.year, expiration.month, expiration.day
        )));
    }
    Ok(())
}

fn parse_keytool_expiration(output: &str) -> Option<CalendarDate> {
    let expiry = output
        .lines()
        .find_map(|line| line.split_once("until:").map(|(_, expiry)| expiry.trim()))?;
    let fields = expiry.split_whitespace().collect::<Vec<_>>();
    let month = match *fields.get(1)? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day = fields.get(2)?.parse::<u8>().ok()?;
    let year = fields.last()?.parse::<i64>().ok()?;
    (day > 0 && day <= days_in_month(year, month)).then_some(CalendarDate { year, month, day })
}

fn utc_today() -> Result<CalendarDate, AndroidError> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
        AndroidError::InvalidRequest(
            "system clock predates the Unix epoch; debug certificate expiry cannot be checked"
                .to_owned(),
        )
    })?;
    let days = i64::try_from(elapsed.as_secs() / 86_400).map_err(|_| {
        AndroidError::InvalidRequest(
            "system clock is outside the supported certificate-validation range".to_owned(),
        )
    })?;
    Ok(civil_date_from_unix_days(days))
}

fn civil_date_from_unix_days(days: i64) -> CalendarDate {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    CalendarDate {
        year,
        month: u8::try_from(month).expect("civil month is bounded"),
        day: u8::try_from(day).expect("civil day is bounded"),
    }
}

fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn validate_password_source(source: &SigningPasswordSource) -> Result<(), AndroidError> {
    match source {
        SigningPasswordSource::File(path) if !path.is_file() => Err(AndroidError::InvalidRequest(
            format!("signing password file does not exist: {path}"),
        )),
        _ => source.apksigner_argument().map(|_| ()),
    }
}

fn create_password_file(path: &Utf8Path) -> Result<(), AndroidError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create debug keystore password file", path, source))?;
    #[cfg(unix)]
    secure_file(path)?;
    writeln!(
        file,
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
    .map_err(|source| io_error("write debug keystore password file", path, source))
}

#[cfg(unix)]
fn secure_directory(path: &Utf8Path) -> Result<(), AndroidError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("set signing directory permissions", path, source))
}

#[cfg(unix)]
fn secure_file(path: &Utf8Path) -> Result<(), AndroidError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("set signing file permissions", path, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AndroidBuildTools, AndroidNdk, AndroidPlatform};

    #[cfg(windows)]
    fn signing_toolchain() -> AndroidToolchain {
        AndroidToolchain {
            sdk_root: r"C:\Android\Sdk".into(),
            platform: AndroidPlatform {
                sdk_root: r"C:\Android\Sdk".into(),
                api_level: 36,
                directory: r"C:\Android\Sdk\platforms\android-36".into(),
                android_jar: r"C:\Android\Sdk\platforms\android-36\android.jar".into(),
            },
            build_tools: AndroidBuildTools {
                sdk_root: r"C:\Android\Sdk".into(),
                version: "36.0.0".to_owned(),
                directory: r"C:\Android\Sdk\build-tools\36.0.0".into(),
                aapt2: None,
                d8: None,
                zipalign: None,
                apksigner: Some(r"C:\Android\Sdk\build-tools\36.0.0\apksigner.bat".into()),
            },
            ndk: AndroidNdk {
                root: r"C:\Android\Sdk\ndk\29.0.0".into(),
                version: "29.0.0".to_owned(),
                llvm_prebuilt: None,
            },
            cargo: r"C:\Rust\cargo.exe".into(),
            rustc: None,
            rustup: None,
            java: None,
            javac: None,
            keytool: r"C:\Java\bin\keytool.exe".into(),
        }
    }

    #[test]
    fn password_values_are_never_command_arguments() {
        #[cfg(windows)]
        let path = r"C:\secure\signing.pass";
        #[cfg(not(windows))]
        let path = "/secure/signing.pass";
        let source = SigningPasswordSource::File(path.into());
        assert_eq!(source.apksigner_argument().unwrap(), format!("file:{path}"));
        assert!(!source.apksigner_argument().unwrap().contains("secret"));
    }

    #[test]
    fn rejects_unsafe_environment_names() {
        let source = SigningPasswordSource::Environment("PASSWORD;echo".to_owned());
        assert!(source.apksigner_argument().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn apksigner_commands_normalize_windows_verbatim_paths() {
        let signing = ResolvedSigningConfig {
            keystore: r"\\?\C:\secure\debug.keystore".into(),
            key_alias: "debug".to_owned(),
            store_password: SigningPasswordSource::File(
                r"\\?\C:\secure\debug-keystore.pass".into(),
            ),
            key_password: None,
        };
        let command = apksigner_sign_command(
            &signing_toolchain(),
            &signing,
            Utf8Path::new(r"\\?\C:\work\aligned.apk"),
            Utf8Path::new(r"\\?\C:\work\calculator.apk"),
            Utf8Path::new(r"\\?\C:\work"),
        )
        .unwrap();
        assert_eq!(command.current_dir, Utf8Path::new(r"C:\work"));
        assert!(command.args.iter().all(|value| !value.contains(r"\\?\")));
        assert!(command.args.contains(&r"C:\work\calculator.apk".to_owned()));

        let verify = apksigner_verify_command(
            &signing_toolchain(),
            Utf8Path::new(r"\\?\C:\work\calculator.apk"),
            Utf8Path::new(r"\\?\C:\work"),
        )
        .unwrap();
        assert!(verify.args.iter().all(|value| !value.contains(r"\\?\")));
    }

    #[test]
    fn parses_and_enforces_debug_certificate_expiry() {
        let output =
            "Valid from: Sat Aug 01 04:45:48 MSK 2026 until: Wed Dec 17 04:45:48 MSK 2053\n";
        let expiration = CalendarDate {
            year: 2053,
            month: 12,
            day: 17,
        };
        assert_eq!(parse_keytool_expiration(output), Some(expiration));
        assert!(
            validate_debug_certificate_expiry(
                output,
                CalendarDate {
                    year: 2053,
                    month: 12,
                    day: 16,
                }
            )
            .is_ok()
        );
        assert!(validate_debug_certificate_expiry(output, expiration).is_err());
    }

    #[test]
    fn unix_day_conversion_handles_epoch_and_leap_days() {
        assert_eq!(
            civil_date_from_unix_days(0),
            CalendarDate {
                year: 1970,
                month: 1,
                day: 1,
            }
        );
        assert_eq!(
            civil_date_from_unix_days(19_782),
            CalendarDate {
                year: 2024,
                month: 2,
                day: 29,
            }
        );
    }
}
