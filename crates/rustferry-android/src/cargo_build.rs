use std::fs;

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::AndroidAbi;
use serde::Deserialize;

use crate::{AndroidError, AndroidToolchain, CommandSpec};

/// Native and JVM artifacts extracted from one Cargo JSON message stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CargoBuildArtifacts {
    /// Matching Android `cdylib`.
    pub native_library: Utf8PathBuf,
    /// DEX files recursively found in dependency build-script output directories.
    pub dependency_dex_files: Vec<Utf8PathBuf>,
    /// Every valid build-script output directory searched.
    pub build_script_out_dirs: Vec<Utf8PathBuf>,
}

/// Create a Cargo cross-build command using explicit target/linker arguments.
///
/// # Errors
///
/// Returns an error when the selected NDK lacks the ABI linker or LLVM archiver.
pub fn cargo_build_command(
    toolchain: &AndroidToolchain,
    project_dir: &Utf8Path,
    cargo_target_dir: &Utf8Path,
    package_name: &str,
    abi: AndroidAbi,
    min_sdk: u32,
    release: bool,
) -> Result<CommandSpec, AndroidError> {
    let linker = toolchain.linker_for(abi, min_sdk)?;
    let archiver = toolchain.llvm_ar()?;
    let target = abi.rust_target();
    let mut command = CommandSpec::new(
        format!("build Rust cdylib for {}", abi.apk_directory()),
        toolchain.cargo.clone(),
        project_dir,
    );
    command.args = vec![
        "build".to_owned(),
        "--manifest-path".to_owned(),
        project_dir.join("Cargo.toml").to_string(),
        "--package".to_owned(),
        package_name.to_owned(),
        "--lib".to_owned(),
        "--target".to_owned(),
        target.to_owned(),
        "--target-dir".to_owned(),
        cargo_target_dir.to_string(),
        "--message-format=json-render-diagnostics".to_owned(),
    ];
    if release {
        command.args.push("--release".to_owned());
    }
    let cargo_target_key = target.replace('-', "_").to_ascii_uppercase();
    let cc_target_key = target.replace('-', "_");
    command.environment.insert(
        format!("CARGO_TARGET_{cargo_target_key}_LINKER"),
        linker.to_string(),
    );
    command
        .environment
        .insert(format!("CC_{cc_target_key}"), linker.to_string());
    command
        .environment
        .insert(format!("AR_{cc_target_key}"), archiver.to_string());
    command
        .environment
        .insert("ANDROID_HOME".to_owned(), toolchain.sdk_root.to_string());
    command.environment.insert(
        "ANDROID_SDK_ROOT".to_owned(),
        toolchain.sdk_root.to_string(),
    );
    command.environment.insert(
        "ANDROID_NDK_HOME".to_owned(),
        toolchain.ndk.root.to_string(),
    );
    Ok(command)
}

/// Parse Cargo JSON, constrain reported paths to Cargo's target directory, and collect DEX files.
///
/// # Errors
///
/// Returns an error for malformed Cargo JSON, unsafe reported paths, or a missing matching
/// `cdylib`.
pub fn collect_cargo_artifacts(
    stdout: &[u8],
    rust_target: &str,
    library_target_name: &str,
    cargo_target_dir: &Utf8Path,
) -> Result<CargoBuildArtifacts, AndroidError> {
    let target_root = canonical_utf8(cargo_target_dir)?;
    let text = std::str::from_utf8(stdout)
        .map_err(|error| AndroidError::CargoOutput(format!("stdout was not UTF-8: {error}")))?;
    let mut native_candidates = Vec::new();
    let mut out_dirs = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            AndroidError::CargoOutput(format!(
                "line {} was not a Cargo JSON message: {error}",
                line_number + 1
            ))
        })?;
        let reason = value.get("reason").and_then(serde_json::Value::as_str);
        match reason {
            Some("compiler-artifact") => {
                let message: CompilerArtifact = serde_json::from_value(value).map_err(|error| {
                    AndroidError::CargoOutput(format!("malformed compiler-artifact: {error}"))
                })?;
                if message.target.name == library_target_name
                    && (message
                        .target
                        .crate_types
                        .iter()
                        .any(|kind| kind == "cdylib")
                        || message.target.kind.iter().any(|kind| kind == "cdylib"))
                {
                    native_candidates.extend(
                        message
                            .filenames
                            .into_iter()
                            .filter(|path| path.extension() == Some("so")),
                    );
                }
            }
            Some("build-script-executed") => {
                let message: BuildScriptExecuted =
                    serde_json::from_value(value).map_err(|error| {
                        AndroidError::CargoOutput(format!(
                            "malformed build-script-executed: {error}"
                        ))
                    })?;
                if let Some(path) = safe_reported_directory(&message.out_dir, &target_root) {
                    out_dirs.push(path);
                }
            }
            _ => {}
        }
    }
    out_dirs.sort();
    out_dirs.dedup();

    let native_library = native_candidates
        .iter()
        .find(|path| {
            path.file_name().is_some_and(|name| {
                name == format!("lib{}.so", library_target_name.replace('-', "_"))
            })
        })
        .or_else(|| native_candidates.first())
        .cloned()
        .ok_or_else(|| AndroidError::NativeLibraryMissing {
            target: rust_target.to_owned(),
            searched: native_candidates.clone(),
        })?;
    let native_library = safe_reported_file(&native_library, &target_root).ok_or_else(|| {
        AndroidError::NativeLibraryMissing {
            target: rust_target.to_owned(),
            searched: native_candidates,
        }
    })?;

    let mut dex_files = Vec::new();
    for out_dir in &out_dirs {
        collect_extension_files(out_dir, "dex", 10, &mut dex_files);
    }
    dex_files.sort();
    dex_files.dedup();
    Ok(CargoBuildArtifacts {
        native_library,
        dependency_dex_files: dex_files,
        build_script_out_dirs: out_dirs,
    })
}

/// Recursively collect explicit bridge DEX/JAR inputs without following symlinks.
///
/// # Errors
///
/// Returns an error when an input is missing or is not a supported file/directory.
pub fn collect_explicit_dex_inputs(
    inputs: &[Utf8PathBuf],
) -> Result<Vec<Utf8PathBuf>, AndroidError> {
    let mut files = Vec::new();
    for input in inputs {
        if input.is_dir() {
            collect_dex_and_jar_files(input, 10, &mut files);
        } else if input.is_file() && matches!(input.extension(), Some("dex" | "jar" | "class")) {
            files.push(input.clone());
        } else {
            return Err(AndroidError::InvalidRequest(format!(
                "DEX/bridge input is missing or unsupported: {input}"
            )));
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

#[derive(Deserialize)]
struct CompilerArtifact {
    target: CargoTarget,
    filenames: Vec<Utf8PathBuf>,
}

#[derive(Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
}

#[derive(Deserialize)]
struct BuildScriptExecuted {
    out_dir: Utf8PathBuf,
}

fn safe_reported_directory(path: &Utf8Path, root: &Utf8Path) -> Option<Utf8PathBuf> {
    let canonical = canonical_utf8(path).ok()?;
    (canonical.starts_with(root) && canonical.is_dir()).then_some(canonical)
}

fn safe_reported_file(path: &Utf8Path, root: &Utf8Path) -> Option<Utf8PathBuf> {
    let canonical = canonical_utf8(path).ok()?;
    (canonical.starts_with(root) && canonical.is_file()).then_some(canonical)
}

fn canonical_utf8(path: &Utf8Path) -> Result<Utf8PathBuf, AndroidError> {
    let canonical = fs::canonicalize(path)
        .map_err(|source| crate::error::io_error("canonicalize build path", path, source))?;
    Utf8PathBuf::from_path_buf(canonical).map_err(AndroidError::NonUtf8Path)
}

fn collect_extension_files(
    root: &Utf8Path,
    extension: &str,
    depth: usize,
    output: &mut Vec<Utf8PathBuf>,
) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .filter_map(|entry| Utf8PathBuf::from_path_buf(entry.path()).ok())
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_extension_files(&path, extension, depth - 1, output);
        } else if path.extension() == Some(extension) {
            output.push(path);
        }
    }
}

fn collect_dex_and_jar_files(root: &Utf8Path, depth: usize, output: &mut Vec<Utf8PathBuf>) {
    if depth == 0 {
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .filter_map(|entry| Utf8PathBuf::from_path_buf(entry.path()).ok())
        .collect::<Vec<_>>();
    paths.sort();
    for path in paths {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_dex_and_jar_files(&path, depth - 1, output);
        } else if matches!(path.extension(), Some("dex" | "jar" | "class")) {
            output.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn extracts_cdylib_and_dependency_dex_from_cargo_json() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let native = root.join("aarch64-linux-android/debug/libweather.so");
        let out_dir = root.join("aarch64-linux-android/debug/build/slint/out");
        let dex = out_dir.join("classes.dex");
        fs::create_dir_all(native.parent().unwrap()).unwrap();
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(&native, b"native").unwrap();
        fs::write(&dex, b"dex\n035\0").unwrap();
        let json = format!(
            "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"weather\",\"kind\":[\"cdylib\"],\"crate_types\":[\"cdylib\"]}},\"filenames\":[\"{native}\"]}}\n{{\"reason\":\"build-script-executed\",\"out_dir\":\"{out_dir}\"}}\n"
        );
        let artifacts =
            collect_cargo_artifacts(json.as_bytes(), "aarch64-linux-android", "weather", &root)
                .unwrap();
        assert_eq!(artifacts.native_library, fs::canonicalize(native).unwrap());
        assert_eq!(
            artifacts.dependency_dex_files,
            vec![fs::canonicalize(dex).unwrap()]
        );
        assert_eq!(artifacts.build_script_out_dirs.len(), 1);
    }

    #[test]
    fn refuses_out_dirs_outside_the_cargo_target() {
        let target = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = Utf8PathBuf::from_path_buf(target.path().to_owned()).unwrap();
        let outside = Utf8PathBuf::from_path_buf(outside.path().to_owned()).unwrap();
        let native = target.join("libweather.so");
        fs::write(&native, b"native").unwrap();
        fs::write(outside.join("classes.dex"), b"dex\n035\0").unwrap();
        let json = format!(
            "{{\"reason\":\"compiler-artifact\",\"target\":{{\"name\":\"weather\",\"kind\":[\"cdylib\"],\"crate_types\":[\"cdylib\"]}},\"filenames\":[\"{native}\"]}}\n{{\"reason\":\"build-script-executed\",\"out_dir\":\"{outside}\"}}\n"
        );
        let artifacts =
            collect_cargo_artifacts(json.as_bytes(), "aarch64-linux-android", "weather", &target)
                .unwrap();
        assert!(artifacts.dependency_dex_files.is_empty());
        assert!(artifacts.build_script_out_dirs.is_empty());
    }
}
