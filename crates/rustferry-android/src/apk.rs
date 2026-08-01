use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Read,
};

use camino::{Utf8Path, Utf8PathBuf};
use rustferry_core::{AndroidAbi, AndroidLiveActivityFallback, FerryConfig};
use serde::{Deserialize, Serialize};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{AndroidError, error::io_error, generate::android_manifest_permissions};

/// Native library produced for one configured ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLibraryInput {
    /// Android ABI directory.
    pub abi: AndroidAbi,
    /// Compiled ELF shared object.
    pub path: Utf8PathBuf,
}

/// Independent expectations for the final APK archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApkExpectation {
    /// Application ID expected from AAPT2 badging output.
    pub package_name: String,
    /// Native library basename without `lib` and `.so`.
    pub native_library_name: String,
    /// ABIs that must be present exactly once.
    pub abis: Vec<AndroidAbi>,
    /// Whether at least `classes.dex` is mandatory.
    pub dex_required: bool,
}

/// Evidence returned by independent APK inspection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApkValidation {
    /// Package ID parsed from `aapt2 dump badging`.
    pub package_name: String,
    /// Launcher activity parsed from AAPT2.
    pub launcher_activity: String,
    /// Archive entries, sorted for stable JSON output.
    pub entries: Vec<String>,
    /// Native ABIs whose ELF headers matched their APK directories.
    pub native_abis: Vec<String>,
    /// Number of sequential DEX files.
    pub dex_files: usize,
    /// Evidence proven from the compiled binary manifest.
    pub manifest: Box<ManifestValidation>,
}

/// Stable evidence extracted from the final APK's compiled binary manifest.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestValidation {
    /// Permissions and optional maximum SDK constraints, sorted by permission name.
    pub permissions: Vec<String>,
    /// Application components as `kind:class`, sorted by class name.
    pub components: Vec<String>,
    /// Deep-link data filters, sorted by scheme, host, and path prefix.
    pub deep_link_filters: Vec<String>,
}

/// Append stored native libraries and DEX files to an AAPT2-linked APK.
///
/// # Errors
///
/// Returns an error for missing/unsafe inputs, duplicate entries, I/O failures, or malformed ZIPs.
pub fn inject_apk_entries(
    apk: &Utf8Path,
    native_libraries: &[NativeLibraryInput],
    dex_files: &[Utf8PathBuf],
) -> Result<(), AndroidError> {
    let existing = archive_entry_names(apk)?;
    let mut additions = BTreeMap::<String, Utf8PathBuf>::new();
    for native in native_libraries {
        if !native.path.is_file() {
            return Err(AndroidError::InvalidArtifact {
                path: native.path.clone(),
                reason: "native library file is missing".to_owned(),
            });
        }
        let name = native
            .path
            .file_name()
            .ok_or_else(|| AndroidError::InvalidArtifact {
                path: native.path.clone(),
                reason: "native library has no filename".to_owned(),
            })?;
        if !name.starts_with("lib") || Utf8Path::new(name).extension() != Some("so") {
            return Err(AndroidError::InvalidArtifact {
                path: native.path.clone(),
                reason: "native library filename must be `lib<name>.so`".to_owned(),
            });
        }
        additions.insert(
            format!("lib/{}/{}", native.abi.apk_directory(), name),
            native.path.clone(),
        );
    }
    for dex in dex_files {
        let name = dex
            .file_name()
            .ok_or_else(|| AndroidError::InvalidArtifact {
                path: dex.clone(),
                reason: "DEX file has no filename".to_owned(),
            })?;
        if !valid_dex_name(name) {
            return Err(AndroidError::InvalidArtifact {
                path: dex.clone(),
                reason: format!("D8 output `{name}` is not classes.dex/classesN.dex"),
            });
        }
        additions.insert(name.to_owned(), dex.clone());
    }
    if let Some(collision) = additions.keys().find(|name| existing.contains(*name)) {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: format!(
                "AAPT2 output already contains `{collision}`; refusing duplicate ZIP entries"
            ),
        });
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(apk)
        .map_err(|source| io_error("open APK for native/DEX injection", apk, source))?;
    let mut writer = ZipWriter::new_append(file).map_err(|error| AndroidError::Zip {
        path: apk.to_owned(),
        message: error.to_string(),
    })?;
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o644);
    for (entry, path) in additions {
        writer
            .start_file(&entry, options)
            .map_err(|error| AndroidError::Zip {
                path: apk.to_owned(),
                message: format!("could not start `{entry}`: {error}"),
            })?;
        let mut input = File::open(&path)
            .map_err(|source| io_error("open APK injection input", &path, source))?;
        std::io::copy(&mut input, &mut writer)
            .map_err(|source| io_error("append APK entry", apk, source))?;
    }
    writer.finish().map_err(|error| AndroidError::Zip {
        path: apk.to_owned(),
        message: error.to_string(),
    })?;
    Ok(())
}

/// Collect and validate sequential D8 output names from a directory.
///
/// # Errors
///
/// Returns an error when the directory is unreadable, `classes.dex` is absent, numbering has a
/// gap, or a DEX header is invalid.
pub fn collect_d8_outputs(directory: &Utf8Path) -> Result<Vec<Utf8PathBuf>, AndroidError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| io_error("read D8 output directory", directory, source))?;
    let mut dex = entries
        .filter_map(Result::ok)
        .filter_map(|entry| Utf8PathBuf::from_path_buf(entry.path()).ok())
        .filter(|path| path.file_name().is_some_and(valid_dex_name))
        .collect::<Vec<_>>();
    dex.sort_by_key(|path| dex_index(path.file_name().unwrap_or_default()));
    if dex.is_empty() || dex_index(dex[0].file_name().unwrap_or_default()) != Some(1) {
        return Err(AndroidError::InvalidArtifact {
            path: directory.to_owned(),
            reason: "D8 did not produce classes.dex".to_owned(),
        });
    }
    for (offset, path) in dex.iter().enumerate() {
        if dex_index(path.file_name().unwrap_or_default()) != Some(offset + 1) {
            return Err(AndroidError::InvalidArtifact {
                path: directory.to_owned(),
                reason: "D8 output contains a gap in classes.dex/classesN.dex numbering".to_owned(),
            });
        }
        validate_dex_header(path)?;
    }
    Ok(dex)
}

/// Validate ZIP safety, resources, DEX headers, and ELF ABI headers without trusting build tools.
///
/// # Errors
///
/// Returns an error for malformed/unsafe archives or any unmet package, DEX, resource, or ABI
/// invariant.
pub fn validate_apk_archive(
    apk: &Utf8Path,
    expectation: &ApkExpectation,
) -> Result<ApkValidation, AndroidError> {
    let file =
        File::open(apk).map_err(|source| io_error("open APK for validation", apk, source))?;
    let mut archive = ZipArchive::new(file).map_err(|error| AndroidError::Zip {
        path: apk.to_owned(),
        message: error.to_string(),
    })?;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut dex_names = Vec::new();
    let mut native_abis = Vec::new();
    let expected_native_entries = expectation
        .abis
        .iter()
        .map(|abi| {
            format!(
                "lib/{}/lib{}.so",
                abi.apk_directory(),
                expectation.native_library_name
            )
        })
        .collect::<BTreeSet<_>>();
    let mut native_entries = BTreeSet::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| AndroidError::Zip {
            path: apk.to_owned(),
            message: error.to_string(),
        })?;
        let name = entry.name().to_owned();
        validate_archive_name(apk, &name)?;
        if !seen.insert(name.clone()) {
            return Err(AndroidError::InvalidArtifact {
                path: apk.to_owned(),
                reason: format!("duplicate ZIP entry `{name}`"),
            });
        }
        if valid_dex_name(&name) {
            if entry.compression() != CompressionMethod::Stored {
                return Err(AndroidError::InvalidArtifact {
                    path: apk.to_owned(),
                    reason: format!(
                        "DEX entry `{name}` is compressed; injection must store it before alignment"
                    ),
                });
            }
            let mut header = [0_u8; 8];
            entry
                .read_exact(&mut header)
                .map_err(|source| io_error("read DEX header", apk, source))?;
            if !valid_dex_magic(header) {
                return Err(AndroidError::InvalidArtifact {
                    path: apk.to_owned(),
                    reason: format!("DEX entry `{name}` has an invalid magic header"),
                });
            }
            dex_names.push(name.clone());
        }
        if name.starts_with("lib/") && Utf8Path::new(&name).extension() == Some("so") {
            if !expected_native_entries.contains(&name) {
                return Err(AndroidError::InvalidArtifact {
                    path: apk.to_owned(),
                    reason: format!("unexpected native library entry `{name}`"),
                });
            }
            for abi in &expectation.abis {
                let expected = format!(
                    "lib/{}/lib{}.so",
                    abi.apk_directory(),
                    expectation.native_library_name
                );
                if name != expected {
                    continue;
                }
                if entry.compression() != CompressionMethod::Stored {
                    return Err(AndroidError::InvalidArtifact {
                        path: apk.to_owned(),
                        reason: format!(
                            "native library `{name}` is compressed and cannot be 16 KiB page-aligned"
                        ),
                    });
                }
                validate_elf_reader(apk, &mut entry, *abi)?;
                native_abis.push(abi.apk_directory().to_owned());
                native_entries.insert(name.clone());
                break;
            }
        }
        entries.push(name);
    }

    for required in ["AndroidManifest.xml", "resources.arsc"] {
        if !seen.contains(required) {
            return Err(AndroidError::InvalidArtifact {
                path: apk.to_owned(),
                reason: format!("required APK entry `{required}` is missing"),
            });
        }
    }
    if !seen
        .iter()
        .any(|name| name.starts_with("res/drawable") && name.contains("ferry_icon"))
    {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: "compiled launcher icon resource is missing".to_owned(),
        });
    }
    if !seen
        .iter()
        .any(|name| name.starts_with("res/drawable") && name.contains("ferry_splash"))
    {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: "compiled splash resource is missing".to_owned(),
        });
    }
    native_abis.sort();
    native_abis.dedup();
    if native_entries != expected_native_entries {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: format!(
                "native library set mismatch: expected {expected_native_entries:?}, found {native_entries:?}"
            ),
        });
    }
    dex_names.sort_by_key(|name| dex_index(name));
    if expectation.dex_required && dex_names.first().map(String::as_str) != Some("classes.dex") {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: "classes.dex is required but missing".to_owned(),
        });
    }
    for (offset, name) in dex_names.iter().enumerate() {
        if dex_index(name) != Some(offset + 1) {
            return Err(AndroidError::InvalidArtifact {
                path: apk.to_owned(),
                reason: "DEX entries are not sequentially numbered".to_owned(),
            });
        }
    }
    entries.sort();
    Ok(ApkValidation {
        package_name: String::new(),
        launcher_activity: String::new(),
        entries,
        native_abis,
        dex_files: dex_names.len(),
        manifest: Box::default(),
    })
}

/// Parse and verify `aapt2 dump badging` package and launcher metadata.
///
/// # Errors
///
/// Returns an error when package or launcher metadata is missing or differs from expectations.
pub fn validate_aapt2_badging(
    apk: &Utf8Path,
    output: &[u8],
    expectation: &ApkExpectation,
    validation: &mut ApkValidation,
) -> Result<(), AndroidError> {
    let output = String::from_utf8_lossy(output);
    let package = extract_quoted_field(&output, "package:", "name=").ok_or_else(|| {
        AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: "aapt2 badging output has no package name".to_owned(),
        }
    })?;
    if package != expectation.package_name {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: format!(
                "package ID mismatch: expected `{}`, found `{package}`",
                expectation.package_name
            ),
        });
    }
    let launcher =
        extract_quoted_field(&output, "launchable-activity:", "name=").ok_or_else(|| {
            AndroidError::InvalidArtifact {
                path: apk.to_owned(),
                reason: "aapt2 badging output has no launcher activity".to_owned(),
            }
        })?;
    if launcher != crate::ACTIVITY_CLASS {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: format!(
                "unexpected launcher activity `{launcher}`; expected `{}`",
                crate::ACTIVITY_CLASS
            ),
        });
    }
    validation.package_name = package;
    validation.launcher_activity = launcher;
    Ok(())
}

/// Verify SDK levels, permissions, components, and deep-link filters from AAPT2 XML output.
///
/// # Errors
///
/// Returns an error when the compiled binary manifest differs from the resolved configuration.
pub fn validate_aapt2_manifest(
    apk: &Utf8Path,
    output: &[u8],
    expectation: &ApkExpectation,
    config: &FerryConfig,
    target_sdk: u32,
    validation: &mut ApkValidation,
) -> Result<(), AndroidError> {
    let nodes = parse_xmltree(apk, output)?;
    let manifest = single_node(apk, &nodes, None, "manifest")?;
    require_attribute(apk, &nodes[manifest], "package", &expectation.package_name)?;
    let uses_sdk = single_node(apk, &nodes, Some(manifest), "uses-sdk")?;
    require_attribute(
        apk,
        &nodes[uses_sdk],
        "minSdkVersion",
        &config.android.min_sdk.to_string(),
    )?;
    require_attribute(
        apk,
        &nodes[uses_sdk],
        "targetSdkVersion",
        &target_sdk.to_string(),
    )?;
    let application = single_node(apk, &nodes, Some(manifest), "application")?;
    require_attribute(apk, &nodes[application], "hasCode", "true")?;

    let expected_permissions = android_manifest_permissions(config, target_sdk)
        .into_iter()
        .map(|(name, max_sdk)| (name.to_owned(), max_sdk))
        .collect::<BTreeMap<_, _>>();
    let mut actual_permissions = BTreeMap::new();
    for index in child_nodes(&nodes, manifest, "uses-permission") {
        let name = required_attribute(apk, &nodes[index], "name")?.to_owned();
        let max_sdk = nodes[index]
            .attributes
            .get("maxSdkVersion")
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| AndroidError::InvalidArtifact {
                        path: apk.to_owned(),
                        reason: format!("compiled permission `{name}` has invalid maxSdkVersion"),
                    })
            })
            .transpose()?;
        if actual_permissions.insert(name.clone(), max_sdk).is_some() {
            return Err(invalid_manifest(
                apk,
                format!("duplicate compiled permission `{name}`"),
            ));
        }
    }
    if actual_permissions != expected_permissions {
        return Err(invalid_manifest(
            apk,
            format!(
                "compiled permissions differ from configuration: expected {expected_permissions:?}, found {actual_permissions:?}"
            ),
        ));
    }

    let notification_component = config.capabilities.notifications.local
        || (config.extensions.live_activity.enabled
            && config.extensions.live_activity.android_fallback
                == AndroidLiveActivityFallback::OngoingNotification);
    let mut expected_components =
        BTreeMap::from([(crate::ACTIVITY_CLASS.to_owned(), "activity".to_owned())]);
    if notification_component {
        expected_components.insert(
            crate::NOTIFICATION_RECEIVER_CLASS.to_owned(),
            "receiver".to_owned(),
        );
    }
    if config.extensions.widget.enabled {
        expected_components.insert(
            crate::WIDGET_PROVIDER_CLASS.to_owned(),
            "receiver".to_owned(),
        );
    }
    if config.capabilities.share.enabled {
        expected_components.insert(crate::FILE_PROVIDER_CLASS.to_owned(), "provider".to_owned());
    }
    let component_kinds = [
        "activity",
        "activity-alias",
        "provider",
        "receiver",
        "service",
    ];
    let mut actual_components = BTreeMap::new();
    let mut component_indices = BTreeMap::new();
    for kind in component_kinds {
        for index in child_nodes(&nodes, application, kind) {
            let name = required_attribute(apk, &nodes[index], "name")?.to_owned();
            if actual_components
                .insert(name.clone(), kind.to_owned())
                .is_some()
            {
                return Err(invalid_manifest(
                    apk,
                    format!("duplicate component `{name}`"),
                ));
            }
            component_indices.insert(name, index);
        }
    }
    if actual_components != expected_components {
        return Err(invalid_manifest(
            apk,
            format!(
                "compiled components differ from configuration: expected {expected_components:?}, found {actual_components:?}"
            ),
        ));
    }

    let activity = component_indices[crate::ACTIVITY_CLASS];
    require_attribute(apk, &nodes[activity], "exported", "true")?;
    let launch_mode = required_attribute(apk, &nodes[activity], "launchMode")?;
    if launch_mode != "1" && launch_mode != "singleTop" {
        return Err(invalid_manifest(
            apk,
            format!("compiled activity launchMode is not singleTop: `{launch_mode}`"),
        ));
    }
    require_metadata(
        apk,
        &nodes,
        activity,
        "android.app.lib_name",
        Some(("value", &expectation.native_library_name)),
    )?;
    if notification_component {
        let receiver = component_indices[crate::NOTIFICATION_RECEIVER_CLASS];
        require_attribute(apk, &nodes[receiver], "enabled", "true")?;
        require_attribute(apk, &nodes[receiver], "exported", "false")?;
    }
    if config.extensions.widget.enabled {
        let receiver = component_indices[crate::WIDGET_PROVIDER_CLASS];
        require_attribute(apk, &nodes[receiver], "enabled", "true")?;
        require_attribute(apk, &nodes[receiver], "exported", "false")?;
        require_metadata(apk, &nodes, receiver, "android.appwidget.provider", None)?;
        require_intent_filter(
            apk,
            &nodes,
            receiver,
            &["android.appwidget.action.APPWIDGET_UPDATE"],
            &[],
        )?;
    }
    if config.capabilities.share.enabled {
        let provider = component_indices[crate::FILE_PROVIDER_CLASS];
        require_attribute(apk, &nodes[provider], "exported", "false")?;
        require_attribute(apk, &nodes[provider], "grantUriPermissions", "true")?;
        require_attribute(
            apk,
            &nodes[provider],
            "authorities",
            &format!("{}.ferry-files", expectation.package_name),
        )?;
    }

    require_intent_filter(
        apk,
        &nodes,
        activity,
        &["android.intent.action.MAIN"],
        &["android.intent.category.LAUNCHER"],
    )?;
    let expected_links = expected_deep_link_filters(config);
    let mut actual_links = BTreeSet::new();
    let mut view_filter_count = 0_usize;
    for filter in child_nodes(&nodes, activity, "intent-filter") {
        let actions = named_children(apk, &nodes, filter, "action")?;
        if !actions.contains("android.intent.action.VIEW") {
            continue;
        }
        view_filter_count += 1;
        let categories = named_children(apk, &nodes, filter, "category")?;
        let required_categories = BTreeSet::from([
            "android.intent.category.BROWSABLE".to_owned(),
            "android.intent.category.DEFAULT".to_owned(),
        ]);
        if actions != BTreeSet::from(["android.intent.action.VIEW".to_owned()])
            || categories != required_categories
        {
            return Err(invalid_manifest(
                apk,
                "compiled deep-link filter has unexpected actions or categories",
            ));
        }
        for data in child_nodes(&nodes, filter, "data") {
            let scheme = required_attribute(apk, &nodes[data], "scheme")?.to_owned();
            let host = nodes[data].attributes.get("host").cloned();
            let path = nodes[data].attributes.get("pathPrefix").cloned();
            actual_links.insert((scheme, host, path));
        }
    }
    let expected_view_filters = usize::from(!expected_links.is_empty());
    if view_filter_count != expected_view_filters || actual_links != expected_links {
        return Err(invalid_manifest(
            apk,
            format!(
                "compiled deep-link filters differ from configuration: expected {expected_links:?}, found {actual_links:?}"
            ),
        ));
    }

    validation.manifest.permissions = actual_permissions
        .into_iter()
        .map(|(name, max_sdk)| match max_sdk {
            Some(max_sdk) => format!("{name} (maxSdkVersion={max_sdk})"),
            None => name,
        })
        .collect();
    validation.manifest.components = actual_components
        .into_iter()
        .map(|(name, kind)| format!("{kind}:{name}"))
        .collect();
    validation.manifest.deep_link_filters = actual_links
        .into_iter()
        .map(|(scheme, host, path)| {
            format!(
                "scheme={scheme};host={};pathPrefix={}",
                host.as_deref().unwrap_or("*"),
                path.as_deref().unwrap_or("*")
            )
        })
        .collect();
    Ok(())
}

#[derive(Debug)]
struct XmlTreeNode {
    name: String,
    parent: Option<usize>,
    attributes: BTreeMap<String, String>,
}

fn parse_xmltree(apk: &Utf8Path, output: &[u8]) -> Result<Vec<XmlTreeNode>, AndroidError> {
    let text = std::str::from_utf8(output)
        .map_err(|_| invalid_manifest(apk, "aapt2 xmltree output is not valid UTF-8"))?;
    let mut nodes = Vec::<XmlTreeNode>::new();
    let mut stack = Vec::<(usize, usize)>::new();
    for line in text.lines() {
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        if let Some(element) = trimmed.strip_prefix("E: ") {
            let name = element.split_whitespace().next().unwrap_or_default();
            if name.is_empty() {
                return Err(invalid_manifest(
                    apk,
                    "aapt2 xmltree contains an unnamed element",
                ));
            }
            while stack.last().is_some_and(|(level, _)| *level >= indent) {
                stack.pop();
            }
            let parent = stack.last().map(|(_, index)| *index);
            let index = nodes.len();
            nodes.push(XmlTreeNode {
                name: name.to_owned(),
                parent,
                attributes: BTreeMap::new(),
            });
            stack.push((indent, index));
        } else if let Some(attribute) = trimmed.strip_prefix("A: ") {
            let Some((_, index)) = stack.last() else {
                return Err(invalid_manifest(
                    apk,
                    "aapt2 xmltree attribute has no element",
                ));
            };
            let (name, value) = parse_xmltree_attribute(apk, attribute)?;
            if nodes[*index]
                .attributes
                .insert(name.clone(), value)
                .is_some()
            {
                return Err(invalid_manifest(
                    apk,
                    format!("aapt2 xmltree element has duplicate `{name}` attribute"),
                ));
            }
        }
    }
    if nodes.is_empty() {
        return Err(invalid_manifest(
            apk,
            "aapt2 xmltree output has no elements",
        ));
    }
    Ok(nodes)
}

fn parse_xmltree_attribute(
    apk: &Utf8Path,
    attribute: &str,
) -> Result<(String, String), AndroidError> {
    let (key, encoded) = attribute
        .split_once('=')
        .ok_or_else(|| invalid_manifest(apk, "malformed aapt2 xmltree attribute"))?;
    let name = key
        .rsplit(':')
        .next()
        .unwrap_or(key)
        .split('(')
        .next()
        .unwrap_or_default()
        .trim();
    if name.is_empty() {
        return Err(invalid_manifest(apk, "aapt2 xmltree attribute has no name"));
    }
    let value = if let Some((_, raw)) = encoded.rsplit_once("(Raw: \"") {
        raw.strip_suffix("\")")
            .ok_or_else(|| invalid_manifest(apk, "malformed raw aapt2 attribute value"))?
            .to_owned()
    } else {
        let encoded = encoded.trim();
        if let Some(quoted) = encoded.strip_prefix('"') {
            quoted
                .split('"')
                .next()
                .ok_or_else(|| invalid_manifest(apk, "malformed quoted aapt2 attribute value"))?
                .to_owned()
        } else {
            encoded
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned()
        }
    };
    Ok((name.to_owned(), value))
}

fn child_nodes(nodes: &[XmlTreeNode], parent: usize, name: &str) -> Vec<usize> {
    nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| {
            (node.parent == Some(parent) && node.name == name).then_some(index)
        })
        .collect()
}

fn single_node(
    apk: &Utf8Path,
    nodes: &[XmlTreeNode],
    parent: Option<usize>,
    name: &str,
) -> Result<usize, AndroidError> {
    let matches = nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.parent == parent && node.name == name).then_some(index))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(invalid_manifest(
            apk,
            format!(
                "compiled manifest expected one `{name}` element, found {}",
                matches.len()
            ),
        ))
    }
}

fn required_attribute<'a>(
    apk: &Utf8Path,
    node: &'a XmlTreeNode,
    name: &str,
) -> Result<&'a str, AndroidError> {
    node.attributes
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| {
            invalid_manifest(
                apk,
                format!("compiled `{}` element is missing `{name}`", node.name),
            )
        })
}

fn require_attribute(
    apk: &Utf8Path,
    node: &XmlTreeNode,
    name: &str,
    expected: &str,
) -> Result<(), AndroidError> {
    let actual = required_attribute(apk, node, name)?;
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_manifest(
            apk,
            format!(
                "compiled `{}` attribute `{name}` expected `{expected}`, found `{actual}`",
                node.name
            ),
        ))
    }
}

fn named_children(
    apk: &Utf8Path,
    nodes: &[XmlTreeNode],
    parent: usize,
    kind: &str,
) -> Result<BTreeSet<String>, AndroidError> {
    child_nodes(nodes, parent, kind)
        .into_iter()
        .map(|index| required_attribute(apk, &nodes[index], "name").map(ToOwned::to_owned))
        .collect()
}

fn require_metadata(
    apk: &Utf8Path,
    nodes: &[XmlTreeNode],
    parent: usize,
    name: &str,
    value: Option<(&str, &str)>,
) -> Result<(), AndroidError> {
    let matches = child_nodes(nodes, parent, "meta-data")
        .into_iter()
        .filter(|index| {
            nodes[*index]
                .attributes
                .get("name")
                .is_some_and(|actual| actual == name)
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(invalid_manifest(
            apk,
            format!("compiled component expected one `{name}` metadata entry"),
        ));
    }
    if let Some((attribute, expected)) = value {
        require_attribute(apk, &nodes[matches[0]], attribute, expected)?;
    } else if !nodes[matches[0]].attributes.contains_key("resource") {
        return Err(invalid_manifest(
            apk,
            format!("compiled `{name}` metadata has no resource"),
        ));
    }
    Ok(())
}

fn require_intent_filter(
    apk: &Utf8Path,
    nodes: &[XmlTreeNode],
    parent: usize,
    actions: &[&str],
    categories: &[&str],
) -> Result<(), AndroidError> {
    let expected_actions = actions.iter().map(|value| (*value).to_owned()).collect();
    let expected_categories = categories.iter().map(|value| (*value).to_owned()).collect();
    let mut found = 0;
    for filter in child_nodes(nodes, parent, "intent-filter") {
        if named_children(apk, nodes, filter, "action")? == expected_actions
            && named_children(apk, nodes, filter, "category")? == expected_categories
        {
            found += 1;
        }
    }
    if found == 1 {
        Ok(())
    } else {
        Err(invalid_manifest(
            apk,
            format!("compiled component expected one intent filter for actions {actions:?}"),
        ))
    }
}

fn expected_deep_link_filters(
    config: &FerryConfig,
) -> BTreeSet<(String, Option<String>, Option<String>)> {
    let hosts = if config.capabilities.deep_links.allowed_hosts.is_empty() {
        vec![None]
    } else {
        config
            .capabilities
            .deep_links
            .allowed_hosts
            .iter()
            .cloned()
            .map(Some)
            .collect()
    };
    let paths = if config.capabilities.deep_links.allowed_actions.is_empty() {
        vec![None]
    } else {
        config
            .capabilities
            .deep_links
            .allowed_actions
            .iter()
            .map(|action| Some(format!("/{action}")))
            .collect()
    };
    let mut filters = BTreeSet::new();
    for scheme in &config.capabilities.deep_links.schemes {
        for host in &hosts {
            for path in &paths {
                filters.insert((scheme.clone(), host.clone(), path.clone()));
            }
        }
    }
    filters
}

fn invalid_manifest(apk: &Utf8Path, reason: impl Into<String>) -> AndroidError {
    AndroidError::InvalidArtifact {
        path: apk.to_owned(),
        reason: reason.into(),
    }
}

fn archive_entry_names(apk: &Utf8Path) -> Result<BTreeSet<String>, AndroidError> {
    let file = File::open(apk).map_err(|source| io_error("open AAPT2 APK", apk, source))?;
    let mut archive = ZipArchive::new(file).map_err(|error| AndroidError::Zip {
        path: apk.to_owned(),
        message: error.to_string(),
    })?;
    let mut names = BTreeSet::new();
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| AndroidError::Zip {
            path: apk.to_owned(),
            message: error.to_string(),
        })?;
        validate_archive_name(apk, entry.name())?;
        if !names.insert(entry.name().to_owned()) {
            return Err(AndroidError::InvalidArtifact {
                path: apk.to_owned(),
                reason: format!("AAPT2 produced duplicate ZIP entry `{}`", entry.name()),
            });
        }
    }
    Ok(names)
}

fn validate_archive_name(apk: &Utf8Path, name: &str) -> Result<(), AndroidError> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
    {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: format!("unsafe ZIP entry name `{name}`"),
        });
    }
    Ok(())
}

fn validate_dex_header(path: &Utf8Path) -> Result<(), AndroidError> {
    let mut file = File::open(path).map_err(|source| io_error("open D8 output", path, source))?;
    let mut header = [0_u8; 8];
    file.read_exact(&mut header)
        .map_err(|source| io_error("read D8 output header", path, source))?;
    if valid_dex_magic(header) {
        Ok(())
    } else {
        Err(AndroidError::InvalidArtifact {
            path: path.to_owned(),
            reason: "invalid DEX magic header".to_owned(),
        })
    }
}

fn valid_dex_magic(header: [u8; 8]) -> bool {
    &header[..4] == b"dex\n" && header[4..7].iter().all(u8::is_ascii_digit) && header[7] == 0
}

fn valid_dex_name(name: &str) -> bool {
    dex_index(name).is_some()
}

fn dex_index(name: &str) -> Option<usize> {
    if name == "classes.dex" {
        return Some(1);
    }
    let index_text = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    let index = index_text.parse::<usize>().ok()?;
    (index >= 2 && index.to_string() == index_text).then_some(index)
}

fn validate_elf_reader(
    apk: &Utf8Path,
    reader: &mut impl Read,
    abi: AndroidAbi,
) -> Result<(), AndroidError> {
    let mut header = [0_u8; 20];
    reader
        .read_exact(&mut header)
        .map_err(|source| io_error("read native ELF header", apk, source))?;
    let expected_class = if abi == AndroidAbi::ArmeabiV7a { 1 } else { 2 };
    let expected_machine = match abi {
        AndroidAbi::Arm64V8a => 183,
        AndroidAbi::X86_64 => 62,
        AndroidAbi::ArmeabiV7a => 40,
    };
    let file_type = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    if &header[..4] != b"\x7fELF"
        || header[4] != expected_class
        || header[5] != 1
        || file_type != 3
        || machine != expected_machine
    {
        return Err(AndroidError::InvalidArtifact {
            path: apk.to_owned(),
            reason: format!(
                "native library ELF header does not match ABI {}",
                abi.apk_directory()
            ),
        });
    }
    Ok(())
}

fn extract_quoted_field(output: &str, line_prefix: &str, field: &str) -> Option<String> {
    let line = output.lines().find(|line| line.starts_with(line_prefix))?;
    let tail = line.split_once(field)?.1;
    let tail = tail.strip_prefix('\'')?;
    Some(tail.split_once('\'')?.0.to_owned())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::TempDir;

    use super::*;

    fn elf(abi: AndroidAbi) -> Vec<u8> {
        let mut header = vec![0_u8; 20];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = if abi == AndroidAbi::ArmeabiV7a { 1 } else { 2 };
        header[5] = 1;
        header[16..18].copy_from_slice(&3_u16.to_le_bytes());
        let machine = match abi {
            AndroidAbi::Arm64V8a => 183_u16,
            AndroidAbi::X86_64 => 62,
            AndroidAbi::ArmeabiV7a => 40,
        };
        header[18..20].copy_from_slice(&machine.to_le_bytes());
        header
    }

    fn base_apk(path: &Utf8Path) {
        let file = File::create(path).unwrap();
        let mut zip = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, contents) in [
            ("AndroidManifest.xml", b"manifest".as_slice()),
            ("resources.arsc", b"resources".as_slice()),
            ("res/drawable/ferry_icon.xml", b"icon".as_slice()),
            ("res/drawable/ferry_splash.xml", b"splash".as_slice()),
        ] {
            zip.start_file(name, options).unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();
    }

    #[test]
    fn injection_and_independent_validation_cover_dex_and_elf() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let apk = root.join("app.apk");
        let native = root.join("libweather.so");
        let dex = root.join("classes.dex");
        base_apk(&apk);
        fs::write(&native, elf(AndroidAbi::Arm64V8a)).unwrap();
        fs::write(&dex, b"dex\n035\0payload").unwrap();
        inject_apk_entries(
            &apk,
            &[NativeLibraryInput {
                abi: AndroidAbi::Arm64V8a,
                path: native,
            }],
            &[dex],
        )
        .unwrap();
        let validation = validate_apk_archive(
            &apk,
            &ApkExpectation {
                package_name: "com.example.weather".to_owned(),
                native_library_name: "weather".to_owned(),
                abis: vec![AndroidAbi::Arm64V8a],
                dex_required: true,
            },
        )
        .unwrap();
        assert_eq!(validation.native_abis, ["arm64-v8a"]);
        assert_eq!(validation.dex_files, 1);
    }

    #[test]
    fn badging_requires_exact_package_and_native_activity() {
        let apk = Utf8Path::new("app.apk");
        let expectation = ApkExpectation {
            package_name: "com.example.weather".to_owned(),
            native_library_name: "weather".to_owned(),
            abis: vec![],
            dex_required: false,
        };
        let mut validation = ApkValidation {
            package_name: String::new(),
            launcher_activity: String::new(),
            entries: vec![],
            native_abis: vec![],
            dex_files: 0,
            manifest: Box::default(),
        };
        validate_aapt2_badging(
            apk,
            b"package: name='com.example.weather' versionCode='1'\nlaunchable-activity: name='org.rustferry.bridge.FerryActivity' label='' icon=''\n",
            &expectation,
            &mut validation,
        )
        .unwrap();
        assert_eq!(validation.package_name, "com.example.weather");
        assert_eq!(validation.launcher_activity, crate::ACTIVITY_CLASS);
    }

    #[test]
    fn compiled_manifest_matches_capabilities_and_records_stable_evidence() {
        let apk = Utf8Path::new("app.apk");
        let mut config = FerryConfig::starter("Weather", "com.example.weather");
        config.capabilities.share.enabled = true;
        config.capabilities.deep_links.schemes = vec!["weather".to_owned()];
        config.capabilities.deep_links.allowed_hosts = vec!["forecast.example".to_owned()];
        config.capabilities.deep_links.allowed_actions = vec!["today".to_owned()];
        config.extensions.widget.enabled = true;
        config.extensions.widget.app_group = Some("group.com.example.weather".to_owned());
        let expectation = ApkExpectation {
            package_name: "com.example.weather".to_owned(),
            native_library_name: "weather".to_owned(),
            abis: vec![],
            dex_required: true,
        };
        let xmltree = br#"
  E: manifest
    A: package="com.example.weather" (Raw: "com.example.weather")
      E: uses-permission
        A: http://schemas.android.com/apk/res/android:name="android.permission.ACCESS_NETWORK_STATE" (Raw: "android.permission.ACCESS_NETWORK_STATE")
      E: uses-permission
        A: http://schemas.android.com/apk/res/android:name="android.permission.POST_NOTIFICATIONS" (Raw: "android.permission.POST_NOTIFICATIONS")
      E: uses-permission
        A: http://schemas.android.com/apk/res/android:name="android.permission.VIBRATE" (Raw: "android.permission.VIBRATE")
      E: uses-sdk
        A: http://schemas.android.com/apk/res/android:minSdkVersion=26
        A: http://schemas.android.com/apk/res/android:targetSdkVersion=35
      E: application
        A: http://schemas.android.com/apk/res/android:hasCode=true
          E: activity
            A: http://schemas.android.com/apk/res/android:name="org.rustferry.bridge.FerryActivity" (Raw: "org.rustferry.bridge.FerryActivity")
            A: http://schemas.android.com/apk/res/android:exported=true
            A: http://schemas.android.com/apk/res/android:launchMode=2 (Raw: "singleTop")
              E: meta-data
                A: http://schemas.android.com/apk/res/android:name="android.app.lib_name" (Raw: "android.app.lib_name")
                A: http://schemas.android.com/apk/res/android:value="weather" (Raw: "weather")
              E: intent-filter
                  E: action
                    A: http://schemas.android.com/apk/res/android:name="android.intent.action.MAIN" (Raw: "android.intent.action.MAIN")
                  E: category
                    A: http://schemas.android.com/apk/res/android:name="android.intent.category.LAUNCHER" (Raw: "android.intent.category.LAUNCHER")
              E: intent-filter
                  E: action
                    A: http://schemas.android.com/apk/res/android:name="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
                  E: category
                    A: http://schemas.android.com/apk/res/android:name="android.intent.category.DEFAULT" (Raw: "android.intent.category.DEFAULT")
                  E: category
                    A: http://schemas.android.com/apk/res/android:name="android.intent.category.BROWSABLE" (Raw: "android.intent.category.BROWSABLE")
                  E: data
                    A: http://schemas.android.com/apk/res/android:scheme="weather" (Raw: "weather")
                    A: http://schemas.android.com/apk/res/android:host="forecast.example" (Raw: "forecast.example")
                    A: http://schemas.android.com/apk/res/android:pathPrefix="/today" (Raw: "/today")
          E: receiver
            A: http://schemas.android.com/apk/res/android:name="org.rustferry.bridge.FerryNotificationReceiver" (Raw: "org.rustferry.bridge.FerryNotificationReceiver")
            A: http://schemas.android.com/apk/res/android:enabled=true
            A: http://schemas.android.com/apk/res/android:exported=false
          E: receiver
            A: http://schemas.android.com/apk/res/android:name="org.rustferry.bridge.FerryWidgetProvider" (Raw: "org.rustferry.bridge.FerryWidgetProvider")
            A: http://schemas.android.com/apk/res/android:enabled=true
            A: http://schemas.android.com/apk/res/android:exported=false
              E: intent-filter
                  E: action
                    A: http://schemas.android.com/apk/res/android:name="android.appwidget.action.APPWIDGET_UPDATE" (Raw: "android.appwidget.action.APPWIDGET_UPDATE")
              E: meta-data
                A: http://schemas.android.com/apk/res/android:name="android.appwidget.provider" (Raw: "android.appwidget.provider")
                A: http://schemas.android.com/apk/res/android:resource=@0x7f040000
          E: provider
            A: http://schemas.android.com/apk/res/android:name="org.rustferry.bridge.FerryFileProvider" (Raw: "org.rustferry.bridge.FerryFileProvider")
            A: http://schemas.android.com/apk/res/android:authorities="com.example.weather.ferry-files" (Raw: "com.example.weather.ferry-files")
            A: http://schemas.android.com/apk/res/android:exported=false
            A: http://schemas.android.com/apk/res/android:grantUriPermissions=true
"#;
        let mut validation = ApkValidation {
            package_name: String::new(),
            launcher_activity: String::new(),
            entries: vec![],
            native_abis: vec![],
            dex_files: 0,
            manifest: Box::default(),
        };
        validate_aapt2_manifest(apk, xmltree, &expectation, &config, 35, &mut validation).unwrap();
        assert_eq!(
            validation.manifest.permissions,
            [
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.POST_NOTIFICATIONS",
                "android.permission.VIBRATE",
            ]
        );
        assert_eq!(
            validation.manifest.deep_link_filters,
            ["scheme=weather;host=forecast.example;pathPrefix=/today"]
        );
        assert!(
            validation
                .manifest
                .components
                .contains(&format!("activity:{}", crate::ACTIVITY_CLASS))
        );

        let wrong_host = String::from_utf8(xmltree.to_vec())
            .unwrap()
            .replace("forecast.example", "attacker.example");
        assert!(
            validate_aapt2_manifest(
                apk,
                wrong_host.as_bytes(),
                &expectation,
                &config,
                35,
                &mut validation,
            )
            .is_err()
        );

        let xmltree = String::from_utf8(xmltree.to_vec()).unwrap();
        let uses_sdk = concat!(
            "      E: uses-sdk\n",
            "        A: http://schemas.android.com/apk/res/android:minSdkVersion=26\n",
            "        A: http://schemas.android.com/apk/res/android:targetSdkVersion=35\n",
        );
        for (actual, expected_error) in [
            (
                xmltree.replace("minSdkVersion=26", "minSdkVersion=25"),
                "attribute `minSdkVersion` expected `26`, found `25`",
            ),
            (
                xmltree.replace("targetSdkVersion=35", "targetSdkVersion=34"),
                "attribute `targetSdkVersion` expected `35`, found `34`",
            ),
            (
                xmltree.replace(uses_sdk, ""),
                "expected one `uses-sdk` element, found 0",
            ),
            (
                xmltree.replace(uses_sdk, &format!("{uses_sdk}{uses_sdk}")),
                "expected one `uses-sdk` element, found 2",
            ),
        ] {
            let error = validate_aapt2_manifest(
                apk,
                actual.as_bytes(),
                &expectation,
                &config,
                35,
                &mut validation,
            )
            .unwrap_err();
            assert!(error.to_string().contains(expected_error), "{error}");
        }
    }

    #[test]
    fn validation_rejects_unexpected_native_libraries_and_noncanonical_dex_names() {
        let temp = TempDir::new().unwrap();
        let root = Utf8PathBuf::from_path_buf(temp.path().to_owned()).unwrap();
        let apk = root.join("app.apk");
        let native = root.join("libweather.so");
        let unexpected = root.join("libother.so");
        base_apk(&apk);
        fs::write(&native, elf(AndroidAbi::Arm64V8a)).unwrap();
        fs::write(&unexpected, elf(AndroidAbi::X86_64)).unwrap();
        inject_apk_entries(
            &apk,
            &[
                NativeLibraryInput {
                    abi: AndroidAbi::Arm64V8a,
                    path: native,
                },
                NativeLibraryInput {
                    abi: AndroidAbi::X86_64,
                    path: unexpected,
                },
            ],
            &[],
        )
        .unwrap();
        let error = validate_apk_archive(
            &apk,
            &ApkExpectation {
                package_name: "com.example.weather".to_owned(),
                native_library_name: "weather".to_owned(),
                abis: vec![AndroidAbi::Arm64V8a],
                dex_required: false,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected native library"));
        assert!(!valid_dex_name("classes02.dex"));
    }
}
