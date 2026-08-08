use std::fs::{self, OpenOptions};
use std::io::Write as _;

use camino::{Utf8Path, Utf8PathBuf};
use image::{
    DynamicImage, ExtendedColorType, ImageEncoder as _, ImageFormat,
    codecs::png::{CompressionType, FilterType as PngFilterType, PngEncoder},
    imageops::FilterType as ResizeFilterType,
};
use rustferry_core::{AssetError, PngMetadata, ProjectAssets};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MIN_SOURCE_EDGE: u32 = 1_024;

const ANDROID_ICON_SIZES: [(&str, u32); 5] = [
    ("mipmap-mdpi/ferry_icon.png", 48),
    ("mipmap-hdpi/ferry_icon.png", 72),
    ("mipmap-xhdpi/ferry_icon.png", 96),
    ("mipmap-xxhdpi/ferry_icon.png", 144),
    ("mipmap-xxxhdpi/ferry_icon.png", 192),
];

const IOS_ICON_SIZES: [IosIcon; 11] = [
    IosIcon::new("20", "2x", "iphone", 40),
    IosIcon::new("20", "3x", "iphone", 60),
    IosIcon::new("29", "2x", "iphone", 58),
    IosIcon::new("29", "3x", "iphone", 87),
    IosIcon::new("40", "2x", "iphone", 80),
    IosIcon::new("40", "3x", "iphone", 120),
    IosIcon::new("60", "2x", "iphone", 120),
    IosIcon::new("60", "3x", "iphone", 180),
    IosIcon::new("76", "2x", "ipad", 152),
    IosIcon::new("83.5", "2x", "ipad", 167),
    IosIcon::new("1024", "1x", "ios-marketing", 1_024),
];

/// One actionable release-readiness problem in the project source assets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssetIssue {
    /// Stable diagnostic identifier.
    pub code: &'static str,
    /// Exact failed invariant.
    pub message: String,
    /// Concrete remediation.
    pub help: &'static str,
}

/// Validation result for the user-owned icon and splash sources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssetCheck {
    /// Project root containing `assets/`.
    pub project: Utf8PathBuf,
    /// Icon PNG metadata.
    pub icon: PngMetadata,
    /// Splash PNG metadata.
    pub splash: PngMetadata,
    /// Stable digest of both source files.
    pub fingerprint: String,
    /// Whether generation can produce release-ready platform inputs.
    pub release_ready: bool,
    /// Actionable validation problems.
    pub issues: Vec<AssetIssue>,
}

/// Deterministic generated platform asset set below `target/ferry/assets`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedAssetSet {
    /// Stable source fingerprint.
    pub fingerprint: String,
    /// Generated asset-catalog root.
    pub root: Utf8PathBuf,
    /// Generated paths relative to `root`.
    pub files: Vec<Utf8PathBuf>,
    /// Whether an existing complete generated set was reused.
    pub cache_hit: bool,
}

/// Deterministic in-memory platform derivatives from one validated source snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedPlatformAssets {
    /// Stable source fingerprint.
    pub fingerprint: String,
    /// Generated paths and bytes relative to the asset-set root.
    pub files: Vec<(Utf8PathBuf, Vec<u8>)>,
}

/// Platform subtree within a generated asset set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedAssetPlatform {
    /// Android density-aware resources.
    Android,
    /// Apple asset catalog.
    Ios,
}

impl GeneratedAssetPlatform {
    const fn directory(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

/// Validate source dimensions, color representation, and release constraints.
///
/// # Errors
///
/// Returns a typed error when either source file is missing, unsafe, oversized, or malformed.
pub fn check_project_assets(project: &Utf8Path) -> Result<AssetCheck, AssetPipelineError> {
    let project = canonical_project(project)?;
    let assets = ProjectAssets::load(&project)?;
    let icon = assets.icon_metadata();
    let splash = assets.splash_metadata();
    let mut issues = icon_issues(icon);
    if splash.width < MIN_SOURCE_EDGE || splash.height < MIN_SOURCE_EDGE {
        issues.push(AssetIssue {
            code: "ferry.assets.splash_too_small",
            message: format!(
                "splash is {}x{}; both edges must be at least {MIN_SOURCE_EDGE}px",
                splash.width, splash.height
            ),
            help: "Replace assets/splash.png with a larger RGB PNG, then run `cargo ferry assets check`.",
        });
    }
    Ok(AssetCheck {
        project,
        icon,
        splash,
        fingerprint: assets.fingerprint().to_owned(),
        release_ready: issues.is_empty(),
        issues,
    })
}

/// Generate Android density images and an iOS asset catalog atomically.
///
/// When `source` is supplied it becomes the source for both icon and splash derivatives without
/// modifying the user's source tree. Otherwise `assets/icon.png` and `assets/splash.png` are used.
///
/// # Errors
///
/// Returns a typed error for unsafe roots, invalid source images, release-readiness failures, or
/// filesystem writes. Existing complete output is reused; partial output is never overwritten.
pub fn generate_platform_assets(
    project: &Utf8Path,
    source: Option<&Utf8Path>,
) -> Result<GeneratedAssetSet, AssetPipelineError> {
    let project = canonical_project(project)?;
    let project_assets = ProjectAssets::load(&project)?;
    let (icon_bytes, splash_bytes, fingerprint) = if let Some(source) = source {
        let source = canonical_source(&project, source)?;
        let bytes = read_source(&source)?;
        let fingerprint = source_fingerprint(&bytes);
        (bytes.clone(), bytes, fingerprint)
    } else {
        (
            project_assets.icon().to_vec(),
            project_assets.splash().to_vec(),
            project_assets.fingerprint().to_owned(),
        )
    };

    let (icon, splash) = decode_and_validate_sources(&icon_bytes, &splash_bytes)?;
    let asset_root = safe_asset_root(&project)?;
    let destination = asset_root.join(&fingerprint);
    if destination.exists() {
        let files = validate_cached_set(&destination, &fingerprint)?;
        return Ok(GeneratedAssetSet {
            fingerprint,
            root: destination,
            files,
            cache_hit: true,
        });
    }
    let rendered = render_decoded_platform_assets(&icon, &splash, fingerprint, None)?;
    let fingerprint = rendered.fingerprint.clone();

    let temporary = tempfile::Builder::new()
        .prefix(".cargo-ferry-assets-")
        .tempdir_in(&asset_root)
        .map_err(|source| AssetPipelineError::Io {
            operation: "create asset staging directory",
            path: asset_root.clone(),
            source,
        })?;
    let staging = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf())
        .map_err(AssetPipelineError::NonUtf8Path)?;

    let mut files = Vec::with_capacity(rendered.files.len());
    let mut manifest_files = Vec::with_capacity(rendered.files.len());
    for (relative, bytes) in rendered.files {
        write_new(&staging, &relative, &bytes)?;
        manifest_files.push(AssetManifestFile {
            path: relative.clone(),
            sha256: sha256_bytes(&bytes),
        });
        files.push(relative);
    }
    let manifest_path = Utf8PathBuf::from("manifest.json");
    write_json(
        &staging,
        &manifest_path,
        &AssetManifest {
            schema_version: 2,
            fingerprint: fingerprint.clone(),
            files: manifest_files,
        },
    )?;
    files.push(manifest_path);

    let staging = Utf8Path::from_path(temporary.path())
        .ok_or_else(|| AssetPipelineError::NonUtf8Path(temporary.path().to_path_buf()))?;
    let cache_hit = match fs::rename(staging, &destination) {
        Ok(()) => false,
        Err(publish_error) => {
            drop(temporary);
            match fs::symlink_metadata(&destination) {
                Ok(_) => {
                    files = validate_cached_set(&destination, &fingerprint)?;
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(AssetPipelineError::Io {
                        operation: "commit generated asset set",
                        path: destination,
                        source: publish_error,
                    });
                }
                Err(source) => {
                    return Err(AssetPipelineError::Io {
                        operation: "inspect concurrent generated asset set",
                        path: destination,
                        source,
                    });
                }
            }
        }
    };

    Ok(GeneratedAssetSet {
        fingerprint,
        root: destination,
        files,
        cache_hit,
    })
}

/// Render all platform derivatives without writing generated output.
///
/// # Errors
///
/// Returns a typed error when the validated PNG snapshot cannot produce release-ready outputs.
pub fn render_platform_assets(
    assets: &ProjectAssets,
) -> Result<RenderedPlatformAssets, AssetPipelineError> {
    render_platform_asset_bytes(
        assets.icon(),
        assets.splash(),
        assets.fingerprint().to_owned(),
    )
}

/// Render one platform's derivatives without writing generated output.
///
/// # Errors
///
/// Returns a typed error when the validated PNG snapshot cannot produce release-ready outputs.
pub fn render_platform_assets_for(
    assets: &ProjectAssets,
    platform: GeneratedAssetPlatform,
) -> Result<RenderedPlatformAssets, AssetPipelineError> {
    let (icon, splash) = decode_and_validate_sources(assets.icon(), assets.splash())?;
    render_decoded_platform_assets(
        &icon,
        &splash,
        assets.fingerprint().to_owned(),
        Some(platform),
    )
}

/// Read one platform subtree from a complete generated set.
///
/// Returned paths are relative to the platform directory. Every path component is checked again
/// immediately before reading, so a modified cache cannot redirect packaging through a symlink.
///
/// # Errors
///
/// Returns a typed error when the cache is incomplete, unsafe, or unreadable.
pub fn read_generated_platform_assets(
    generated: &GeneratedAssetSet,
    platform: GeneratedAssetPlatform,
) -> Result<Vec<(Utf8PathBuf, Vec<u8>)>, AssetPipelineError> {
    let files = validate_cached_set(&generated.root, &generated.fingerprint)?;
    let prefix = Utf8Path::new(platform.directory());
    let mut loaded = Vec::new();
    for relative in files {
        let Ok(platform_relative) = relative.strip_prefix(prefix) else {
            continue;
        };
        if platform_relative.as_str().is_empty() {
            continue;
        }
        let path = generated.root.join(&relative);
        let bytes = fs::read(&path).map_err(|source| AssetPipelineError::Io {
            operation: "read generated platform asset",
            path,
            source,
        })?;
        loaded.push((platform_relative.to_owned(), bytes));
    }
    loaded.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(loaded)
}

fn render_platform_asset_bytes(
    icon_bytes: &[u8],
    splash_bytes: &[u8],
    fingerprint: String,
) -> Result<RenderedPlatformAssets, AssetPipelineError> {
    let (icon, splash) = decode_and_validate_sources(icon_bytes, splash_bytes)?;
    render_decoded_platform_assets(&icon, &splash, fingerprint, None)
}

fn decode_and_validate_sources(
    icon_bytes: &[u8],
    splash_bytes: &[u8],
) -> Result<(DynamicImage, DynamicImage), AssetPipelineError> {
    let icon = decode_source(icon_bytes, "icon")?;
    let splash = decode_source(splash_bytes, "splash")?;
    let issues = decoded_issues(&icon, &splash);
    if !issues.is_empty() {
        return Err(AssetPipelineError::NotReleaseReady { issues });
    }
    Ok((icon, splash))
}

fn render_decoded_platform_assets(
    icon: &DynamicImage,
    splash: &DynamicImage,
    fingerprint: String,
    platform: Option<GeneratedAssetPlatform>,
) -> Result<RenderedPlatformAssets, AssetPipelineError> {
    let mut files = Vec::new();
    if platform.is_none() || platform == Some(GeneratedAssetPlatform::Android) {
        for (relative, size) in ANDROID_ICON_SIZES {
            let relative = Utf8PathBuf::from(format!("android/{relative}"));
            files.push((relative.clone(), encode_png(&relative, icon, size)?));
        }
        let android_splash = Utf8PathBuf::from("android/drawable-nodpi/ferry_splash.png");
        files.push((
            android_splash.clone(),
            encode_png(&android_splash, splash, 1_024)?,
        ));
    }
    if platform.is_none() || platform == Some(GeneratedAssetPlatform::Ios) {
        let mut ios_images = Vec::new();
        for icon_spec in IOS_ICON_SIZES {
            let filename = icon_spec.filename();
            let relative =
                Utf8PathBuf::from(format!("ios/Assets.xcassets/AppIcon.appiconset/{filename}"));
            files.push((
                relative.clone(),
                encode_png(&relative, icon, icon_spec.pixels)?,
            ));
            ios_images.push(IosImageEntry {
                filename,
                idiom: icon_spec.idiom,
                scale: icon_spec.scale,
                size: Some(format!("{}x{}", icon_spec.points, icon_spec.points)),
            });
        }
        let app_icon_contents =
            Utf8PathBuf::from("ios/Assets.xcassets/AppIcon.appiconset/Contents.json");
        files.push((
            app_icon_contents,
            json_bytes(&IosContents::new(ios_images))?,
        ));

        let mut launch_images = Vec::new();
        for (scale, pixels) in [("1x", 512), ("2x", 1_024), ("3x", 1_536)] {
            let filename = format!("FerryLaunch-{scale}.png");
            let relative = Utf8PathBuf::from(format!(
                "ios/Assets.xcassets/FerryLaunch.imageset/{filename}"
            ));
            files.push((relative.clone(), encode_png(&relative, splash, pixels)?));
            launch_images.push(IosImageEntry {
                filename,
                idiom: "universal",
                scale,
                size: None,
            });
        }
        let launch_contents =
            Utf8PathBuf::from("ios/Assets.xcassets/FerryLaunch.imageset/Contents.json");
        files.push((
            launch_contents,
            json_bytes(&IosContents::new(launch_images))?,
        ));
        files.push((
            Utf8PathBuf::from("ios/Assets.xcassets/Contents.json"),
            json_bytes(&IosContents::new(Vec::new()))?,
        ));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(RenderedPlatformAssets { fingerprint, files })
}

fn canonical_project(project: &Utf8Path) -> Result<Utf8PathBuf, AssetPipelineError> {
    let metadata = fs::symlink_metadata(project).map_err(|source| AssetPipelineError::Io {
        operation: "inspect project root",
        path: project.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AssetPipelineError::UnsafePath(project.to_owned()));
    }
    project
        .canonicalize_utf8()
        .map_err(|source| AssetPipelineError::Io {
            operation: "canonicalize project root",
            path: project.to_owned(),
            source,
        })
}

fn canonical_source(
    project: &Utf8Path,
    source: &Utf8Path,
) -> Result<Utf8PathBuf, AssetPipelineError> {
    let candidate = if source.is_absolute() {
        source.to_owned()
    } else {
        project.join(source)
    };
    let metadata = fs::symlink_metadata(&candidate).map_err(|source| AssetPipelineError::Io {
        operation: "inspect asset source",
        path: candidate.clone(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AssetPipelineError::UnsafePath(candidate));
    }
    let canonical = candidate
        .canonicalize_utf8()
        .map_err(|source| AssetPipelineError::Io {
            operation: "canonicalize asset source",
            path: candidate.clone(),
            source,
        })?;
    if !canonical.starts_with(project) {
        return Err(AssetPipelineError::SourceOutsideProject(canonical));
    }
    Ok(canonical)
}

fn safe_asset_root(project: &Utf8Path) -> Result<Utf8PathBuf, AssetPipelineError> {
    let mut current = project.to_owned();
    for component in ["target", "ferry", "assets"] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(AssetPipelineError::UnsafePath(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&current).map_err(|source| {
                            AssetPipelineError::Io {
                                operation: "inspect concurrently created asset directory",
                                path: current.clone(),
                                source,
                            }
                        })?;
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(AssetPipelineError::UnsafePath(current));
                        }
                    }
                    Err(source) => {
                        return Err(AssetPipelineError::Io {
                            operation: "create generated asset directory",
                            path: current,
                            source,
                        });
                    }
                }
            }
            Err(source) => {
                return Err(AssetPipelineError::Io {
                    operation: "inspect generated asset directory",
                    path: current,
                    source,
                });
            }
        }
    }
    Ok(current)
}

fn read_source(path: &Utf8Path) -> Result<Vec<u8>, AssetPipelineError> {
    let size = fs::metadata(path)
        .map_err(|source| AssetPipelineError::Io {
            operation: "inspect asset source",
            path: path.to_owned(),
            source,
        })?
        .len();
    if size > MAX_SOURCE_BYTES {
        return Err(AssetPipelineError::SourceTooLarge {
            path: path.to_owned(),
            size,
        });
    }
    fs::read(path).map_err(|source| AssetPipelineError::Io {
        operation: "read asset source",
        path: path.to_owned(),
        source,
    })
}

fn decode_source(bytes: &[u8], role: &'static str) -> Result<DynamicImage, AssetPipelineError> {
    image::load_from_memory_with_format(bytes, ImageFormat::Png)
        .map_err(|source| AssetPipelineError::Decode { role, source })
}

fn decoded_issues(icon: &DynamicImage, splash: &DynamicImage) -> Vec<AssetIssue> {
    let mut issues = icon_issues(PngMetadata {
        width: icon.width(),
        height: icon.height(),
        bit_depth: 8,
        color_type: png_color_type(icon.color()),
        has_alpha: icon.color().has_alpha(),
    });
    if splash.width() < MIN_SOURCE_EDGE || splash.height() < MIN_SOURCE_EDGE {
        issues.push(AssetIssue {
            code: "ferry.assets.splash_too_small",
            message: format!(
                "splash is {}x{}; both edges must be at least {MIN_SOURCE_EDGE}px",
                splash.width(),
                splash.height()
            ),
            help: "Provide a larger RGB PNG and rerun `cargo ferry assets generate`.",
        });
    }
    issues
}

fn icon_issues(icon: PngMetadata) -> Vec<AssetIssue> {
    let mut issues = Vec::new();
    if icon.width != icon.height {
        issues.push(AssetIssue {
            code: "ferry.assets.icon_not_square",
            message: format!("icon is {}x{}; it must be square", icon.width, icon.height),
            help: "Use a square source PNG, ideally 1024x1024.",
        });
    }
    if icon.width < MIN_SOURCE_EDGE || icon.height < MIN_SOURCE_EDGE {
        issues.push(AssetIssue {
            code: "ferry.assets.icon_too_small",
            message: format!(
                "icon is {}x{}; both edges must be at least {MIN_SOURCE_EDGE}px",
                icon.width, icon.height
            ),
            help: "Replace assets/icon.png with a 1024x1024 or larger RGB PNG.",
        });
    }
    if icon.has_alpha {
        issues.push(AssetIssue {
            code: "ferry.assets.icon_has_alpha",
            message: "icon contains an alpha channel or transparency chunk".to_owned(),
            help: "Flatten the icon onto an opaque background before generating iOS assets.",
        });
    }
    issues
}

const fn png_color_type(color: image::ColorType) -> u8 {
    match color {
        image::ColorType::L8 | image::ColorType::L16 => 0,
        image::ColorType::Rgb8 | image::ColorType::Rgb16 | image::ColorType::Rgb32F => 2,
        image::ColorType::La8 | image::ColorType::La16 => 4,
        _ => 6,
    }
}

fn encode_png(
    relative: &Utf8Path,
    source: &DynamicImage,
    size: u32,
) -> Result<Vec<u8>, AssetPipelineError> {
    let resized = source
        .resize_exact(size, size, ResizeFilterType::Triangle)
        .to_rgb8();
    let mut encoded = Vec::new();
    PngEncoder::new_with_quality(&mut encoded, CompressionType::Fast, PngFilterType::NoFilter)
        .write_image(
            resized.as_raw(),
            resized.width(),
            resized.height(),
            ExtendedColorType::Rgb8,
        )
        .map_err(|source| AssetPipelineError::Encode {
            path: relative.to_owned(),
            source,
        })?;
    Ok(encoded)
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>, AssetPipelineError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(AssetPipelineError::Json)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_json(
    root: &Utf8Path,
    relative: &Utf8Path,
    value: &impl Serialize,
) -> Result<(), AssetPipelineError> {
    let bytes = json_bytes(value)?;
    write_new(root, relative, &bytes)
}

fn write_new(root: &Utf8Path, relative: &Utf8Path, bytes: &[u8]) -> Result<(), AssetPipelineError> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, camino::Utf8Component::ParentDir))
    {
        return Err(AssetPipelineError::UnsafePath(relative.to_owned()));
    }
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| AssetPipelineError::Io {
            operation: "create generated asset parent",
            path: parent.to_owned(),
            source,
        })?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|source| AssetPipelineError::Io {
            operation: "create generated asset",
            path: path.clone(),
            source,
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|source| AssetPipelineError::Io {
            operation: "write generated asset",
            path,
            source,
        })
}

fn source_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"cargo-ferry-generated-assets-v1\0");
    hasher.update(bytes);
    hex::encode(&hasher.finalize()[..12])
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_cached_set(
    root: &Utf8Path,
    fingerprint: &str,
) -> Result<Vec<Utf8PathBuf>, AssetPipelineError> {
    let metadata = fs::symlink_metadata(root).map_err(|source| AssetPipelineError::Io {
        operation: "inspect cached asset set",
        path: root.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AssetPipelineError::UnsafePath(root.to_owned()));
    }
    let manifest_relative = Utf8Path::new("manifest.json");
    validate_cached_file(root, manifest_relative)?;
    let path = root.join(manifest_relative);
    let bytes = fs::read(&path).map_err(|source| AssetPipelineError::Io {
        operation: "read cached asset manifest",
        path: path.clone(),
        source,
    })?;
    let manifest: AssetManifest =
        serde_json::from_slice(&bytes).map_err(AssetPipelineError::Json)?;
    let manifest_paths = manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if manifest.schema_version != 2
        || manifest.fingerprint != fingerprint
        || manifest_paths != expected_asset_paths()
    {
        return Err(AssetPipelineError::InvalidCache(root.to_owned()));
    }
    for file in &manifest.files {
        validate_cached_file(root, &file.path)?;
        let path = root.join(&file.path);
        let bytes = fs::read(&path).map_err(|source| AssetPipelineError::Io {
            operation: "read cached asset for integrity validation",
            path,
            source,
        })?;
        if sha256_bytes(&bytes) != file.sha256 {
            return Err(AssetPipelineError::InvalidCache(root.to_owned()));
        }
    }
    let mut files = manifest_paths;
    files.push(Utf8PathBuf::from("manifest.json"));
    Ok(files)
}

fn expected_asset_paths() -> Vec<Utf8PathBuf> {
    let mut paths = ANDROID_ICON_SIZES
        .into_iter()
        .map(|(relative, _)| Utf8PathBuf::from(format!("android/{relative}")))
        .collect::<Vec<_>>();
    paths.push(Utf8PathBuf::from("android/drawable-nodpi/ferry_splash.png"));
    paths.extend(IOS_ICON_SIZES.into_iter().map(|icon| {
        Utf8PathBuf::from(format!(
            "ios/Assets.xcassets/AppIcon.appiconset/{}",
            icon.filename()
        ))
    }));
    paths.push(Utf8PathBuf::from(
        "ios/Assets.xcassets/AppIcon.appiconset/Contents.json",
    ));
    paths.extend(["1x", "2x", "3x"].into_iter().map(|scale| {
        Utf8PathBuf::from(format!(
            "ios/Assets.xcassets/FerryLaunch.imageset/FerryLaunch-{scale}.png"
        ))
    }));
    paths.extend([
        Utf8PathBuf::from("ios/Assets.xcassets/FerryLaunch.imageset/Contents.json"),
        Utf8PathBuf::from("ios/Assets.xcassets/Contents.json"),
    ]);
    paths.sort();
    paths
}

fn validate_cached_file(root: &Utf8Path, relative: &Utf8Path) -> Result<(), AssetPipelineError> {
    if relative.as_str().is_empty() || relative.is_absolute() {
        return Err(AssetPipelineError::InvalidCache(root.to_owned()));
    }
    let components = relative.components().collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| !matches!(component, camino::Utf8Component::Normal(_)))
    {
        return Err(AssetPipelineError::InvalidCache(root.to_owned()));
    }
    let mut current = root.to_owned();
    for (index, component) in components.iter().enumerate() {
        let camino::Utf8Component::Normal(component) = component else {
            unreachable!("validated normal path component")
        };
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(AssetPipelineError::InvalidCache(root.to_owned()));
            }
            Err(source) => {
                return Err(AssetPipelineError::Io {
                    operation: "inspect cached asset path",
                    path: current,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(AssetPipelineError::UnsafePath(current));
        }
        let final_component = index + 1 == components.len();
        if (final_component && !metadata.is_file()) || (!final_component && !metadata.is_dir()) {
            return Err(AssetPipelineError::InvalidCache(root.to_owned()));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IosIcon {
    points: &'static str,
    scale: &'static str,
    idiom: &'static str,
    pixels: u32,
}

impl IosIcon {
    const fn new(
        points: &'static str,
        scale: &'static str,
        idiom: &'static str,
        pixels: u32,
    ) -> Self {
        Self {
            points,
            scale,
            idiom,
            pixels,
        }
    }

    fn filename(self) -> String {
        format!(
            "AppIcon-{}-{}.png",
            self.points.replace('.', "_"),
            self.scale
        )
    }
}

#[derive(Serialize)]
struct IosContents<'a> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    images: Vec<IosImageEntry<'a>>,
    info: IosInfo<'a>,
}

impl<'a> IosContents<'a> {
    fn new(images: Vec<IosImageEntry<'a>>) -> Self {
        Self {
            images,
            info: IosInfo {
                author: "cargo-ferry",
                version: 1,
            },
        }
    }
}

#[derive(Serialize)]
struct IosImageEntry<'a> {
    filename: String,
    idiom: &'a str,
    scale: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<String>,
}

#[derive(Serialize)]
struct IosInfo<'a> {
    author: &'a str,
    version: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, Serialize)]
struct AssetManifest {
    schema_version: u8,
    fingerprint: String,
    files: Vec<AssetManifestFile>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, Serialize)]
struct AssetManifestFile {
    path: Utf8PathBuf,
    sha256: String,
}

/// Asset validation or deterministic platform generation failure.
#[derive(Debug, Error)]
pub enum AssetPipelineError {
    /// Project source assets are missing or malformed.
    #[error(transparent)]
    Asset(#[from] AssetError),
    /// A path could not be represented in protocol and manifest output.
    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(std::path::PathBuf),
    /// A source path escaped the selected project.
    #[error("asset source must stay inside the project: {0}")]
    SourceOutsideProject(Utf8PathBuf),
    /// A source or generated path crossed a symlink or non-directory boundary.
    #[error("refusing unsafe asset path: {0}")]
    UnsafePath(Utf8PathBuf),
    /// A custom source exceeded the bounded decoder input.
    #[error("asset source {path} is {size} bytes; maximum is {MAX_SOURCE_BYTES} bytes")]
    SourceTooLarge {
        /// Rejected source.
        path: Utf8PathBuf,
        /// Observed size.
        size: u64,
    },
    /// A source was structurally readable but not a supported PNG.
    #[error("could not decode {role} PNG: {source}")]
    Decode {
        /// Source role.
        role: &'static str,
        /// Decoder failure.
        #[source]
        source: image::ImageError,
    },
    /// A generated derivative could not be encoded.
    #[error("could not encode generated asset {path}: {source}")]
    Encode {
        /// Generated relative path.
        path: Utf8PathBuf,
        /// Encoder failure.
        #[source]
        source: image::ImageError,
    },
    /// Sources are valid PNG files but not release-ready.
    #[error("project assets are not release-ready")]
    NotReleaseReady {
        /// Exact actionable failures.
        issues: Vec<AssetIssue>,
    },
    /// An existing fingerprint directory was incomplete or inconsistent.
    #[error("generated asset cache is incomplete or inconsistent: {0}")]
    InvalidCache(Utf8PathBuf),
    /// JSON manifest/catalog serialization or parsing failed.
    #[error("could not process generated asset metadata: {0}")]
    Json(#[from] serde_json::Error),
    /// Filesystem operation failed.
    #[error("could not {operation} at {path}: {source}")]
    Io {
        /// Exact operation.
        operation: &'static str,
        /// Affected path.
        path: Utf8PathBuf,
        /// Operating-system failure.
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICON: &[u8] = include_bytes!("../assets/default-icon.png");
    const SPLASH: &[u8] = include_bytes!("../assets/default-splash.png");

    fn fixture() -> (tempfile::TempDir, Utf8PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_path_buf()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), ICON).unwrap();
        fs::write(root.join("assets/splash.png"), SPLASH).unwrap();
        (temporary, root)
    }

    #[test]
    fn default_sources_are_release_ready_and_generate_deterministically() {
        let (_temporary, root) = fixture();
        let checked = check_project_assets(&root).unwrap();
        assert!(checked.release_ready, "{:?}", checked.issues);
        assert_eq!((checked.icon.width, checked.icon.height), (1_024, 1_024));
        assert!(!checked.icon.has_alpha);

        let first = generate_platform_assets(&root, None).unwrap();
        assert!(!first.cache_hit);
        assert!(
            first
                .root
                .join("ios/Assets.xcassets/AppIcon.appiconset/Contents.json")
                .is_file()
        );
        assert!(
            first
                .root
                .join("android/mipmap-xxxhdpi/ferry_icon.png")
                .is_file()
        );
        let second = generate_platform_assets(&root, None).unwrap();
        assert!(second.cache_hit);
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.files, second.files);
    }

    #[test]
    fn modified_cached_bytes_are_rejected() {
        let (_temporary, root) = fixture();
        let generated = generate_platform_assets(&root, None).unwrap();
        let icon = generated.root.join("android/mipmap-mdpi/ferry_icon.png");
        let original = fs::read(&icon).unwrap();
        fs::write(&icon, b"tampered").unwrap();

        assert!(matches!(
            generate_platform_assets(&root, None),
            Err(AssetPipelineError::InvalidCache(path)) if path == generated.root
        ));

        fs::write(icon, original).unwrap();
        let manifest_path = generated.root.join("manifest.json");
        let mut manifest: AssetManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest.files[0].sha256 = "0".repeat(64);
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        manifest_bytes.push(b'\n');
        fs::write(manifest_path, manifest_bytes).unwrap();
        assert!(matches!(
            generate_platform_assets(&root, None),
            Err(AssetPipelineError::InvalidCache(path)) if path == generated.root
        ));
    }

    #[test]
    fn concurrent_generation_publishes_one_complete_cache() {
        use std::sync::{Arc, Barrier};

        const WORKERS: usize = 2;
        let (_temporary, root) = fixture();
        let barrier = Arc::new(Barrier::new(WORKERS));
        let handles = (0..WORKERS)
            .map(|_| {
                let root = root.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    generate_platform_assets(&root, None)
                })
            })
            .collect::<Vec<_>>();
        let generated = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            generated.iter().filter(|assets| !assets.cache_hit).count(),
            1
        );
        for assets in &generated[1..] {
            assert_eq!(assets.root, generated[0].root);
            assert_eq!(assets.files, generated[0].files);
        }
        let asset_root = root.join("target/ferry/assets");
        let entries = fs::read_dir(asset_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(entries, [generated[0].fingerprint.clone()]);
    }

    #[test]
    fn custom_source_must_stay_inside_project() {
        let (temporary, root) = fixture();
        let outside = Utf8PathBuf::from_path_buf(temporary.path().with_extension("png")).unwrap();
        fs::write(&outside, ICON).unwrap();
        assert!(matches!(
            generate_platform_assets(&root, Some(&outside)),
            Err(AssetPipelineError::SourceOutsideProject(_))
        ));
        fs::remove_file(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn generated_root_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let (_temporary, root) = fixture();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.join("target")).unwrap();
        assert!(matches!(
            generate_platform_assets(&root, None),
            Err(AssetPipelineError::UnsafePath(_))
        ));
    }
}
