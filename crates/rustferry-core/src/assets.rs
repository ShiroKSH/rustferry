use std::{
    fs,
    io::{self, Read as _},
};

use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DECODED_ASSET_BYTES: u64 = 128 * 1024 * 1024;

/// Validated project icon and splash image bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectAssets {
    icon: Vec<u8>,
    icon_metadata: PngMetadata,
    splash: Vec<u8>,
    splash_metadata: PngMetadata,
    fingerprint: String,
}

/// Metadata read from a validated PNG without trusting filename extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PngMetadata {
    /// Pixel width.
    pub width: u32,
    /// Pixel height.
    pub height: u32,
    /// PNG bit depth.
    pub bit_depth: u8,
    /// PNG color-type number from the IHDR chunk.
    pub color_type: u8,
    /// Whether pixels can carry transparency through alpha or a `tRNS` chunk.
    pub has_alpha: bool,
}

impl ProjectAssets {
    /// Load `assets/icon.png` and `assets/splash.png` from a project.
    ///
    /// # Errors
    ///
    /// Returns a typed error when either file is missing, unsafe, oversized, unreadable, or not
    /// a structurally valid PNG.
    pub fn load(project_dir: &Utf8Path) -> Result<Self, AssetError> {
        let icon_path = project_dir.join("assets/icon.png");
        let splash_path = project_dir.join("assets/splash.png");
        let (icon, icon_metadata) = read_png(&icon_path, "icon")?;
        let (splash, splash_metadata) = read_png(&splash_path, "splash")?;
        let mut hasher = Sha256::new();
        hasher.update(b"cargo-ferry-project-assets-v1");
        hasher.update(b"icon.png\0");
        hasher.update(&icon);
        hasher.update(b"splash.png\0");
        hasher.update(&splash);
        let fingerprint = hex::encode(&hasher.finalize()[..12]);
        Ok(Self {
            icon,
            icon_metadata,
            splash,
            splash_metadata,
            fingerprint,
        })
    }

    /// Validated icon PNG bytes.
    pub fn icon(&self) -> &[u8] {
        &self.icon
    }

    /// Validated icon dimensions and color representation.
    pub const fn icon_metadata(&self) -> PngMetadata {
        self.icon_metadata
    }

    /// Validated splash PNG bytes.
    pub fn splash(&self) -> &[u8] {
        &self.splash
    }

    /// Validated splash dimensions and color representation.
    pub const fn splash_metadata(&self) -> PngMetadata {
        self.splash_metadata
    }

    /// Stable digest of both filenames and file contents.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Project asset loading or validation failure.
#[derive(Debug, Error)]
pub enum AssetError {
    /// An asset path is absent or is not a regular file.
    #[error("project {kind} asset must be a regular PNG file at `{path}`")]
    NotRegular {
        /// Asset role.
        kind: &'static str,
        /// Expected path.
        path: Utf8PathBuf,
    },
    /// An asset exceeds the bounded input size.
    #[error("project {kind} asset `{path}` is {size} bytes; maximum is {maximum} bytes")]
    TooLarge {
        /// Asset role.
        kind: &'static str,
        /// Asset path.
        path: Utf8PathBuf,
        /// Observed file size.
        size: u64,
        /// Maximum accepted file size.
        maximum: u64,
    },
    /// An asset is not a minimally valid, bounded PNG.
    #[error("project {kind} asset `{path}` is not a valid PNG: {reason}")]
    InvalidPng {
        /// Asset role.
        kind: &'static str,
        /// Asset path.
        path: Utf8PathBuf,
        /// Failed structural invariant.
        reason: &'static str,
    },
    /// A filesystem operation failed.
    #[error("could not {operation} project {kind} asset `{path}`: {source}")]
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Asset role.
        kind: &'static str,
        /// Asset path.
        path: Utf8PathBuf,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
}

fn read_png(path: &Utf8Path, kind: &'static str) -> Result<(Vec<u8>, PngMetadata), AssetError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            AssetError::NotRegular {
                kind,
                path: path.to_owned(),
            }
        } else {
            AssetError::Io {
                operation: "inspect",
                kind,
                path: path.to_owned(),
                source,
            }
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AssetError::NotRegular {
            kind,
            path: path.to_owned(),
        });
    }
    if metadata.len() > MAX_ASSET_BYTES {
        return Err(AssetError::TooLarge {
            kind,
            path: path.to_owned(),
            size: metadata.len(),
            maximum: MAX_ASSET_BYTES,
        });
    }
    let bytes = fs::read(path).map_err(|source| AssetError::Io {
        operation: "read",
        kind,
        path: path.to_owned(),
        source,
    })?;
    let png_metadata = validate_png(&bytes, path, kind)?;
    Ok((bytes, png_metadata))
}

fn validate_png(
    bytes: &[u8],
    path: &Utf8Path,
    kind: &'static str,
) -> Result<PngMetadata, AssetError> {
    let invalid = |reason| AssetError::InvalidPng {
        kind,
        path: path.to_owned(),
        reason,
    };
    if bytes.len() < 57 || bytes.get(..8) != Some(PNG_SIGNATURE) {
        return Err(invalid("missing PNG signature or required chunks"));
    }
    let mut offset = PNG_SIGNATURE.len();
    let mut png_metadata = None;
    let mut transparency = false;
    let mut idat = Vec::new();
    let mut finished = false;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(8)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| invalid("truncated chunk header"))?;
        let length = usize::try_from(u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("bounded chunk length"),
        ))
        .map_err(|_| invalid("chunk length is not representable"))?;
        let data_end = header_end
            .checked_add(length)
            .filter(|end| {
                end.checked_add(4)
                    .is_some_and(|crc_end| crc_end <= bytes.len())
            })
            .ok_or_else(|| invalid("truncated or oversized chunk"))?;
        let chunk_end = data_end + 4;
        let chunk_type = &bytes[offset + 4..header_end];
        let expected_crc = u32::from_be_bytes(
            bytes[data_end..chunk_end]
                .try_into()
                .expect("bounded chunk CRC"),
        );
        if png_crc32(&bytes[offset + 4..data_end]) != expected_crc {
            return Err(invalid("chunk CRC does not match"));
        }
        match chunk_type {
            b"IHDR" if offset == PNG_SIGNATURE.len() && length == 13 => {
                let data = &bytes[header_end..data_end];
                let width = u32::from_be_bytes(data[..4].try_into().expect("bounded width"));
                let height = u32::from_be_bytes(data[4..8].try_into().expect("bounded height"));
                if width == 0 || height == 0 || width > 16_384 || height > 16_384 {
                    return Err(invalid(
                        "image dimensions must be between 1 and 16384 pixels",
                    ));
                }
                if !valid_png_color_format(data[8], data[9])
                    || data[10] != 0
                    || data[11] != 0
                    || data[12] > 1
                {
                    return Err(invalid("unsupported or invalid IHDR encoding"));
                }
                png_metadata = Some(PngMetadata {
                    width,
                    height,
                    bit_depth: data[8],
                    color_type: data[9],
                    has_alpha: matches!(data[9], 4 | 6),
                });
            }
            b"IHDR" => return Err(invalid("first chunk is not a 13-byte IHDR")),
            b"tRNS" if png_metadata.is_some() && idat.is_empty() && !finished => {
                transparency = true;
            }
            b"IDAT" if png_metadata.is_some() && !finished => {
                idat.extend_from_slice(&bytes[header_end..data_end]);
            }
            b"IEND" if length == 0 && png_metadata.is_some() && !idat.is_empty() => {
                finished = true;
                offset = chunk_end;
                break;
            }
            b"IEND" => return Err(invalid("invalid IEND ordering or length")),
            _ if png_metadata.is_none() => return Err(invalid("IHDR is not the first chunk")),
            _ => {}
        }
        offset = chunk_end;
    }
    if !finished || offset != bytes.len() {
        return Err(invalid("final chunk is not IEND"));
    }
    let mut decoded = Vec::new();
    flate2::read::ZlibDecoder::new(idat.as_slice())
        .take(MAX_DECODED_ASSET_BYTES + 1)
        .read_to_end(&mut decoded)
        .map_err(|_| invalid("IDAT data is not a valid zlib stream"))?;
    if decoded.is_empty()
        || u64::try_from(decoded.len()).unwrap_or(u64::MAX) > MAX_DECODED_ASSET_BYTES
    {
        return Err(invalid("decoded image data is empty or exceeds 128 MiB"));
    }
    let mut png_metadata = png_metadata.expect("validated PNG contains IHDR");
    png_metadata.has_alpha |= transparency;
    Ok(png_metadata)
}

fn valid_png_color_format(bit_depth: u8, color_type: u8) -> bool {
    match color_type {
        0 => matches!(bit_depth, 1 | 2 | 4 | 8 | 16),
        2 | 4 | 6 => matches!(bit_depth, 8 | 16),
        3 => matches!(bit_depth, 1 | 2 | 4 | 8),
        _ => false,
    }
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb_88320
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    mod png_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/opaque_png.rs"
        ));
    }

    use png_fixture::OPAQUE_1024_PNG as PNG;

    fn fixture() -> (tempfile::TempDir, Utf8PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let root = Utf8PathBuf::from_path_buf(temporary.path().to_owned()).unwrap();
        fs::create_dir(root.join("assets")).unwrap();
        fs::write(root.join("assets/icon.png"), PNG).unwrap();
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        (temporary, root)
    }

    #[test]
    fn loads_and_fingerprints_both_assets() {
        let (_temporary, root) = fixture();
        let first = ProjectAssets::load(&root).unwrap();
        let mut malformed = PNG.to_vec();
        malformed.push(0);
        fs::write(root.join("assets/splash.png"), malformed).unwrap();
        assert!(matches!(
            ProjectAssets::load(&root),
            Err(AssetError::InvalidPng { .. })
        ));
        fs::write(root.join("assets/splash.png"), PNG).unwrap();
        let second = ProjectAssets::load(&root).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.icon(), PNG);
        assert_eq!(
            (first.icon_metadata().width, first.icon_metadata().height),
            (1024, 1024)
        );
        assert!(!first.icon_metadata().has_alpha);
    }

    #[test]
    fn rejects_missing_and_malformed_assets() {
        let (_temporary, root) = fixture();
        fs::write(root.join("assets/icon.png"), b"not a png").unwrap();
        assert!(matches!(
            ProjectAssets::load(&root),
            Err(AssetError::InvalidPng { kind: "icon", .. })
        ));
        fs::remove_file(root.join("assets/icon.png")).unwrap();
        assert!(matches!(
            ProjectAssets::load(&root),
            Err(AssetError::NotRegular { kind: "icon", .. })
        ));
    }

    #[test]
    fn rejects_png_with_invalid_compressed_pixels() {
        const INVALID_ZLIB_PNG: &[u8] = &[
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
            0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x08,
            0x1d, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0x00, 0x05, 0x80, 0x01, 0xff, 0x89, 0x99,
            0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
        ];
        let (_temporary, root) = fixture();
        fs::write(root.join("assets/icon.png"), INVALID_ZLIB_PNG).unwrap();
        assert!(matches!(
            ProjectAssets::load(&root),
            Err(AssetError::InvalidPng { kind: "icon", .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_asset_symlinks() {
        use std::os::unix::fs::symlink;

        let (_temporary, root) = fixture();
        fs::rename(
            root.join("assets/icon.png"),
            root.join("assets/real-icon.png"),
        )
        .unwrap();
        symlink("real-icon.png", root.join("assets/icon.png")).unwrap();
        assert!(matches!(
            ProjectAssets::load(&root),
            Err(AssetError::NotRegular { kind: "icon", .. })
        ));
    }
}
