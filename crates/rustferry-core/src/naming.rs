use sha2::{Digest, Sha256};
use thiserror::Error;

/// Validated names derived from the value passed to `cargo ferry new`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectNames {
    /// Directory name requested by the user.
    pub directory_name: String,
    /// Cargo-compatible package name.
    pub crate_name: String,
    /// Human-readable application name.
    pub display_name: String,
    /// Cross-platform application identifier.
    pub application_identifier: String,
}

/// Project or application identifier validation failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum NamingError {
    /// The requested name cannot safely identify a child directory.
    #[error("invalid project name: {reason}")]
    InvalidProjectName {
        /// Human-readable constraint that failed.
        reason: String,
    },
    /// The application identifier cannot be used on every target platform.
    #[error("invalid application identifier `{identifier}`: {reason}")]
    InvalidApplicationIdentifier {
        /// Rejected identifier.
        identifier: String,
        /// Human-readable constraint that failed.
        reason: String,
    },
}

/// Validate and derive all project names without touching the filesystem.
///
/// # Errors
///
/// Returns [`NamingError`] when the name is unsafe or the identifier is not portable.
pub fn derive_project_names(
    requested_name: &str,
    identifier: Option<&str>,
) -> Result<ProjectNames, NamingError> {
    validate_project_name(requested_name)?;

    let crate_name = crate_name(requested_name);
    let display_name = display_name(requested_name);
    let application_identifier = identifier.map_or_else(
        || {
            let suffix = crate_name
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>();
            format!("org.rustferry.{suffix}")
        },
        ToOwned::to_owned,
    );
    validate_application_identifier(&application_identifier)?;

    Ok(ProjectNames {
        directory_name: requested_name.to_owned(),
        crate_name,
        display_name,
        application_identifier,
    })
}

fn validate_project_name(name: &str) -> Result<(), NamingError> {
    if name.is_empty() {
        return Err(invalid_name("the name is empty"));
    }
    if name.trim() != name {
        return Err(invalid_name(
            "leading or trailing whitespace is not allowed",
        ));
    }
    if matches!(name, "." | "..") {
        return Err(invalid_name("`.` and `..` are not project names"));
    }
    if name.contains(['/', '\\']) {
        return Err(invalid_name("path separators are not allowed"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid_name("control characters are not allowed"));
    }
    if name.contains(['<', '>', ':', '"', '|', '?', '*']) || name.ends_with('.') {
        return Err(invalid_name(
            "the name contains characters that are unsafe on supported filesystems",
        ));
    }
    let windows_stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
    if matches!(windows_stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || windows_stem
            .strip_prefix("COM")
            .or_else(|| windows_stem.strip_prefix("LPT"))
            .is_some_and(|number| {
                matches!(number, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
    {
        return Err(invalid_name("the name is reserved by Windows"));
    }
    Ok(())
}

fn invalid_name(reason: &str) -> NamingError {
    NamingError::InvalidProjectName {
        reason: reason.to_owned(),
    }
}

fn crate_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !output.is_empty() {
                output.push('-');
            }
            separator = false;
            output.push(character.to_ascii_lowercase());
        } else {
            separator = true;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        let digest = Sha256::digest(name.as_bytes());
        output = format!("app-{}", hex::encode(&digest[..4]));
    }
    if output.as_bytes()[0].is_ascii_digit() {
        output.insert_str(0, "app-");
    }
    if rust_keyword(&output) {
        output.insert_str(0, "app-");
    }
    output
}

fn rust_keyword(value: &str) -> bool {
    matches!(
        value,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
            | "try"
            | "gen"
    )
}

fn display_name(name: &str) -> String {
    let mut words = name
        .split(['-', '_'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut characters = word.chars();
            characters.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + characters.as_str()
            })
        })
        .collect::<Vec<_>>();
    if words.is_empty() {
        name.to_owned()
    } else {
        words.retain(|word| !word.is_empty());
        words.join(" ")
    }
}

/// Validate the conservative intersection of Android application IDs and Apple bundle IDs.
///
/// # Errors
///
/// Returns [`NamingError::InvalidApplicationIdentifier`] for a non-portable identifier.
pub fn validate_application_identifier(identifier: &str) -> Result<(), NamingError> {
    if identifier.len() > 255 {
        return Err(invalid_identifier(identifier, "it exceeds 255 bytes"));
    }
    let segments = identifier.split('.').collect::<Vec<_>>();
    if segments.len() < 3 {
        return Err(invalid_identifier(
            identifier,
            "use at least three dot-separated segments, for example `com.example.app`",
        ));
    }
    for segment in segments {
        let mut characters = segment.chars();
        let Some(first) = characters.next() else {
            return Err(invalid_identifier(
                identifier,
                "empty segments are not allowed",
            ));
        };
        if !first.is_ascii_lowercase() {
            return Err(invalid_identifier(
                identifier,
                "each segment must start with a lowercase ASCII letter",
            ));
        }
        if !characters.all(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        {
            return Err(invalid_identifier(
                identifier,
                "segments may contain only lowercase ASCII letters and digits",
            ));
        }
    }
    Ok(())
}

fn invalid_identifier(identifier: &str, reason: &str) -> NamingError {
    NamingError::InvalidApplicationIdentifier {
        identifier: identifier.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_safe_names() {
        let names = derive_project_names("Weather App", None).unwrap();
        assert_eq!(names.crate_name, "weather-app");
        assert_eq!(names.display_name, "Weather App");
        assert_eq!(names.application_identifier, "org.rustferry.weatherapp");
    }

    #[test]
    fn unicode_names_are_deterministic() {
        let first = derive_project_names("Погода", None).unwrap();
        let second = derive_project_names("Погода", None).unwrap();
        assert_eq!(first.crate_name, second.crate_name);
        assert!(first.crate_name.starts_with("app-"));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(derive_project_names("../weather", None).is_err());
        assert!(derive_project_names("..", None).is_err());
    }

    #[test]
    fn rejects_cross_platform_reserved_names() {
        assert!(derive_project_names("NUL", None).is_err());
        assert!(derive_project_names("weather?", None).is_err());
        assert_eq!(
            derive_project_names("fn", None).unwrap().crate_name,
            "app-fn"
        );
    }

    #[test]
    fn rejects_unsafe_identifier() {
        assert!(validate_application_identifier("com.Example.weather").is_err());
        assert!(validate_application_identifier("com.example.weather_app").is_err());
        assert!(validate_application_identifier("com.example.weather-app").is_err());
        assert!(validate_application_identifier("example").is_err());
    }
}
