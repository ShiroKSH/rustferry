use camino::Utf8PathBuf;
use rustferry_core::{AndroidLiveActivityFallback, FerryConfig, NetworkMode};

/// Generated launcher activity and private Rust bridge entry point.
pub const ACTIVITY_CLASS: &str = "org.rustferry.bridge.FerryActivity";
/// Generated Java dispatcher invoked through the activity.
pub const BRIDGE_CLASS: &str = "org.rustferry.bridge.FerryBridge";
/// Generated alarm and notification-action receiver.
pub const NOTIFICATION_RECEIVER_CLASS: &str = "org.rustferry.bridge.FerryNotificationReceiver";
/// Generated Android home-screen widget provider.
pub const WIDGET_PROVIDER_CLASS: &str = "org.rustferry.bridge.FerryWidgetProvider";
/// Generated read-only provider for application-owned share files.
pub const FILE_PROVIDER_CLASS: &str = "org.rustferry.bridge.FerryFileProvider";

const ACTIVITY_SOURCE: &str = include_str!("../java/org/rustferry/bridge/FerryActivity.java");
const BRIDGE_SOURCE: &str = include_str!("../java/org/rustferry/bridge/FerryBridge.java");
const NOTIFICATION_SOURCE: &str =
    include_str!("../java/org/rustferry/bridge/FerryNotificationReceiver.java");
const WIDGET_SOURCE: &str = include_str!("../java/org/rustferry/bridge/FerryWidgetProvider.java");
const FILE_PROVIDER_SOURCE: &str =
    include_str!("../java/org/rustferry/bridge/FerryFileProvider.java");

pub(crate) fn generate_bridge_sources(config: &FerryConfig) -> Vec<(Utf8PathBuf, String)> {
    let network_status = config.capabilities.network.mode != NetworkMode::None;
    let network_probe = matches!(
        config.capabilities.network.mode,
        NetworkMode::Optional | NetworkMode::Required
    ) || config.capabilities.network.probe_url.is_some();
    let notifications = config.capabilities.notifications.local;
    let live_activity = config.extensions.live_activity.enabled
        && config.extensions.live_activity.android_fallback
            == AndroidLiveActivityFallback::OngoingNotification;
    let any_permission = notifications
        || live_activity
        || network_status
        || config.permissions.camera.enabled
        || config.permissions.photos.enabled
        || config.permissions.microphone.enabled
        || config.permissions.location_when_in_use.enabled;
    let replacements = [
        ("@CAP_NETWORK_STATUS@", network_status),
        ("@CAP_NETWORK_PROBE@", network_probe),
        ("@CAP_STORAGE@", config.capabilities.storage.enabled),
        ("@CAP_HAPTICS@", config.capabilities.haptics.enabled),
        ("@CAP_CLIPBOARD@", config.capabilities.clipboard.enabled),
        ("@CAP_SHARE@", config.capabilities.share.enabled),
        ("@CAP_NOTIFICATIONS@", notifications),
        (
            "@CAP_DEEP_LINKS@",
            !config.capabilities.deep_links.schemes.is_empty(),
        ),
        ("@CAP_WIDGET@", config.extensions.widget.enabled),
        ("@CAP_LIVE_ACTIVITY@", live_activity),
        ("@PERMISSION_CAMERA@", config.permissions.camera.enabled),
        ("@PERMISSION_PHOTOS@", config.permissions.photos.enabled),
        (
            "@PERMISSION_MICROPHONE@",
            config.permissions.microphone.enabled,
        ),
        (
            "@PERMISSION_LOCATION@",
            config.permissions.location_when_in_use.enabled,
        ),
        ("@ANY_GENERAL_PERMISSION@", any_permission),
    ];
    let mut bridge = BRIDGE_SOURCE.to_owned();
    for (token, enabled) in replacements {
        bridge = bridge.replace(token, if enabled { "true" } else { "false" });
    }
    let java_strings = |values: &[String]| {
        values
            .iter()
            .map(|value| serde_json::to_string(value).expect("strings always serialize"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let deep_link_schemes = java_strings(&config.capabilities.deep_links.schemes);
    let deep_link_hosts = java_strings(&config.capabilities.deep_links.allowed_hosts);
    let deep_link_actions = java_strings(&config.capabilities.deep_links.allowed_actions);
    bridge = bridge.replace("@DEEP_LINK_SCHEMES@", &deep_link_schemes);
    bridge = bridge.replace("@DEEP_LINK_HOSTS@", &deep_link_hosts);
    bridge = bridge.replace("@DEEP_LINK_ACTIONS@", &deep_link_actions);
    let prefix = "java/org/rustferry/bridge";
    vec![
        (
            Utf8PathBuf::from(format!("{prefix}/FerryActivity.java")),
            ACTIVITY_SOURCE.to_owned(),
        ),
        (
            Utf8PathBuf::from(format!("{prefix}/FerryBridge.java")),
            bridge,
        ),
        (
            Utf8PathBuf::from(format!("{prefix}/FerryFileProvider.java")),
            FILE_PROVIDER_SOURCE.to_owned(),
        ),
        (
            Utf8PathBuf::from(format!("{prefix}/FerryNotificationReceiver.java")),
            NOTIFICATION_SOURCE.to_owned(),
        ),
        (
            Utf8PathBuf::from(format!("{prefix}/FerryWidgetProvider.java")),
            WIDGET_SOURCE.to_owned(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_capabilities_are_baked_without_template_tokens() {
        let config = FerryConfig::starter("Counter", "com.example.counter");
        let sources = generate_bridge_sources(&config);
        let bridge = sources
            .iter()
            .find(|(path, _)| path.file_name() == Some("FerryBridge.java"))
            .map(|(_, source)| source)
            .unwrap();
        assert!(!bridge.contains("@CAP_"));
        assert!(!bridge.contains("@PERMISSION_"));
        assert!(!bridge.contains("@DEEP_LINK_SCHEMES@"));
        assert!(!bridge.contains("@DEEP_LINK_HOSTS@"));
        assert!(!bridge.contains("@DEEP_LINK_ACTIONS@"));
        assert!(bridge.contains("CAP_NETWORK_STATUS = true"));
        assert!(bridge.contains("CAP_CLIPBOARD = false"));
        assert!(bridge.contains("areNotificationsEnabled"));
        assert!(bridge.contains("initialize(activity);\n            return JSONObject.NULL;"));
        assert!(bridge.contains("new String[] {\"counter\"}"));
        assert!(bridge.contains("isAllowedDeepLink(data)"));
        assert!(bridge.contains("DEEP_LINK_HOSTS.length > 0"));
        assert!(bridge.contains("DEEP_LINK_ACTIONS.length > 0"));
        assert!(bridge.contains("validateWidgetContent"));
        assert!(bridge.contains("one link/button action"));
        assert!(bridge.contains("\"https\".equalsIgnoreCase(scheme)"));
        assert!(!bridge.contains("\"data\".equalsIgnoreCase(scheme)"));
        assert!(FILE_PROVIDER_SOURCE.contains("root.directory == null"));
    }

    #[test]
    fn bridge_bakes_complete_deep_link_policy() {
        let mut config = FerryConfig::starter("Routes", "com.example.routes");
        config.capabilities.deep_links.schemes = vec!["routes".to_owned()];
        config.capabilities.deep_links.allowed_hosts = vec!["app.example.com".to_owned()];
        config.capabilities.deep_links.allowed_actions = vec!["details".to_owned()];
        let sources = generate_bridge_sources(&config);
        let bridge = sources
            .iter()
            .find(|(path, _)| path.file_name() == Some("FerryBridge.java"))
            .map(|(_, source)| source)
            .unwrap();
        assert!(bridge.contains("new String[] {\"routes\"}"));
        assert!(bridge.contains("new String[] {\"app.example.com\"}"));
        assert!(bridge.contains("new String[] {\"details\"}"));
        assert!(bridge.contains("allowed.equalsIgnoreCase(host)"));
        assert!(bridge.contains("allowed.equals(action)"));
    }

    #[test]
    fn activity_intents_are_initialized_and_consumed_once() {
        assert!(ACTIVITY_SOURCE.contains("FerryBridge.attach(this, getIntent())"));
        assert!(BRIDGE_SOURCE.contains(
            "handleIntent(activity, activity.getIntent(), !startedSent);\n        nativeReady = true;"
        ));
        assert!(BRIDGE_SOURCE.contains("static synchronized void handleIntent"));
        for consumed in [
            "intent.removeExtra(EXTRA_NOTIFICATION_ID)",
            "intent.removeExtra(EXTRA_OPEN_EVENT)",
            "intent.removeExtra(EXTRA_DEEP_LINK)",
            "intent.removeExtra(EXTRA_INTERNAL_TOKEN)",
            "intent.setData(null)",
        ] {
            assert!(BRIDGE_SOURCE.contains(consumed));
        }
    }

    #[test]
    fn provider_paths_and_live_updates_fail_safely() {
        assert!(FILE_PROVIDER_SOURCE.contains("filePath.substring(rootPath.length())"));
        assert!(FILE_PROVIDER_SOURCE.contains(".appendPath(relative)"));
        assert!(!FILE_PROVIDER_SOURCE.contains("toURI().relativize"));
        let update = BRIDGE_SOURCE
            .split("private static void updateLiveActivity")
            .nth(1)
            .unwrap()
            .split("private static void endLiveActivity")
            .next()
            .unwrap();
        assert!(update.contains("requireNotificationPermissionForContext(context);"));
        assert!(BRIDGE_SOURCE.contains(
            "if (ongoing) throw new SecurityException(\"notification permission is not granted\")"
        ));
    }
}
