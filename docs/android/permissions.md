# Android manifest permissions

Manifest declarations come only from enabled capabilities and permission settings. Purpose text is validated in `ferry.toml` for cross-platform UX but is not embedded in Android's manifest; Android rationale UI remains application code.

| Configuration | Android manifest output |
| --- | --- |
| network `none` | no network permission |
| network `status` | `ACCESS_NETWORK_STATE` |
| network `optional` or `required` | `ACCESS_NETWORK_STATE`, `INTERNET` |
| configured network probe | `INTERNET` |
| local notifications | `POST_NOTIFICATIONS` |
| Live Activity ongoing-notification fallback | `POST_NOTIFICATIONS` |
| haptics | `VIBRATE` |
| camera | `CAMERA` |
| microphone | `RECORD_AUDIO` |
| location when in use | `ACCESS_COARSE_LOCATION`, `ACCESS_FINE_LOCATION` |
| photos, target API 33+ | `READ_MEDIA_IMAGES` |
| photos, minimum API below 33 | `READ_EXTERNAL_STORAGE` capped with `android:maxSdkVersion="32"` |
| local network | no Android declaration; Apple-only privacy permission |
| widget extension | widget receiver and provider metadata |
| sharing | non-exported, read-only application file provider |
| custom deep-link schemes | `VIEW`/`BROWSABLE` intent filter on the launcher activity |

Deep-link filters are the Cartesian product of configured `schemes`, `allowed_hosts`, and
`allowed_actions`; actions become path prefixes. The generated bridge repeats the same checks for
cold-start and running-app intents, and rejects undeclared scheme/host/action values before Rust
receives an event. An empty host or action list leaves that dimension unrestricted.

The notification permission is declared only for local notifications or the enabled ongoing-notification fallback. The runtime requests it only in response to an explicit application call on Android versions where a runtime request exists. On older versions it also checks whether the user disabled this application's notifications in system settings.

Notification, widget, and share components are omitted when their capabilities are disabled. Every generated activity, receiver, or provider is checked against the merged DEX before packaging completes.

Review generated output at:

```text
target/ferry/android/<profile>/generated/<fingerprint>/AndroidManifest.xml
```

The final binary manifest and package metadata are checked again from the signed APK.
