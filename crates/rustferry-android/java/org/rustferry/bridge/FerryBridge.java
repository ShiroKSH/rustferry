package org.rustferry.bridge;

import android.Manifest;
import android.app.Activity;
import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.Uri;
import android.os.Build;
import android.os.Looper;
import android.os.SystemClock;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.service.notification.StatusBarNotification;
import android.util.DisplayMetrics;
import android.view.HapticFeedbackConstants;
import android.view.View;
import android.widget.RemoteViews;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Android implementation behind the typed Rust runtime API. */
@SuppressWarnings("deprecation")
final class FerryBridge {
    private static final boolean CAP_NETWORK_STATUS = @CAP_NETWORK_STATUS@;
    private static final boolean CAP_NETWORK_PROBE = @CAP_NETWORK_PROBE@;
    private static final boolean CAP_STORAGE = @CAP_STORAGE@;
    private static final boolean CAP_HAPTICS = @CAP_HAPTICS@;
    private static final boolean CAP_CLIPBOARD = @CAP_CLIPBOARD@;
    private static final boolean CAP_SHARE = @CAP_SHARE@;
    private static final boolean CAP_NOTIFICATIONS = @CAP_NOTIFICATIONS@;
    private static final boolean CAP_DEEP_LINKS = @CAP_DEEP_LINKS@;
    private static final boolean CAP_WIDGET = @CAP_WIDGET@;
    private static final boolean CAP_LIVE_ACTIVITY = @CAP_LIVE_ACTIVITY@;
    private static final boolean PERMISSION_CAMERA = @PERMISSION_CAMERA@;
    private static final boolean PERMISSION_PHOTOS = @PERMISSION_PHOTOS@;
    private static final boolean PERMISSION_MICROPHONE = @PERMISSION_MICROPHONE@;
    private static final boolean PERMISSION_LOCATION = @PERMISSION_LOCATION@;
    private static final boolean ANY_GENERAL_PERMISSION = @ANY_GENERAL_PERMISSION@;
    private static final String[] DEEP_LINK_SCHEMES = new String[] {@DEEP_LINK_SCHEMES@};
    private static final String[] DEEP_LINK_HOSTS = new String[] {@DEEP_LINK_HOSTS@};
    private static final String[] DEEP_LINK_ACTIONS = new String[] {@DEEP_LINK_ACTIONS@};

    private static final String NOTIFICATION_PREFS = "org.rustferry.notifications";
    private static final String WIDGET_PREFS = "org.rustferry.widgets";
    private static final String LIVE_PREFS = "org.rustferry.live-activities";
    private static final String PERMISSION_PREFS = "org.rustferry.permissions";
    private static final String PENDING_PREFIX = "pending.";
    private static final String DELIVERED_PREFIX = "delivered.";
    private static final String LIVE_PREFIX = "activity.";
    private static final String LAST_OPEN_EVENT = "last-open-event";
    private static final String EXTRA_NOTIFICATION_ID = "rustferry.notification-id";
    private static final String EXTRA_OPEN_EVENT = "rustferry.open-event";
    private static final String EXTRA_DEEP_LINK = "rustferry.deep-link";
    private static final String EXTRA_INTERNAL_TOKEN = "rustferry.internal-token";
    private static final String ACTION_DELIVER = "org.rustferry.action.DELIVER";
    private static final String ACTION_OPEN = "org.rustferry.action.OPEN";
    private static final int PENDING_FLAGS = PendingIntent.FLAG_UPDATE_CURRENT
            | PendingIntent.FLAG_IMMUTABLE;

    private static final Object EVENT_LOCK = new Object();
    private static final ArrayDeque<String> PENDING_EVENTS = new ArrayDeque<String>();
    private static final ConcurrentHashMap<Integer, PermissionWait> PERMISSION_WAITS =
            new ConcurrentHashMap<Integer, PermissionWait>();
    private static final AtomicInteger NEXT_PERMISSION_REQUEST = new AtomicInteger(4100);

    private static WeakReference<FerryActivity> currentActivity =
            new WeakReference<FerryActivity>(null);
    private static volatile boolean nativeReady;
    private static volatile boolean startedSent;
    private static volatile String initialDeepLink;
    private static ConnectivityManager.NetworkCallback networkCallback;

    private FerryBridge() {}

    private static native void nativeDispatchEvent(String event);

    static void attach(FerryActivity activity, Intent intent) {
        currentActivity = new WeakReference<FerryActivity>(activity);
        handleIntent(activity, intent, !startedSent);
    }

    static String invoke(FerryActivity activity, String operation, String payload) {
        currentActivity = new WeakReference<FerryActivity>(activity);
        try {
            JSONObject input = payload == null || payload.length() == 0
                    ? new JSONObject()
                    : new JSONObject(payload);
            Object value = invokeValue(activity, operation, input);
            return success(value);
        } catch (Throwable error) {
            return failure(error);
        }
    }

    private static Object invokeValue(FerryActivity activity, String operation, JSONObject input)
            throws Exception {
        if ("initialize".equals(operation)) {
            initialize(activity);
            return JSONObject.NULL;
        }
        if ("supports".equals(operation)) {
            return supports(input.getString("operation"));
        }
        if ("network-current".equals(operation)) {
            require(CAP_NETWORK_STATUS, "network status");
            return networkStatus(activity);
        }
        if ("network-probe".equals(operation)) {
            require(CAP_NETWORK_PROBE, "network probes");
            return probe(input.getString("url"), input.getLong("timeout_ms"));
        }
        if ("haptic".equals(operation)) {
            require(CAP_HAPTICS, "haptics");
            haptic(activity, input.get("call"));
            return JSONObject.NULL;
        }
        if ("clipboard-read-text".equals(operation)) {
            require(CAP_CLIPBOARD, "clipboard");
            return clipboardRead(activity);
        }
        if ("clipboard-write-text".equals(operation)) {
            require(CAP_CLIPBOARD, "clipboard");
            clipboardWrite(activity, input.getString("text"));
            return JSONObject.NULL;
        }
        if ("share".equals(operation)) {
            require(CAP_SHARE, "sharing");
            share(activity, input.getJSONObject("request"));
            return JSONObject.NULL;
        }
        if ("open-url".equals(operation)) {
            openUrl(activity, input.getString("url"));
            return JSONObject.NULL;
        }
        if ("open-settings".equals(operation)) {
            openSettings(activity);
            return JSONObject.NULL;
        }
        if ("app-info".equals(operation)) {
            return appInfo(activity);
        }
        if ("device-info".equals(operation)) {
            return deviceInfo(activity);
        }
        if ("theme".equals(operation)) {
            return theme(activity);
        }
        if ("notification-permission-status".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            return notificationPermissionStatus(activity);
        }
        if ("notification-request-permission".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            return requestPermission(activity, "notifications");
        }
        if ("notification-schedule".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            scheduleNotification(activity, input.getJSONObject("notification"));
            return JSONObject.NULL;
        }
        if ("notification-show-now".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            requireNotificationPermission(activity);
            showNotification(activity, input.getJSONObject("notification"), false);
            return JSONObject.NULL;
        }
        if ("notification-cancel".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            cancelNotification(activity, input.getString("id"));
            return JSONObject.NULL;
        }
        if ("notification-cancel-all".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            cancelAllNotifications(activity);
            return JSONObject.NULL;
        }
        if ("notification-pending".equals(operation)) {
            require(CAP_NOTIFICATIONS, "local notifications");
            return pendingNotifications(activity);
        }
        if ("notification-delivered".equals(operation)) {
            require(CAP_NOTIFICATIONS && Build.VERSION.SDK_INT >= 23,
                    "delivered notification inspection");
            return deliveredNotifications(activity);
        }
        if ("permission-is-supported".equals(operation)) {
            return permissionSupported(input.getString("permission"));
        }
        if ("permission-status".equals(operation)) {
            require(ANY_GENERAL_PERMISSION, "runtime permissions");
            return permissionStatus(activity, input.getString("permission"));
        }
        if ("permission-request".equals(operation)) {
            require(ANY_GENERAL_PERMISSION, "runtime permissions");
            return requestPermission(activity, input.getString("permission"));
        }
        if ("deep-link-initial".equals(operation)) {
            require(CAP_DEEP_LINKS, "deep links");
            return initialDeepLink == null ? JSONObject.NULL : initialDeepLink;
        }
        if ("widget-update".equals(operation)) {
            require(CAP_WIDGET, "widgets");
            updateWidgetSnapshot(activity, input.getString("id"), input.getJSONObject("snapshot"));
            return JSONObject.NULL;
        }
        if ("live-activity-start".equals(operation)) {
            require(CAP_LIVE_ACTIVITY, "ongoing-notification Live Activity fallback");
            return startLiveActivity(activity, input.getJSONObject("request"));
        }
        if ("live-activity-update".equals(operation)) {
            require(CAP_LIVE_ACTIVITY, "ongoing-notification Live Activity fallback");
            updateLiveActivity(activity, input.getJSONObject("request"));
            return JSONObject.NULL;
        }
        if ("live-activity-end".equals(operation)) {
            require(CAP_LIVE_ACTIVITY, "ongoing-notification Live Activity fallback");
            endLiveActivity(activity, input.getJSONObject("request"));
            return JSONObject.NULL;
        }
        if ("live-activity-list".equals(operation)) {
            require(CAP_LIVE_ACTIVITY, "ongoing-notification Live Activity fallback");
            return listLiveActivities(activity);
        }
        throw new UnsupportedOperationException("unknown RustFerry operation");
    }

    private static boolean supports(String operation) {
        if ("network-status".equals(operation)) return CAP_NETWORK_STATUS;
        if ("network-probe".equals(operation)) return CAP_NETWORK_PROBE;
        if ("storage".equals(operation)) return CAP_STORAGE;
        if ("haptics".equals(operation)) return CAP_HAPTICS;
        if ("clipboard-read".equals(operation) || "clipboard-write".equals(operation)) {
            return CAP_CLIPBOARD;
        }
        if ("share".equals(operation)) return CAP_SHARE;
        if ("open-url".equals(operation)
                || "open-settings".equals(operation)
                || "app-info".equals(operation)
                || "device-info".equals(operation)
                || "theme".equals(operation)) return true;
        if ("notification-permission-status".equals(operation)
                || "notification-permission-request".equals(operation)
                || "notification-schedule".equals(operation)
                || "notification-show-now".equals(operation)
                || "notification-cancel".equals(operation)
                || "notification-pending".equals(operation)) return CAP_NOTIFICATIONS;
        if ("notification-delivered".equals(operation)) {
            return CAP_NOTIFICATIONS && Build.VERSION.SDK_INT >= 23;
        }
        if ("permission-status".equals(operation)
                || "permission-request".equals(operation)) return ANY_GENERAL_PERMISSION;
        if ("deep-link-initial".equals(operation)) return CAP_DEEP_LINKS;
        if ("widget-update".equals(operation)) return CAP_WIDGET;
        if (operation.startsWith("live-activity-")) return CAP_LIVE_ACTIVITY;
        return false;
    }

    private static void initialize(FerryActivity activity) throws JSONException {
        currentActivity = new WeakReference<FerryActivity>(activity);
        handleIntent(activity, activity.getIntent(), !startedSent);
        nativeReady = true;
        if (!startedSent) {
            startedSent = true;
            dispatchEvent(new JSONObject().put("kind", "started"));
        }
        synchronized (EVENT_LOCK) {
            while (!PENDING_EVENTS.isEmpty()) {
                nativeDispatchEvent(PENDING_EVENTS.removeFirst());
            }
        }
        String storedOpen = notificationPrefs(activity).getString(LAST_OPEN_EVENT, null);
        if (storedOpen != null) {
            notificationPrefs(activity).edit().remove(LAST_OPEN_EVENT).apply();
            dispatchEvent(new JSONObject(storedOpen));
        }
        registerNetworkCallback(activity);
    }

    static void lifecycle(String kind) {
        try {
            dispatchEvent(new JSONObject().put("kind", kind));
        } catch (JSONException ignored) {
            // Constant JSON keys and values cannot fail.
        }
    }

    static void configurationChanged(Context context) {
        try {
            dispatchEvent(new JSONObject().put("kind", "theme-changed").put("value", theme(context)));
            DisplayMetrics metrics = context.getResources().getDisplayMetrics();
            float density = metrics.density <= 0.0f ? 1.0f : metrics.density;
            dispatchEvent(new JSONObject()
                    .put("kind", "window-resized")
                    .put("width", metrics.widthPixels / density)
                    .put("height", metrics.heightPixels / density));
        } catch (JSONException ignored) {
            // Constant JSON keys and a bounded theme value cannot fail.
        }
    }

    static synchronized void handleIntent(Context context, Intent intent, boolean coldStart) {
        if (intent == null) return;
        String open = intent.getStringExtra(EXTRA_OPEN_EVENT);
        boolean trustedInternal = internalToken(context).equals(
                intent.getStringExtra(EXTRA_INTERNAL_TOKEN));
        String explicitDeepLink = trustedInternal
                ? intent.getStringExtra(EXTRA_DEEP_LINK)
                : null;
        Uri data = explicitDeepLink == null ? intent.getData() : Uri.parse(explicitDeepLink);
        intent.removeExtra(EXTRA_NOTIFICATION_ID);
        intent.removeExtra(EXTRA_OPEN_EVENT);
        intent.removeExtra(EXTRA_DEEP_LINK);
        intent.removeExtra(EXTRA_INTERNAL_TOKEN);
        intent.setData(null);
        boolean handledNotification = false;
        if (open != null && trustedInternal) {
            try {
                dispatchEvent(new JSONObject(open));
                handledNotification = true;
            } catch (JSONException ignored) {
                // Ignore malformed extras not generated by this package.
            }
        }
        if (!handledNotification && CAP_DEEP_LINKS && data != null && isAllowedDeepLink(data)) {
            String value = data.toString();
            if (coldStart && initialDeepLink == null) initialDeepLink = value;
            try {
                dispatchEvent(new JSONObject().put("kind", "deep-link").put("value", value));
            } catch (JSONException ignored) {
                // Uri text is safely escaped by JSONObject.
            }
        }
    }

    private static void dispatchEvent(JSONObject event) {
        String encoded = event.toString();
        synchronized (EVENT_LOCK) {
            if (!nativeReady) {
                if (PENDING_EVENTS.size() == 64) PENDING_EVENTS.removeFirst();
                PENDING_EVENTS.addLast(encoded);
                return;
            }
        }
        nativeDispatchEvent(encoded);
    }

    private static JSONObject networkStatus(Context context) throws JSONException {
        ConnectivityManager manager = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (Build.VERSION.SDK_INT < 23) return legacyNetworkStatus(manager);
        Network network = manager == null ? null : manager.getActiveNetwork();
        NetworkCapabilities capabilities = network == null ? null : manager.getNetworkCapabilities(network);
        String state = "offline";
        String transport = "unknown";
        if (network != null) state = "local-only";
        if (capabilities != null) {
            boolean validated = Build.VERSION.SDK_INT < 23
                    || capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);
            if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && validated) {
                state = "online";
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transport = "vpn";
            else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transport = "wifi";
            else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transport = "cellular";
            else if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transport = "ethernet";
            else transport = "other";
        }
        JSONObject value = new JSONObject()
                .put("state", state)
                .put("transport", transport);
        if (manager == null || network == null) {
            value.put("expensive", JSONObject.NULL).put("constrained", JSONObject.NULL);
        } else {
            value.put("expensive", manager.isActiveNetworkMetered());
            if (Build.VERSION.SDK_INT >= 24) {
                value.put(
                        "constrained",
                        manager.getRestrictBackgroundStatus()
                                != ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED);
            } else {
                value.put("constrained", JSONObject.NULL);
            }
        }
        return value;
    }

    @SuppressWarnings("deprecation")
    private static JSONObject legacyNetworkStatus(ConnectivityManager manager) throws JSONException {
        NetworkInfo info = manager == null ? null : manager.getActiveNetworkInfo();
        String state = info == null || !info.isConnected() ? "offline" : "online";
        String transport = "unknown";
        if (info != null) {
            if (info.getType() == ConnectivityManager.TYPE_WIFI) transport = "wifi";
            else if (info.getType() == ConnectivityManager.TYPE_MOBILE) transport = "cellular";
            else if (info.getType() == ConnectivityManager.TYPE_ETHERNET) transport = "ethernet";
            else transport = "other";
        }
        return new JSONObject()
                .put("state", state)
                .put("transport", transport)
                .put("expensive", manager == null ? JSONObject.NULL : manager.isActiveNetworkMetered())
                .put("constrained", JSONObject.NULL);
    }

    private static void registerNetworkCallback(Context context) {
        if (!CAP_NETWORK_STATUS || networkCallback != null) return;
        final Context applicationContext = context.getApplicationContext();
        if (applicationContext == null) return;
        final ConnectivityManager manager = (ConnectivityManager)
                applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) return;
        networkCallback = new ConnectivityManager.NetworkCallback() {
            private void changed() {
                try {
                    dispatchEvent(new JSONObject()
                            .put("kind", "network-changed")
                            .put("value", networkStatus(applicationContext)));
                } catch (JSONException ignored) {
                    // Network status uses only constant fields.
                }
            }

            @Override public void onAvailable(Network network) { changed(); }
            @Override public void onLost(Network network) { changed(); }
            @Override public void onCapabilitiesChanged(
                    Network network,
                    NetworkCapabilities capabilities) { changed(); }
        };
        try {
            if (Build.VERSION.SDK_INT >= 24) {
                manager.registerDefaultNetworkCallback(networkCallback);
            } else {
                NetworkRequest request = new NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build();
                manager.registerNetworkCallback(request, networkCallback);
            }
        } catch (SecurityException error) {
            networkCallback = null;
        }
    }

    private static JSONObject probe(String source, long timeoutMillis) throws Exception {
        URL url = new URL(source);
        String protocol = url.getProtocol();
        if (!("http".equals(protocol) || "https".equals(protocol))) {
            throw new IllegalArgumentException("network probes require HTTP or HTTPS");
        }
        int timeout = (int) Math.max(1L, Math.min(timeoutMillis, Integer.MAX_VALUE));
        long started = SystemClock.elapsedRealtime();
        Integer status = null;
        boolean reachable = false;
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("HEAD");
            connection.connect();
            status = connection.getResponseCode();
            reachable = true;
        } catch (IOException ignored) {
            reachable = false;
        } finally {
            if (connection != null) connection.disconnect();
        }
        long latency = Math.max(0L, SystemClock.elapsedRealtime() - started);
        JSONObject duration = new JSONObject()
                .put("secs", latency / 1000L)
                .put("nanos", (latency % 1000L) * 1000000L);
        return new JSONObject()
                .put("url", source)
                .put("reachable", reachable)
                .put("status_code", status == null ? JSONObject.NULL : status)
                .put("latency", duration);
    }

    private static void haptic(final Activity activity, final Object call) throws Exception {
        runUi(activity, new ThrowingRunnable() {
            @Override public void run() {
                String type = String.valueOf(call);
                if (call instanceof JSONObject) {
                    JSONObject object = (JSONObject) call;
                    if (object.has("Impact")) type = object.optString("Impact", "medium");
                    else if (object.has("Notification")) {
                        type = object.optString("Notification", "success");
                    }
                }
                int feedback = "Selection".equals(type)
                        ? HapticFeedbackConstants.KEYBOARD_TAP
                        : HapticFeedbackConstants.VIRTUAL_KEY;
                if (activity.getWindow().getDecorView().performHapticFeedback(feedback)) return;
                Vibrator vibrator = (Vibrator) activity.getSystemService(Context.VIBRATOR_SERVICE);
                if (vibrator == null || !vibrator.hasVibrator()) return;
                long duration = ("heavy".equals(type) || "error".equals(type)) ? 70L : 30L;
                if (Build.VERSION.SDK_INT >= 26) {
                    vibrator.vibrate(VibrationEffect.createOneShot(duration, VibrationEffect.DEFAULT_AMPLITUDE));
                } else {
                    vibrator.vibrate(duration);
                }
            }
        });
    }

    private static Object clipboardRead(Context context) {
        ClipboardManager clipboard = (ClipboardManager)
                context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null || !clipboard.hasPrimaryClip()) return JSONObject.NULL;
        ClipData clip = clipboard.getPrimaryClip();
        if (clip == null || clip.getItemCount() == 0) return JSONObject.NULL;
        CharSequence text = clip.getItemAt(0).coerceToText(context);
        return text == null ? JSONObject.NULL : text.toString();
    }

    private static void clipboardWrite(Context context, String text) {
        ClipboardManager clipboard = (ClipboardManager)
                context.getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard == null) throw new IllegalStateException("clipboard service is unavailable");
        clipboard.setPrimaryClip(ClipData.newPlainText("RustFerry", text));
    }

    private static void share(final Activity activity, JSONObject request) throws Exception {
        String kind = request.getString("kind");
        Object content = request.get("content");
        final Intent send;
        if ("files".equals(kind)) {
            JSONArray files = (JSONArray) content;
            ArrayList<Uri> uris = new ArrayList<Uri>();
            for (int index = 0; index < files.length(); index++) {
                uris.add(FerryFileProvider.uriFor(activity, files.getString(index)));
            }
            send = new Intent(uris.size() == 1 ? Intent.ACTION_SEND : Intent.ACTION_SEND_MULTIPLE);
            send.setType("*/*");
            send.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            if (uris.size() == 1) {
                send.putExtra(Intent.EXTRA_STREAM, uris.get(0));
                send.setClipData(ClipData.newUri(activity.getContentResolver(), "shared file", uris.get(0)));
            } else {
                send.putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris);
                ClipData clip = ClipData.newUri(activity.getContentResolver(), "shared files", uris.get(0));
                for (int index = 1; index < uris.size(); index++) {
                    clip.addItem(new ClipData.Item(uris.get(index)));
                }
                send.setClipData(clip);
            }
        } else {
            send = new Intent(Intent.ACTION_SEND);
            send.setType("text/plain");
            send.putExtra(Intent.EXTRA_TEXT, String.valueOf(content));
        }
        runUi(activity, new ThrowingRunnable() {
            @Override public void run() {
                activity.startActivity(Intent.createChooser(send, null));
            }
        });
    }

    private static void openUrl(final Activity activity, String value) throws Exception {
        final Uri uri = Uri.parse(value);
        String scheme = uri.getScheme();
        if (scheme == null
                || !("http".equalsIgnoreCase(scheme)
                        || "https".equalsIgnoreCase(scheme)
                        || "mailto".equalsIgnoreCase(scheme)
                        || "tel".equalsIgnoreCase(scheme)
                        || "sms".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("URL scheme cannot be opened externally");
        }
        runUi(activity, new ThrowingRunnable() {
            @Override public void run() {
                Intent intent = new Intent(Intent.ACTION_VIEW, uri);
                if (intent.resolveActivity(activity.getPackageManager()) == null) {
                    throw new IllegalStateException("no application can open this URL");
                }
                activity.startActivity(intent);
            }
        });
    }

    private static void openSettings(final Activity activity) throws Exception {
        runUi(activity, new ThrowingRunnable() {
            @Override public void run() {
                Intent intent = new Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", activity.getPackageName(), null));
                activity.startActivity(intent);
            }
        });
    }

    @SuppressWarnings("deprecation")
    private static JSONObject appInfo(Context context) throws Exception {
        PackageManager manager = context.getPackageManager();
        PackageInfo info = manager.getPackageInfo(context.getPackageName(), 0);
        CharSequence label = manager.getApplicationLabel(context.getApplicationInfo());
        long build = Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
        return new JSONObject()
                .put("display_name", label == null ? context.getPackageName() : label.toString())
                .put("identifier", context.getPackageName())
                .put("version", info.versionName == null ? "" : info.versionName)
                .put("build", Long.toString(build));
    }

    private static JSONObject deviceInfo(Context context) throws JSONException {
        Locale locale;
        if (Build.VERSION.SDK_INT >= 24) {
            locale = context.getResources().getConfiguration().getLocales().get(0);
        } else {
            locale = context.getResources().getConfiguration().locale;
        }
        return new JSONObject()
                .put("platform", "android")
                .put("os_version", Build.VERSION.RELEASE == null ? "" : Build.VERSION.RELEASE)
                .put("model", Build.MODEL == null ? JSONObject.NULL : Build.MODEL)
                .put("locale", locale == null ? JSONObject.NULL : locale.toLanguageTag());
    }

    private static String theme(Context context) {
        int mode = context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        if (mode == Configuration.UI_MODE_NIGHT_YES) return "dark";
        if (mode == Configuration.UI_MODE_NIGHT_NO) return "light";
        return "unknown";
    }

    private static boolean permissionSupported(String permission) {
        if ("notifications".equals(permission)) return CAP_NOTIFICATIONS || CAP_LIVE_ACTIVITY;
        if ("network-state".equals(permission)) return CAP_NETWORK_STATUS;
        if ("camera".equals(permission)) return PERMISSION_CAMERA;
        if ("photos".equals(permission)) return PERMISSION_PHOTOS;
        if ("microphone".equals(permission)) return PERMISSION_MICROPHONE;
        if ("location-when-in-use".equals(permission)) return PERMISSION_LOCATION;
        return false;
    }

    private static String[] androidPermissions(String permission) {
        if ("notifications".equals(permission)) {
            return Build.VERSION.SDK_INT >= 33
                    ? new String[] {Manifest.permission.POST_NOTIFICATIONS}
                    : new String[0];
        }
        if ("camera".equals(permission)) return new String[] {Manifest.permission.CAMERA};
        if ("photos".equals(permission)) {
            return new String[] {Build.VERSION.SDK_INT >= 33
                    ? Manifest.permission.READ_MEDIA_IMAGES
                    : Manifest.permission.READ_EXTERNAL_STORAGE};
        }
        if ("microphone".equals(permission)) {
            return new String[] {Manifest.permission.RECORD_AUDIO};
        }
        if ("location-when-in-use".equals(permission)) {
            return new String[] {
                    Manifest.permission.ACCESS_COARSE_LOCATION,
                    Manifest.permission.ACCESS_FINE_LOCATION
            };
        }
        return new String[0];
    }

    private static String permissionStatus(Activity activity, String permission) {
        if (!permissionSupported(permission)) return "unsupported";
        if ("network-state".equals(permission)) return "granted";
        if ("notifications".equals(permission) && Build.VERSION.SDK_INT < 33) {
            return notificationsEnabled(activity) ? "granted" : "denied";
        }
        String[] androidPermissions = androidPermissions(permission);
        if (androidPermissions.length == 0 || Build.VERSION.SDK_INT < 23) return "granted";
        for (String androidPermission : androidPermissions) {
            if (activity.checkSelfPermission(androidPermission) == PackageManager.PERMISSION_GRANTED) {
                if (!"notifications".equals(permission) || notificationsEnabled(activity)) {
                    return "granted";
                }
                return "denied";
            }
        }
        boolean requested = activity.getSharedPreferences(PERMISSION_PREFS, Context.MODE_PRIVATE)
                .getBoolean(permission, false);
        if (!requested) return "not-determined";
        for (String androidPermission : androidPermissions) {
            if (activity.shouldShowRequestPermissionRationale(androidPermission)) return "denied";
        }
        return "permanently-denied";
    }

    private static String notificationPermissionStatus(Activity activity) {
        return permissionStatus(activity, "notifications");
    }

    private static String requestPermission(final FerryActivity activity, final String permission)
            throws Exception {
        if (!permissionSupported(permission)) return "unsupported";
        if ("notifications".equals(permission) && Build.VERSION.SDK_INT < 33) {
            return notificationPermissionStatus(activity);
        }
        final String[] androidPermissions = androidPermissions(permission);
        if (androidPermissions.length == 0 || Build.VERSION.SDK_INT < 23) return "granted";
        if ("granted".equals(permissionStatus(activity, permission))) {
            return "granted";
        }
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("permission requests must run on a RustFerry worker thread");
        }
        final int requestCode = NEXT_PERMISSION_REQUEST.incrementAndGet();
        final PermissionWait wait = new PermissionWait(permission);
        PERMISSION_WAITS.put(requestCode, wait);
        activity.getSharedPreferences(PERMISSION_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(permission, true).apply();
        activity.runOnUiThread(new Runnable() {
            @Override public void run() {
                activity.requestPermissions(androidPermissions, requestCode);
            }
        });
        if (!wait.latch.await(60, TimeUnit.SECONDS)) {
            PERMISSION_WAITS.remove(requestCode);
            throw new IllegalStateException("permission request timed out");
        }
        return permissionStatus(activity, permission);
    }

    static void onRequestPermissionsResult(
            FerryActivity activity,
            int requestCode,
            String[] permissions,
            int[] grantResults) {
        PermissionWait wait = PERMISSION_WAITS.remove(requestCode);
        if (wait != null) wait.latch.countDown();
    }

    private static void requireNotificationPermission(Activity activity) {
        if (!"granted".equals(notificationPermissionStatus(activity))) {
            throw new SecurityException("notification permission is not granted");
        }
    }

    private static void validateNotification(JSONObject notification) throws JSONException {
        JSONObject sound = notification.optJSONObject("sound");
        if (sound != null && "named".equals(sound.optString("mode"))) {
            throw new UnsupportedOperationException("named Android notification sounds are not packaged yet");
        }
        requireAllowedDeepLink(nullableString(notification, "deep_link"));
    }

    private static void scheduleNotification(Context context, JSONObject notification) throws Exception {
        validateNotification(notification);
        String id = notification.getString("id");
        long scheduledAt = notification.getLong("scheduled_at");
        notificationPrefs(context).edit().putString(PENDING_PREFIX + id, notification.toString()).apply();
        Intent intent = new Intent(context, FerryNotificationReceiver.class)
                .setAction(ACTION_DELIVER)
                .setData(internalUri("notification", id))
                .putExtra(EXTRA_NOTIFICATION_ID, id);
        PendingIntent pending = PendingIntent.getBroadcast(context, 0, intent, PENDING_FLAGS);
        AlarmManager alarms = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (alarms == null) throw new IllegalStateException("alarm service is unavailable");
        long interval = durationMillis(notification.optJSONObject("repeat_interval"));
        if (interval > 0L) {
            alarms.setInexactRepeating(AlarmManager.RTC_WAKEUP, scheduledAt, interval, pending);
        } else if (Build.VERSION.SDK_INT >= 23) {
            alarms.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, scheduledAt, pending);
        } else {
            alarms.set(AlarmManager.RTC_WAKEUP, scheduledAt, pending);
        }
    }

    static void receiveNotification(Context context, Intent intent) {
        if (intent == null) return;
        if (ACTION_OPEN.equals(intent.getAction())) {
            String event = intent.getStringExtra(EXTRA_OPEN_EVENT);
            if (event != null) dispatchOrStoreOpen(context, event);
            return;
        }
        if (!ACTION_DELIVER.equals(intent.getAction())) return;
        String id = intent.getStringExtra(EXTRA_NOTIFICATION_ID);
        if (id == null) return;
        String encoded = notificationPrefs(context).getString(PENDING_PREFIX + id, null);
        if (encoded == null) return;
        try {
            JSONObject notification = new JSONObject(encoded);
            showNotification(context, notification, false);
            if (durationMillis(notification.optJSONObject("repeat_interval")) == 0L) {
                notificationPrefs(context).edit().remove(PENDING_PREFIX + id).apply();
            }
        } catch (Exception ignored) {
            notificationPrefs(context).edit().remove(PENDING_PREFIX + id).apply();
        }
    }

    private static void showNotification(
            Context context,
            JSONObject source,
            boolean ongoing) throws Exception {
        validateNotification(source);
        if (!"granted".equals(notificationPermissionStatusForContext(context))) {
            if (ongoing) throw new SecurityException("notification permission is not granted");
            return;
        }
        String id = source.getString("id");
        JSONObject sound = source.optJSONObject("sound");
        boolean silent = sound != null && "silent".equals(sound.optString("mode"));
        String requestedChannel = source.optString("android_channel", "rustferry-local");
        if (requestedChannel.length() == 0 || "null".equals(requestedChannel)) {
            requestedChannel = "rustferry-local";
        }
        String channel = silent ? requestedChannel + "-silent" : requestedChannel;
        NotificationManager manager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) throw new IllegalStateException("notification service is unavailable");
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel created = new NotificationChannel(
                    channel,
                    ongoing ? "Live updates" : "Local notifications",
                    ongoing ? NotificationManager.IMPORTANCE_LOW : NotificationManager.IMPORTANCE_DEFAULT);
            if (silent) created.setSound(null, null);
            manager.createNotificationChannel(created);
        }
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(context, channel)
                : new Notification.Builder(context);
        int icon = context.getResources().getIdentifier("ferry_icon", "mipmap", context.getPackageName());
        if (icon == 0) icon = context.getResources().getIdentifier("ferry_icon", "drawable", context.getPackageName());
        if (icon == 0) icon = android.R.drawable.ic_dialog_info;
        builder.setSmallIcon(icon)
                .setContentTitle(source.optString("title", ""))
                .setContentText(source.optString("body", ""))
                .setAutoCancel(!ongoing)
                .setOngoing(ongoing)
                .setOnlyAlertOnce(ongoing);
        String subtitle = nullableString(source, "subtitle");
        if (subtitle != null) builder.setSubText(subtitle);
        if (silent) builder.setSound(null);
        else if (Build.VERSION.SDK_INT < 26) builder.setDefaults(Notification.DEFAULT_SOUND);
        JSONObject openEvent = notificationOpenEvent(source, null);
        Intent content = new Intent(context, FerryActivity.class)
                .setData(internalUri("open", id))
                .putExtra(EXTRA_OPEN_EVENT, openEvent.toString())
                .putExtra(EXTRA_INTERNAL_TOKEN, internalToken(context))
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        String deepLink = nullableString(source, "deep_link");
        if (deepLink != null) content.putExtra(EXTRA_DEEP_LINK, deepLink);
        builder.setContentIntent(PendingIntent.getActivity(context, 0, content, PENDING_FLAGS));
        JSONArray actions = source.optJSONArray("actions");
        if (actions != null) {
            for (int index = 0; index < actions.length(); index++) {
                JSONObject action = actions.getJSONObject(index);
                JSONObject event = notificationOpenEvent(source, action.getString("id"));
                PendingIntent pending;
                if (action.optBoolean("foreground", true)) {
                    Intent actionIntent = new Intent(context, FerryActivity.class)
                            .setData(internalUri("action", id + "/" + action.getString("id")))
                            .putExtra(EXTRA_OPEN_EVENT, event.toString())
                            .putExtra(EXTRA_INTERNAL_TOKEN, internalToken(context))
                            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                    pending = PendingIntent.getActivity(context, 0, actionIntent, PENDING_FLAGS);
                } else {
                    Intent actionIntent = new Intent(context, FerryNotificationReceiver.class)
                            .setAction(ACTION_OPEN)
                            .setData(internalUri("action", id + "/" + action.getString("id")))
                            .putExtra(EXTRA_OPEN_EVENT, event.toString());
                    pending = PendingIntent.getBroadcast(context, 0, actionIntent, PENDING_FLAGS);
                }
                Notification.Action.Builder actionBuilder = new Notification.Action.Builder(
                        0,
                        action.getString("title"),
                        pending);
                if (Build.VERSION.SDK_INT >= 31) {
                    actionBuilder.setAuthenticationRequired(
                            action.optBoolean("authentication_required", false));
                }
                builder.addAction(actionBuilder.build());
            }
        }
        manager.notify(notificationTag(id), 0, builder.build());
        if (!ongoing) {
            JSONObject delivered = new JSONObject()
                    .put("notification", source)
                    .put("delivered_at", System.currentTimeMillis());
            notificationPrefs(context).edit()
                    .putString(DELIVERED_PREFIX + id, delivered.toString()).apply();
        }
    }

    private static JSONObject notificationOpenEvent(JSONObject source, String action)
            throws JSONException {
        JSONObject event = new JSONObject()
                .put("kind", "notification-opened")
                .put("id", source.getString("id"))
                .put("action", action == null ? JSONObject.NULL : action)
                .put("payload", source.has("payload") ? source.get("payload") : JSONObject.NULL)
                .put("deep_link", source.has("deep_link") ? source.get("deep_link") : JSONObject.NULL);
        return event;
    }

    private static void dispatchOrStoreOpen(Context context, String encoded) {
        if (!nativeReady) {
            notificationPrefs(context).edit().putString(LAST_OPEN_EVENT, encoded).apply();
            return;
        }
        try {
            dispatchEvent(new JSONObject(encoded));
        } catch (JSONException ignored) {
            // Ignore malformed internal extras.
        }
    }

    private static void cancelNotification(Context context, String id) {
        Intent intent = new Intent(context, FerryNotificationReceiver.class)
                .setAction(ACTION_DELIVER)
                .setData(internalUri("notification", id));
        PendingIntent pending = PendingIntent.getBroadcast(
                context,
                0,
                intent,
                PendingIntent.FLAG_NO_CREATE | PendingIntent.FLAG_IMMUTABLE);
        AlarmManager alarms = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        if (pending != null && alarms != null) alarms.cancel(pending);
        NotificationManager manager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager != null) manager.cancel(notificationTag(id), 0);
        notificationPrefs(context).edit()
                .remove(PENDING_PREFIX + id)
                .remove(DELIVERED_PREFIX + id)
                .apply();
    }

    private static void cancelAllNotifications(Context context) {
        for (String id : prefixedKeys(notificationPrefs(context), PENDING_PREFIX)) {
            cancelNotification(context, id);
        }
        NotificationManager manager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
        SharedPreferences.Editor editor = notificationPrefs(context).edit();
        for (String id : prefixedKeys(notificationPrefs(context), DELIVERED_PREFIX)) {
            if (manager != null) manager.cancel(notificationTag(id), 0);
            editor.remove(DELIVERED_PREFIX + id);
        }
        editor.apply();
    }

    private static JSONArray pendingNotifications(Context context) throws JSONException {
        JSONArray result = new JSONArray();
        SharedPreferences prefs = notificationPrefs(context);
        for (String id : prefixedKeys(prefs, PENDING_PREFIX)) {
            String encoded = prefs.getString(PENDING_PREFIX + id, null);
            if (encoded != null) result.put(new JSONObject().put("notification", new JSONObject(encoded)));
        }
        return result;
    }

    private static JSONArray deliveredNotifications(Context context) throws JSONException {
        NotificationManager manager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
        Set<String> active = new HashSet<String>();
        if (manager != null) {
            for (StatusBarNotification notification : manager.getActiveNotifications()) {
                if (notification.getTag() != null && notification.getTag().startsWith("rustferry:")) {
                    active.add(notification.getTag().substring("rustferry:".length()));
                }
            }
        }
        JSONArray result = new JSONArray();
        SharedPreferences prefs = notificationPrefs(context);
        SharedPreferences.Editor cleanup = prefs.edit();
        for (String id : prefixedKeys(prefs, DELIVERED_PREFIX)) {
            String encoded = prefs.getString(DELIVERED_PREFIX + id, null);
            if (active.contains(id) && encoded != null) result.put(new JSONObject(encoded));
            else cleanup.remove(DELIVERED_PREFIX + id);
        }
        cleanup.apply();
        return result;
    }

    private static String notificationPermissionStatusForContext(Context context) {
        if (Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                        != PackageManager.PERMISSION_GRANTED) {
            return "denied";
        }
        return notificationsEnabled(context) ? "granted" : "denied";
    }

    private static boolean notificationsEnabled(Context context) {
        NotificationManager manager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager == null) return false;
        return Build.VERSION.SDK_INT < 24 || manager.areNotificationsEnabled();
    }

    private static SharedPreferences notificationPrefs(Context context) {
        return context.getSharedPreferences(NOTIFICATION_PREFS, Context.MODE_PRIVATE);
    }

    private static List<String> prefixedKeys(SharedPreferences prefs, String prefix) {
        ArrayList<String> result = new ArrayList<String>();
        for (String key : prefs.getAll().keySet()) {
            if (key.startsWith(prefix)) result.add(key.substring(prefix.length()));
        }
        Collections.sort(result);
        return result;
    }

    private static String notificationTag(String id) {
        return "rustferry:" + id;
    }

    private static Uri internalUri(String category, String value) {
        return new Uri.Builder()
                .scheme("rustferry-internal")
                .authority(category)
                .appendPath(value)
                .build();
    }

    private static String internalToken(Context context) {
        synchronized (EVENT_LOCK) {
            SharedPreferences prefs = notificationPrefs(context);
            String token = prefs.getString("internal-token", null);
            if (token != null) return token;
            token = UUID.randomUUID().toString();
            prefs.edit().putString("internal-token", token).commit();
            return prefs.getString("internal-token", token);
        }
    }

    private static boolean isAllowedDeepLink(Uri uri) {
        String scheme = uri.getScheme();
        if (scheme == null) return false;
        boolean schemeAllowed = false;
        for (String allowed : DEEP_LINK_SCHEMES) {
            if (allowed.equalsIgnoreCase(scheme)) {
                schemeAllowed = true;
                break;
            }
        }
        if (!schemeAllowed) return false;
        if (DEEP_LINK_HOSTS.length > 0) {
            String host = uri.getHost();
            boolean hostAllowed = false;
            for (String allowed : DEEP_LINK_HOSTS) {
                if (host != null && allowed.equalsIgnoreCase(host)) {
                    hostAllowed = true;
                    break;
                }
            }
            if (!hostAllowed) return false;
        }
        if (DEEP_LINK_ACTIONS.length > 0) {
            String action = null;
            for (String segment : uri.getPathSegments()) {
                if (segment.length() > 0) {
                    action = segment;
                    break;
                }
            }
            boolean actionAllowed = false;
            for (String allowed : DEEP_LINK_ACTIONS) {
                if (allowed.equals(action)) {
                    actionAllowed = true;
                    break;
                }
            }
            if (!actionAllowed) return false;
        }
        return true;
    }

    private static void requireAllowedDeepLink(String value) {
        if (value != null && !isAllowedDeepLink(Uri.parse(value))) {
            throw new IllegalArgumentException("deep-link scheme is not enabled in ferry.toml");
        }
    }

    private static void updateWidgetSnapshot(Context context, String id, JSONObject snapshot) {
        requireAllowedDeepLink(nullableString(snapshot, "deep_link"));
        validateWidgetContent(snapshot.optJSONObject("content"));
        context.getSharedPreferences(WIDGET_PREFS, Context.MODE_PRIVATE)
                .edit()
                .putString("snapshot." + id, snapshot.toString())
                .putString("latest", snapshot.toString())
                .apply();
        AppWidgetManager manager = AppWidgetManager.getInstance(context);
        ComponentName provider = new ComponentName(context, FerryWidgetProvider.class);
        updateWidgets(context, manager, manager.getAppWidgetIds(provider));
    }

    static void updateWidgets(Context context, AppWidgetManager manager, int[] appWidgetIds) {
        String encoded = context.getSharedPreferences(WIDGET_PREFS, Context.MODE_PRIVATE)
                .getString("latest", null);
        if (encoded == null) return;
        try {
            JSONObject snapshot = new JSONObject(encoded);
            int layout = context.getResources().getIdentifier(
                    "ferry_widget", "layout", context.getPackageName());
            int textId = context.getResources().getIdentifier(
                    "ferry_widget_text", "id", context.getPackageName());
            int progressId = context.getResources().getIdentifier(
                    "ferry_widget_progress", "id", context.getPackageName());
            if (layout == 0 || textId == 0 || progressId == 0) return;
            StringBuilder text = new StringBuilder();
            appendWidgetLine(text, nullableString(snapshot, "title"));
            appendWidgetLine(text, nullableString(snapshot, "value"));
            appendWidgetLine(text, nullableString(snapshot, "caption"));
            JSONObject content = snapshot.optJSONObject("content");
            if (content != null) appendWidgetLine(text, content.getString(
                    "text".equals(content.getString("kind")) ? "value" : "label"));
            for (int appWidgetId : appWidgetIds) {
                RemoteViews views = new RemoteViews(context.getPackageName(), layout);
                views.setTextViewText(textId, text.length() == 0
                        ? context.getApplicationInfo().loadLabel(context.getPackageManager())
                        : text.toString());
                if (snapshot.isNull("progress")) {
                    views.setViewVisibility(progressId, View.GONE);
                } else {
                    int progress = (int) Math.round(snapshot.getDouble("progress") * 100.0);
                    views.setProgressBar(progressId, 100, progress, false);
                    views.setViewVisibility(progressId, View.VISIBLE);
                }
                String deepLink = widgetContentLink(content);
                if (deepLink == null) deepLink = nullableString(snapshot, "deep_link");
                if (deepLink != null) {
                    Intent open = new Intent(context, FerryActivity.class)
                            .setAction(Intent.ACTION_VIEW)
                            .setData(Uri.parse(deepLink));
                    views.setOnClickPendingIntent(
                            textId,
                            PendingIntent.getActivity(context, appWidgetId, open, PENDING_FLAGS));
                }
                manager.updateAppWidget(appWidgetId, views);
            }
        } catch (JSONException ignored) {
            // A malformed private snapshot is ignored until the next Rust update.
        }
    }

    private static void appendWidgetLine(StringBuilder text, String value) {
        if (value == null || value.length() == 0) return;
        if (text.length() > 0) text.append('\n');
        text.append(value);
    }

    private static void validateWidgetContent(JSONObject content) {
        if (content == null) return;
        String kind = content.optString("kind", "");
        if ("text".equals(kind)) {
            if (!content.has("value") || content.isNull("value")) {
                throw new IllegalArgumentException("text widget content requires a value");
            }
            return;
        }
        if ("button".equals(kind) || "link".equals(kind)) {
            String label = nullableString(content, "label");
            String destination = nullableString(content, "destination");
            if (label == null || label.length() == 0 || destination == null) {
                throw new IllegalArgumentException(
                        "button/link widget content requires a label and destination");
            }
            requireAllowedDeepLink(destination);
            return;
        }
        throw new UnsupportedOperationException(
                "Android widgets currently support text and one link/button action");
    }

    private static String widgetContentLink(JSONObject content) {
        if (content == null) return null;
        String kind = content.optString("kind", "");
        return "button".equals(kind) || "link".equals(kind)
                ? nullableString(content, "destination")
                : null;
    }

    private static String startLiveActivity(Context context, JSONObject request) throws Exception {
        requireNotificationPermissionForContext(context);
        String id = UUID.randomUUID().toString();
        JSONObject active = new JSONObject()
                .put("id", id)
                .put("attributes", request.get("attributes"))
                .put("state", request.get("state"))
                .put("snapshot", request.has("snapshot") ? request.get("snapshot") : JSONObject.NULL);
        showNotification(context, liveNotification(active), true);
        livePrefs(context).edit().putString(LIVE_PREFIX + id, active.toString()).apply();
        return id;
    }

    private static void updateLiveActivity(Context context, JSONObject request) throws Exception {
        requireNotificationPermissionForContext(context);
        String id = request.getString("id");
        SharedPreferences prefs = livePrefs(context);
        String encoded = prefs.getString(LIVE_PREFIX + id, null);
        if (encoded == null) throw new IllegalArgumentException("live activity does not exist");
        JSONObject active = new JSONObject(encoded)
                .put("state", request.get("state"))
                .put("snapshot", request.has("snapshot") ? request.get("snapshot") : JSONObject.NULL);
        showNotification(context, liveNotification(active), true);
        prefs.edit().putString(LIVE_PREFIX + id, active.toString()).apply();
    }

    private static void endLiveActivity(Context context, JSONObject request) throws Exception {
        String id = request.getString("id");
        livePrefs(context).edit().remove(LIVE_PREFIX + id).apply();
        NotificationManager manager = (NotificationManager)
                context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (manager != null) manager.cancel(notificationTag("live-" + id), 0);
    }

    private static JSONArray listLiveActivities(Context context) throws JSONException {
        JSONArray result = new JSONArray();
        SharedPreferences prefs = livePrefs(context);
        for (String id : prefixedKeys(prefs, LIVE_PREFIX)) {
            String encoded = prefs.getString(LIVE_PREFIX + id, null);
            if (encoded != null) result.put(new JSONObject(encoded));
        }
        return result;
    }

    private static JSONObject liveNotification(JSONObject active) throws JSONException {
        JSONObject snapshot = active.optJSONObject("snapshot");
        String id = active.getString("id");
        String title = snapshot == null ? "Live update" : snapshot.optString("title", "Live update");
        String body = snapshot == null ? active.get("state").toString() : snapshot.optString("status", "");
        JSONObject sound = new JSONObject().put("mode", "silent");
        JSONObject notification = new JSONObject()
                .put("id", "live-" + id)
                .put("title", title)
                .put("body", body)
                .put("subtitle", JSONObject.NULL)
                .put("payload", active.get("state"))
                .put("deep_link", snapshot == null ? JSONObject.NULL : snapshot.opt("deep_link"))
                .put("scheduled_at", JSONObject.NULL)
                .put("repeat_interval", JSONObject.NULL)
                .put("android_channel", "rustferry-live")
                .put("actions", new JSONArray())
                .put("badge", JSONObject.NULL)
                .put("sound", sound);
        return notification;
    }

    private static SharedPreferences livePrefs(Context context) {
        return context.getSharedPreferences(LIVE_PREFS, Context.MODE_PRIVATE);
    }

    private static void requireNotificationPermissionForContext(Context context) {
        if (!"granted".equals(notificationPermissionStatusForContext(context))) {
            throw new SecurityException("notification permission is not granted");
        }
    }

    private static long durationMillis(JSONObject duration) {
        if (duration == null) return 0L;
        long seconds = duration.optLong("secs", 0L);
        long nanos = duration.optLong("nanos", 0L);
        if (seconds > Long.MAX_VALUE / 1000L) return Long.MAX_VALUE;
        return seconds * 1000L + nanos / 1000000L;
    }

    private static String nullableString(JSONObject object, String key) {
        if (!object.has(key) || object.isNull(key)) return null;
        return object.optString(key, null);
    }

    private static void runUi(final Activity activity, final ThrowingRunnable action)
            throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            action.run();
            return;
        }
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<Throwable> failure = new AtomicReference<Throwable>();
        activity.runOnUiThread(new Runnable() {
            @Override public void run() {
                try {
                    action.run();
                } catch (Throwable error) {
                    failure.set(error);
                } finally {
                    latch.countDown();
                }
            }
        });
        if (!latch.await(15, TimeUnit.SECONDS)) {
            throw new IllegalStateException("Android main-thread dispatch timed out");
        }
        Throwable error = failure.get();
        if (error instanceof Exception) throw (Exception) error;
        if (error != null) throw new IllegalStateException("Android UI operation failed", error);
    }

    private static void require(boolean supported, String capability) {
        if (!supported) throw new UnsupportedOperationException(capability + " is disabled");
    }

    private static String success(Object value) {
        try {
            return new JSONObject()
                    .put("ok", true)
                    .put("value", value == null ? JSONObject.NULL : value)
                    .toString();
        } catch (JSONException impossible) {
            return "{\"ok\":false,\"error\":\"could not encode Android response\"}";
        }
    }

    private static String failure(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.length() == 0) message = error.getClass().getSimpleName();
        if (message.length() > 300) message = message.substring(0, 300);
        try {
            return new JSONObject().put("ok", false).put("error", message).toString();
        } catch (JSONException impossible) {
            return "{\"ok\":false,\"error\":\"Android operation failed\"}";
        }
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static final class PermissionWait {
        final String permission;
        final CountDownLatch latch = new CountDownLatch(1);

        PermissionWait(String permission) {
            this.permission = permission;
        }
    }
}
