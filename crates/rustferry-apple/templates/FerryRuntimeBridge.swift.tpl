import ActivityKit
import AVFoundation
import CoreLocation
import Darwin
import Foundation
import Network
import ObjectiveC.runtime
import Photos
import UIKit
import UserNotifications
import WidgetKit
{{activity_model_import}}

private let ferryStorageEnabled = {{storage_enabled}}
private let ferryNetworkEnabled = {{network_enabled}}
private let ferryNetworkProbeEnabled = {{network_probe_enabled}}
private let ferryHapticsEnabled = {{haptics_enabled}}
private let ferryNotificationsEnabled = {{notifications_enabled}}
private let ferryClipboardEnabled = {{clipboard_enabled}}
private let ferryShareEnabled = {{share_enabled}}
private let ferryPhotosEnabled = {{photos_enabled}}
private let ferryCameraEnabled = {{camera_enabled}}
private let ferryMicrophoneEnabled = {{microphone_enabled}}
private let ferryLocationEnabled = {{location_enabled}}
private let ferryWidgetAppGroup: String? = {{widget_app_group}}
private let ferryLiveActivityEnabled = {{live_activity_enabled}}
private let ferryDeepLinkSchemes: Set<String> = {{deep_link_schemes}}
private let ferryDeepLinkHosts: Set<String> = {{deep_link_hosts}}
private let ferryDeepLinkActions: Set<String> = {{deep_link_actions}}

public typealias FerryEventCallback = @convention(c) (UnsafePointer<CChar>?, Int) -> Void
public typealias FerryApplicationCallback = @convention(c) (
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Void

private struct BridgeFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

private func fail(_ message: String) -> BridgeFailure {
    BridgeFailure(message: message)
}

private func jsonObject(_ value: Any) throws -> Any {
    guard JSONSerialization.isValidJSONObject(value) else {
        throw fail("native bridge produced a non-JSON value")
    }
    return value
}

private func jsonString(_ value: Any) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    guard let value = String(data: data, encoding: .utf8) else {
        throw fail("native bridge could not encode UTF-8 JSON")
    }
    return value
}

private func parseJSON(_ value: String) throws -> Any {
    guard let data = value.data(using: .utf8) else {
        throw fail("native bridge input is not UTF-8")
    }
    return try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
}

private func dictionary(_ value: Any?, _ label: String = "request") throws -> [String: Any] {
    guard let value = value as? [String: Any] else {
        throw fail("\(label) must be a JSON object")
    }
    return value
}

private func string(_ value: Any?, _ label: String) throws -> String {
    guard let value = value as? String, !value.isEmpty else {
        throw fail("\(label) must be a non-empty string")
    }
    return value
}

private func optionalString(_ value: Any?) -> String? {
    value as? String
}

private func responseCString(ok: Bool, value: Any = NSNull(), error: String? = nil)
    -> UnsafeMutablePointer<CChar>?
{
    var response: [String: Any] = ["ok": ok, "value": value]
    if let error { response["error"] = error }
    guard JSONSerialization.isValidJSONObject(response),
          let data = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]),
          let text = String(data: data, encoding: .utf8)
    else {
        return strdup("{\"ok\":false,\"error\":\"native bridge response encoding failed\"}")
    }
    return strdup(text)
}

private func onMain<T>(_ work: @escaping () throws -> T) throws -> T {
    if Thread.isMainThread { return try work() }
    var outcome: Result<T, Error>?
    DispatchQueue.main.sync { outcome = Result { try work() } }
    guard let outcome else { throw fail("main-thread dispatch did not complete") }
    return try outcome.get()
}

private func awaitCallback<T>(
    timeout: TimeInterval = 15,
    start: (@escaping (Result<T, Error>) -> Void) -> Void
) throws -> T {
    let semaphore = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var outcome: Result<T, Error>?
    start { result in
        lock.lock()
        outcome = result
        lock.unlock()
        semaphore.signal()
    }
    guard semaphore.wait(timeout: .now() + timeout) == .success else {
        throw fail("native operation timed out")
    }
    lock.lock()
    let result = outcome
    lock.unlock()
    guard let result else { throw fail("native operation completed without a result") }
    return try result.get()
}

{{activity_attributes_declaration}}

private final class LocationPermissionWaiter: NSObject, CLLocationManagerDelegate {
    let manager = CLLocationManager()
    let completion: (String) -> Void
    private var completed = false

    init(completion: @escaping (String) -> Void) {
        self.completion = completion
        super.init()
        manager.delegate = self
    }

    func start() {
        manager.requestWhenInUseAuthorization()
        completeIfDetermined(manager.authorizationStatus)
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        completeIfDetermined(manager.authorizationStatus)
    }

    private func completeIfDetermined(_ status: CLAuthorizationStatus) {
        guard status != .notDetermined, !completed else { return }
        completed = true
        completion(FerryBridge.permissionStatus(status))
    }
}

@objc(FerryApplicationDelegate)
public final class FerryApplicationDelegate: UIResponder, UIApplicationDelegate {
    public func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        FerryBridge.shared.captureApplication(application)
        if let url = launchOptions?[.url] as? URL {
            _ = FerryBridge.shared.acceptDeepLink(url, initial: true)
        }
        return true
    }

    public func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        FerryBridge.shared.acceptDeepLink(url, initial: false)
    }
}

private final class FerryBridge: NSObject, UNUserNotificationCenterDelegate {
    static let shared = FerryBridge()

    private let lock = NSLock()
    private var eventCallback: FerryEventCallback?
    private var networkStatus: [String: Any] = [
        "state": "unknown",
        "transport": "unknown",
        "expensive": NSNull(),
        "constrained": NSNull(),
    ]
    private var networkMonitor: NWPathMonitor?
    private var locationWaiter: LocationPermissionWaiter?
    private var lifecycleObservers: [NSObjectProtocol] = []
    private weak var application: UIApplication?
    private var applicationDelegate: FerryApplicationDelegate?
    private var initialDeepLink: String?
    private var lastTheme: String?
    private var lastWindowSize: CGSize?

    var capabilities: [String] {
        var values = ["open-url", "open-settings", "app-info", "device-info", "theme"]
        if ferryStorageEnabled { values.append("storage") }
        if ferryNetworkEnabled { values.append("network-status") }
        if ferryNetworkProbeEnabled { values.append("network-probe") }
        if ferryHapticsEnabled { values.append("haptics") }
        if ferryClipboardEnabled { values += ["clipboard-read", "clipboard-write"] }
        if ferryShareEnabled { values.append("share") }
        if ferryNotificationsEnabled {
            values += [
                "notification-permission-status", "notification-permission-request",
                "notification-schedule", "notification-show-now", "notification-cancel",
                "notification-pending", "notification-delivered",
            ]
        }
        if ferryNetworkEnabled || ferryNotificationsEnabled || ferryPhotosEnabled
            || ferryCameraEnabled || ferryMicrophoneEnabled || ferryLocationEnabled
        {
            values += ["permission-status", "permission-request"]
        }
        if ferryWidgetAppGroup != nil { values.append("widget-update") }
        if ferryLiveActivityEnabled {
            values += [
                "live-activity-start", "live-activity-update", "live-activity-end",
                "live-activity-list",
            ]
        }
        if !ferryDeepLinkSchemes.isEmpty { values.append("deep-link-initial") }
        return values
    }

    func install(callback: FerryEventCallback?) -> Bool {
        guard installApplicationDelegateHook() else { return false }
        lock.lock()
        eventCallback = callback
        lock.unlock()
        if ferryNotificationsEnabled {
            UNUserNotificationCenter.current().delegate = self
        }
        if ferryNetworkEnabled, networkMonitor == nil {
            let monitor = NWPathMonitor()
            networkMonitor = monitor
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self else { return }
                let status = self.networkDictionary(path)
                self.lock.lock()
                self.networkStatus = status
                self.lock.unlock()
                self.emit(["type": "network_changed", "status": status])
            }
            monitor.start(queue: DispatchQueue(label: "org.rustferry.network-path"))
        }
        installLifecycleObservers()
        return true
    }

    func captureApplication(
        _ application: UIApplication,
        delegate: FerryApplicationDelegate? = nil
    ) {
        lock.lock()
        self.application = application
        if let delegate { applicationDelegate = delegate }
        lock.unlock()
    }

    private func capturedApplication() -> UIApplication? {
        lock.lock()
        defer { lock.unlock() }
        return application
    }

    func withApplication(
        context: UnsafeMutableRawPointer?,
        callback: FerryApplicationCallback
    ) -> Bool {
        let invoke = { () -> Bool in
            guard let application = self.capturedApplication() else { return false }
            callback(context, Unmanaged.passUnretained(application).toOpaque())
            return true
        }
        if Thread.isMainThread { return invoke() }
        return DispatchQueue.main.sync(execute: invoke)
    }

    func call(operation: String, input: Any) throws -> Any {
        switch operation {
        case "capabilities": return capabilities
        case "storage_directory": return try storageDirectory()
        case "network_current": return currentNetwork()
        case "network_probe": return try probeNetwork(try dictionary(input))
        case "haptic": return try haptic(input)
        case "clipboard_read_text": return try clipboardRead()
        case "clipboard_write_text": return try clipboardWrite(try string(input, "clipboard text"))
        case "share": return try share(try dictionary(input))
        case "open_url": return try openURL(try string(input, "URL"))
        case "open_settings": return try openSettings()
        case "app_info": return appInfo()
        case "device_info": return try deviceInfo()
        case "theme": return try theme()
        case "notification_permission_status": return try notificationPermissionStatus()
        case "notification_request_permission": return try notificationRequestPermission()
        case "notification_schedule": return try addNotification(try dictionary(input), immediate: false)
        case "notification_show_now": return try addNotification(try dictionary(input), immediate: true)
        case "notification_cancel": return cancelNotification(try string(input, "notification id"))
        case "notification_cancel_all": return cancelAllNotifications()
        case "notification_pending": return try pendingNotifications()
        case "notification_delivered": return try deliveredNotifications()
        case "permission_supported": return permissionSupported(try string(input, "permission"))
        case "permission_status": return try permissionStatus(try string(input, "permission"))
        case "permission_request": return try requestPermission(try dictionary(input))
        case "deep_link_initial": return currentInitialDeepLink()
        case "widget_update": return try updateWidget(try dictionary(input))
        case "live_activity_supported": return liveActivitySupported()
        case "live_activity_start": return try startLiveActivity(try dictionary(input))
        case "live_activity_update": return try updateLiveActivity(try dictionary(input))
        case "live_activity_end": return try endLiveActivity(try dictionary(input))
        case "live_activity_list": return try listLiveActivities()
        default: throw fail("unknown native operation \(operation)")
        }
    }

    private func emit(_ event: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8)
        else { return }
        lock.lock()
        let callback = eventCallback
        lock.unlock()
        json.utf8CString.withUnsafeBufferPointer { buffer in
            callback?(buffer.baseAddress, max(0, buffer.count - 1))
        }
    }

    func acceptDeepLink(_ url: URL, initial: Bool) -> Bool {
        guard isAllowedDeepLink(url) else { return false }
        let value = url.absoluteString
        lock.lock()
        if initial && initialDeepLink == nil { initialDeepLink = value }
        lock.unlock()
        emit(["type": "deep_link_received", "url": value])
        return true
    }

    private func isAllowedDeepLink(_ url: URL) -> Bool {
        let scheme = url.scheme?.lowercased() ?? ""
        guard ferryDeepLinkSchemes.contains(scheme) else { return false }
        if !ferryDeepLinkHosts.isEmpty {
            guard let host = url.host?.lowercased(), ferryDeepLinkHosts.contains(host) else {
                return false
            }
        }
        if !ferryDeepLinkActions.isEmpty {
            let action = url.pathComponents.first(where: { $0 != "/" && !$0.isEmpty })
            guard let action, ferryDeepLinkActions.contains(action) else { return false }
        }
        return true
    }

    private func currentInitialDeepLink() -> Any {
        lock.lock()
        defer { lock.unlock() }
        return initialDeepLink ?? NSNull()
    }

    private func installLifecycleObservers() {
        guard lifecycleObservers.isEmpty else { return }
        let center = NotificationCenter.default
        let events: [(Notification.Name, String)] = [
            (UIApplication.willEnterForegroundNotification, "foregrounded"),
            (UIApplication.didEnterBackgroundNotification, "backgrounded"),
            (UIApplication.didBecomeActiveNotification, "resumed"),
            (UIApplication.willResignActiveNotification, "paused"),
            (UIApplication.didReceiveMemoryWarningNotification, "low_memory"),
            (UIApplication.willTerminateNotification, "terminating"),
        ]
        for (name, type) in events {
            lifecycleObservers.append(center.addObserver(
                forName: name,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                self?.emit(["type": type])
                if type == "resumed" {
                    self?.emitThemeIfChanged()
                    self?.emitWindowSizeIfChanged()
                }
            })
        }
        for name in [
            UIDevice.orientationDidChangeNotification,
            UIWindow.didBecomeVisibleNotification,
            UIScreen.modeDidChangeNotification,
        ] {
            lifecycleObservers.append(center.addObserver(
                forName: name,
                object: nil,
                queue: nil
            ) { [weak self] _ in self?.emitWindowSizeIfChanged() })
        }
    }

    private func emitThemeIfChanged() {
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            let value = self.currentTheme()
            guard value != self.lastTheme else { return }
            self.lastTheme = value
            self.emit(["type": "theme_changed", "theme": value])
        }
    }

    private func emitWindowSizeIfChanged() {
        DispatchQueue.main.async { [weak self] in
            guard let self, let size = self.currentWindowSize(), size != self.lastWindowSize else {
                return
            }
            self.lastWindowSize = size
            self.emit([
                "type": "window_resized",
                "width": Double(size.width),
                "height": Double(size.height),
            ])
        }
    }

    private func currentTheme() -> String {
        let style = topViewController()?.traitCollection.userInterfaceStyle
        switch style {
        case .dark: return "dark"
        case .light: return "light"
        default: return "unknown"
        }
    }

    private func currentWindowSize() -> CGSize? {
        guard let application = capturedApplication() else { return nil }
        let scenes = application.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.flatMap(\.windows).first(where: { $0.isKeyWindow })?.bounds.size
            ?? scenes.flatMap(\.windows).first?.bounds.size
    }

    private func storageDirectory() throws -> String {
        guard ferryStorageEnabled else { throw fail("storage capability is disabled") }
        let root = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("FerryStore", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root.path
    }

    private func networkDictionary(_ path: NWPath) -> [String: Any] {
        let state: String
        switch path.status {
        case .satisfied: state = "online"
        case .requiresConnection: state = "local-only"
        case .unsatisfied: state = "offline"
        @unknown default: state = "unknown"
        }
        let transport: String
        if path.usesInterfaceType(.wifi) { transport = "wifi" }
        else if path.usesInterfaceType(.cellular) { transport = "cellular" }
        else if path.usesInterfaceType(.wiredEthernet) { transport = "ethernet" }
        else if path.usesInterfaceType(.other) { transport = "other" }
        else { transport = "unknown" }
        return [
            "state": state,
            "transport": transport,
            "expensive": path.isExpensive,
            "constrained": path.isConstrained,
        ]
    }

    private func currentNetwork() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        return networkStatus
    }

    private func probeNetwork(_ request: [String: Any]) throws -> [String: Any] {
        guard ferryNetworkProbeEnabled else { throw fail("network probing is disabled") }
        let value = try string(request["url"], "probe URL")
        guard let url = URL(string: value), ["http", "https"].contains(url.scheme?.lowercased() ?? "") else {
            throw fail("probe URL must use HTTP or HTTPS")
        }
        let timeoutMillis = (request["timeout_millis"] as? NSNumber)?.uint64Value ?? 0
        guard timeoutMillis > 0 else { throw fail("probe timeout must be greater than zero") }
        let timeout = TimeInterval(timeoutMillis) / 1_000
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: configuration)
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "HEAD"
        urlRequest.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let started = Date()
        let result: (Bool, Int?) = try awaitCallback(timeout: timeout + 1) { completion in
            let task = session.dataTask(with: urlRequest) { _, response, error in
                if let response = response as? HTTPURLResponse {
                    completion(.success((true, response.statusCode)))
                } else if error != nil {
                    completion(.success((false, nil)))
                } else {
                    completion(.success((false, nil)))
                }
            }
            task.resume()
        }
        session.invalidateAndCancel()
        let latency = UInt64(max(0, Date().timeIntervalSince(started) * 1_000))
        return [
            "reachable": result.0,
            "status_code": result.1 ?? NSNull(),
            "latency_millis": latency,
        ]
    }

    private func haptic(_ input: Any) throws -> NSNull {
        guard ferryHapticsEnabled else { throw fail("haptics capability is disabled") }
        try onMain {
            if let kind = input as? String, kind == "Selection" {
                let generator = UISelectionFeedbackGenerator()
                generator.prepare()
                generator.selectionChanged()
                return
            }
            let value = try dictionary(input, "haptic request")
            if let style = value["Impact"] as? String {
                let native: UIImpactFeedbackGenerator.FeedbackStyle
                switch style {
                case "light": native = .light
                case "medium": native = .medium
                case "heavy": native = .heavy
                case "rigid": native = .rigid
                case "soft": native = .soft
                default: throw fail("unsupported impact style")
                }
                let generator = UIImpactFeedbackGenerator(style: native)
                generator.prepare()
                generator.impactOccurred()
                return
            }
            if let kind = value["Notification"] as? String {
                let native: UINotificationFeedbackGenerator.FeedbackType
                switch kind {
                case "success": native = .success
                case "warning": native = .warning
                case "error": native = .error
                default: throw fail("unsupported notification haptic kind")
                }
                let generator = UINotificationFeedbackGenerator()
                generator.prepare()
                generator.notificationOccurred(native)
                return
            }
            throw fail("unsupported haptic request")
        }
        return NSNull()
    }

    private func clipboardRead() throws -> Any {
        guard ferryClipboardEnabled else { throw fail("clipboard capability is disabled") }
        return try onMain {
            if let value = UIPasteboard.general.string { return value as Any }
            return NSNull()
        }
    }

    private func clipboardWrite(_ text: String) throws -> NSNull {
        guard ferryClipboardEnabled else { throw fail("clipboard capability is disabled") }
        try onMain { UIPasteboard.general.string = text }
        return NSNull()
    }

    private func share(_ request: [String: Any]) throws -> NSNull {
        guard ferryShareEnabled else { throw fail("share capability is disabled") }
        let kind = try string(request["kind"], "share kind")
        let content = request["content"]
        var items: [Any] = []
        switch kind {
        case "text": items = [try string(content, "share text")]
        case "url":
            let value = try string(content, "share URL")
            guard let url = URL(string: value) else { throw fail("share URL is invalid") }
            items = [url]
        case "files":
            guard let paths = content as? [String], !paths.isEmpty else {
                throw fail("share files must contain at least one path")
            }
            for path in paths {
                guard FileManager.default.fileExists(atPath: path) else {
                    throw fail("shared file does not exist")
                }
                items.append(URL(fileURLWithPath: path))
            }
        default: throw fail("unsupported share kind")
        }
        try onMain {
            guard let presenter = self.topViewController() else {
                throw fail("no active view controller can present the share sheet")
            }
            let controller = UIActivityViewController(activityItems: items, applicationActivities: nil)
            if let popover = controller.popoverPresentationController {
                popover.sourceView = presenter.view
                popover.sourceRect = CGRect(
                    x: presenter.view.bounds.midX,
                    y: presenter.view.bounds.midY,
                    width: 1,
                    height: 1
                )
            }
            presenter.present(controller, animated: true)
        }
        return NSNull()
    }

    private func openURL(_ value: String) throws -> NSNull {
        guard let url = URL(string: value), let scheme = url.scheme?.lowercased() else {
            throw fail("URL must be absolute")
        }
        guard ["http", "https", "mailto", "tel", "sms"].contains(scheme) else {
            throw fail("URL scheme is not allowed")
        }
        guard let application = capturedApplication() else {
            throw fail("UIApplication is unavailable before application startup")
        }
        DispatchQueue.main.async { application.open(url, options: [:]) }
        return NSNull()
    }

    private func openSettings() throws -> NSNull {
        guard let url = URL(string: UIApplication.openSettingsURLString) else {
            throw fail("application settings URL is unavailable")
        }
        guard let application = capturedApplication() else {
            throw fail("UIApplication is unavailable before application startup")
        }
        DispatchQueue.main.async { application.open(url, options: [:]) }
        return NSNull()
    }

    private func appInfo() -> [String: Any] {
        let bundle = Bundle.main
        return [
            "display_name": bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? bundle.object(forInfoDictionaryKey: "CFBundleName") as? String ?? "",
            "identifier": bundle.bundleIdentifier ?? "",
            "version": bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "",
            "build": bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "",
        ]
    }

    private func deviceInfo() throws -> [String: Any] {
        try onMain {
            UIDevice.current.isBatteryMonitoringEnabled = false
            return [
                "platform": "ios",
                "os_version": UIDevice.current.systemVersion,
                "model": UIDevice.current.model,
                "locale": Locale.preferredLanguages.first ?? NSNull(),
            ]
        }
    }

    private func theme() throws -> String {
        try onMain { self.currentTheme() }
    }

    private func topViewController() -> UIViewController? {
        guard let application = capturedApplication() else { return nil }
        let scenes = application.connectedScenes.compactMap { $0 as? UIWindowScene }
        let window = scenes.flatMap(\.windows).first(where: { $0.isKeyWindow })
            ?? scenes.flatMap(\.windows).first
        var controller = window?.rootViewController
        while let presented = controller?.presentedViewController { controller = presented }
        if let navigation = controller as? UINavigationController {
            controller = navigation.visibleViewController
        } else if let tabs = controller as? UITabBarController {
            controller = tabs.selectedViewController
        }
        return controller
    }

    private func notificationPermissionStatus() throws -> String {
        guard ferryNotificationsEnabled else { throw fail("notifications capability is disabled") }
        let settings: UNNotificationSettings = try awaitCallback { completion in
            UNUserNotificationCenter.current().getNotificationSettings {
                completion(.success($0))
            }
        }
        return Self.permissionStatus(settings.authorizationStatus)
    }

    private func notificationRequestPermission() throws -> String {
        guard ferryNotificationsEnabled else { throw fail("notifications capability is disabled") }
        _ = try awaitCallback { completion in
            UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) {
                granted, error in
                if let error { completion(.failure(error)) }
                else { completion(.success(granted)) }
            }
        } as Bool
        return try notificationPermissionStatus()
    }

    private func addNotification(_ request: [String: Any], immediate: Bool) throws -> NSNull {
        guard ferryNotificationsEnabled else { throw fail("notifications capability is disabled") }
        let identifier = try string(request["id"], "notification id")
        let content = UNMutableNotificationContent()
        content.title = request["title"] as? String ?? ""
        content.body = request["body"] as? String ?? ""
        content.subtitle = request["subtitle"] as? String ?? ""
        if let badge = request["badge"] as? NSNumber { content.badge = badge }
        if let sound = request["sound"] as? [String: Any] {
            switch sound["mode"] as? String {
            case "default": content.sound = .default
            case "named":
                content.sound = UNNotificationSound(
                    named: UNNotificationSoundName(try string(sound["name"], "sound name"))
                )
            case "silent": content.sound = nil
            default: throw fail("unsupported notification sound mode")
            }
        }
        let originalJSON = try jsonString(request)
        var userInfo: [AnyHashable: Any] = ["rustferry.notification.json": originalJSON]
        if let deepLink = request["deep_link"] as? String {
            userInfo["rustferry.deep_link"] = deepLink
        }
        content.userInfo = userInfo

        if let actions = request["actions"] as? [[String: Any]], !actions.isEmpty {
            let categoryIdentifier = "rustferry.notification.\(identifier)"
            var nativeActions: [UNNotificationAction] = []
            for action in actions {
                var options: UNNotificationActionOptions = []
                if action["foreground"] as? Bool == true { options.insert(.foreground) }
                if action["authentication_required"] as? Bool == true {
                    options.insert(.authenticationRequired)
                }
                nativeActions.append(UNNotificationAction(
                    identifier: try string(action["id"], "notification action id"),
                    title: try string(action["title"], "notification action title"),
                    options: options
                ))
            }
            let center = UNUserNotificationCenter.current()
            let existing: Set<UNNotificationCategory> = try awaitCallback { completion in
                center.getNotificationCategories { completion(.success($0)) }
            }
            var categories = existing
            categories.update(with: UNNotificationCategory(
                identifier: categoryIdentifier,
                actions: nativeActions,
                intentIdentifiers: [],
                options: []
            ))
            center.setNotificationCategories(categories)
            content.categoryIdentifier = categoryIdentifier
        }

        let trigger: UNNotificationTrigger?
        if immediate {
            trigger = nil
        } else if let interval = request["repeat_interval"] as? [String: Any] {
            let seconds = ((interval["secs"] as? NSNumber)?.doubleValue ?? 0)
                + ((interval["nanos"] as? NSNumber)?.doubleValue ?? 0) / 1_000_000_000
            guard seconds >= 60 else { throw fail("repeating notifications require at least 60 seconds on iOS") }
            trigger = UNTimeIntervalNotificationTrigger(timeInterval: seconds, repeats: true)
        } else {
            guard let millis = (request["scheduled_at"] as? NSNumber)?.doubleValue else {
                throw fail("scheduled notification has no delivery time")
            }
            let date = Date(timeIntervalSince1970: millis / 1_000)
            guard date > Date() else { throw fail("scheduled notification time must be in the future") }
            let components = Calendar.current.dateComponents(
                [.year, .month, .day, .hour, .minute, .second],
                from: date
            )
            trigger = UNCalendarNotificationTrigger(dateMatching: components, repeats: false)
        }
        let native = UNNotificationRequest(identifier: identifier, content: content, trigger: trigger)
        try awaitCallback { completion in
            UNUserNotificationCenter.current().add(native) { error in
                if let error { completion(.failure(error)) }
                else { completion(.success(())) }
            }
        } as Void
        return NSNull()
    }

    private func cancelNotification(_ identifier: String) -> NSNull {
        UNUserNotificationCenter.current().removePendingNotificationRequests(
            withIdentifiers: [identifier]
        )
        return NSNull()
    }

    private func cancelAllNotifications() -> NSNull {
        UNUserNotificationCenter.current().removeAllPendingNotificationRequests()
        return NSNull()
    }

    private func pendingNotifications() throws -> [[String: Any]] {
        let requests: [UNNotificationRequest] = try awaitCallback { completion in
            UNUserNotificationCenter.current().getPendingNotificationRequests {
                completion(.success($0))
            }
        }
        return requests.compactMap { request in
            guard let model = notificationModel(request.content) else { return nil }
            return ["notification": model]
        }
    }

    private func deliveredNotifications() throws -> [[String: Any]] {
        let values: [UNNotification] = try awaitCallback { completion in
            UNUserNotificationCenter.current().getDeliveredNotifications {
                completion(.success($0))
            }
        }
        return values.compactMap { delivered in
            guard let model = notificationModel(delivered.request.content) else { return nil }
            return [
                "notification": model,
                "delivered_at": Int64(delivered.date.timeIntervalSince1970 * 1_000),
            ]
        }
    }

    private func notificationModel(_ content: UNNotificationContent) -> [String: Any]? {
        guard let json = content.userInfo["rustferry.notification.json"] as? String,
              let value = try? parseJSON(json) as? [String: Any]
        else { return nil }
        return value
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let content = response.notification.request.content
        let model = notificationModel(content)
        let action = response.actionIdentifier == UNNotificationDefaultActionIdentifier
            ? nil : response.actionIdentifier
        emit([
            "type": "notification_opened",
            "id": response.notification.request.identifier,
            "action": action ?? NSNull(),
            "payload": model?["payload"] ?? NSNull(),
            "deep_link": model?["deep_link"] ?? NSNull(),
        ])
        completionHandler()
    }

    private func permissionSupported(_ permission: String) -> Bool {
        switch permission {
        case "notifications": return ferryNotificationsEnabled
        case "network-state": return ferryNetworkEnabled
        case "photos": return ferryPhotosEnabled
        case "camera": return ferryCameraEnabled
        case "microphone": return ferryMicrophoneEnabled
        case "location-when-in-use": return ferryLocationEnabled
        case "local-network": return false
        default: return false
        }
    }

    private func permissionStatus(_ permission: String) throws -> String {
        guard permissionSupported(permission) else { return "unsupported" }
        switch permission {
        case "notifications": return try notificationPermissionStatus()
        case "network-state": return "granted"
        case "photos": return Self.permissionStatus(PHPhotoLibrary.authorizationStatus(for: .readWrite))
        case "camera": return Self.permissionStatus(AVCaptureDevice.authorizationStatus(for: .video))
        case "microphone": return Self.permissionStatus(AVAudioSession.sharedInstance().recordPermission)
        case "location-when-in-use":
            return try onMain { Self.permissionStatus(CLLocationManager().authorizationStatus) }
        default: return "unsupported"
        }
    }

    private func requestPermission(_ request: [String: Any]) throws -> String {
        let permission = try string(request["permission"], "permission")
        guard permissionSupported(permission) else { return "unsupported" }
        switch permission {
        case "notifications": return try notificationRequestPermission()
        case "network-state": return "granted"
        case "photos":
            let status: PHAuthorizationStatus = try awaitCallback(timeout: 60) { completion in
                PHPhotoLibrary.requestAuthorization(for: .readWrite) { completion(.success($0)) }
            }
            return Self.permissionStatus(status)
        case "camera":
            _ = try awaitCallback(timeout: 60) { completion in
                AVCaptureDevice.requestAccess(for: .video) { completion(.success($0)) }
            } as Bool
            return Self.permissionStatus(AVCaptureDevice.authorizationStatus(for: .video))
        case "microphone":
            _ = try awaitCallback(timeout: 60) { completion in
                AVAudioSession.sharedInstance().requestRecordPermission {
                    completion(.success($0))
                }
            } as Bool
            return Self.permissionStatus(AVAudioSession.sharedInstance().recordPermission)
        case "location-when-in-use":
            return try awaitCallback(timeout: 60) { completion in
                DispatchQueue.main.async {
                    let waiter = LocationPermissionWaiter { status in
                        self.locationWaiter = nil
                        completion(.success(status))
                    }
                    self.locationWaiter = waiter
                    waiter.start()
                }
            }
        default: return "unsupported"
        }
    }

    static func permissionStatus(_ status: UNAuthorizationStatus) -> String {
        switch status {
        case .authorized, .provisional, .ephemeral: return "granted"
        case .denied: return "denied"
        case .notDetermined: return "not-determined"
        @unknown default: return "unsupported"
        }
    }

    static func permissionStatus(_ status: PHAuthorizationStatus) -> String {
        switch status {
        case .authorized, .limited: return "granted"
        case .denied: return "permanently-denied"
        case .restricted: return "restricted"
        case .notDetermined: return "not-determined"
        @unknown default: return "unsupported"
        }
    }

    static func permissionStatus(_ status: AVAuthorizationStatus) -> String {
        switch status {
        case .authorized: return "granted"
        case .denied: return "permanently-denied"
        case .restricted: return "restricted"
        case .notDetermined: return "not-determined"
        @unknown default: return "unsupported"
        }
    }

    static func permissionStatus(_ status: AVAudioSession.RecordPermission) -> String {
        switch status {
        case .granted: return "granted"
        case .denied: return "permanently-denied"
        case .undetermined: return "not-determined"
        @unknown default: return "unsupported"
        }
    }

    static func permissionStatus(_ status: CLAuthorizationStatus) -> String {
        switch status {
        case .authorizedAlways, .authorizedWhenInUse: return "granted"
        case .denied: return "permanently-denied"
        case .restricted: return "restricted"
        case .notDetermined: return "not-determined"
        @unknown default: return "unsupported"
        }
    }

    private func updateWidget(_ request: [String: Any]) throws -> NSNull {
        guard let group = ferryWidgetAppGroup,
              let defaults = UserDefaults(suiteName: group)
        else { throw fail("widget app-group storage is unavailable") }
        let identifier = try string(request["id"], "widget id")
        let snapshot = try dictionary(request["snapshot"], "widget snapshot")
        try validateWidgetSnapshot(snapshot)
        let encoded = try jsonString(snapshot)
        defaults.set(encoded, forKey: "rustferry.widget.snapshot")
        defaults.set(encoded, forKey: "rustferry.widget.\(identifier).snapshot")
        defaults.set(identifier, forKey: "rustferry.widget.id")
        setWidgetValue(snapshot["title"], key: "rustferry.widget.title", defaults: defaults)
        setWidgetValue(snapshot["value"], key: "rustferry.widget.value", defaults: defaults)
        setWidgetValue(snapshot["caption"], key: "rustferry.widget.caption", defaults: defaults)
        setWidgetValue(snapshot["progress"], key: "rustferry.widget.progress", defaults: defaults)
        setWidgetValue(snapshot["deep_link"], key: "rustferry.widget.deep_link", defaults: defaults)
        defaults.synchronize()
        WidgetCenter.shared.reloadAllTimelines()
        return NSNull()
    }

    private func validateWidgetSnapshot(_ snapshot: [String: Any]) throws {
        if let progress = snapshot["progress"] as? NSNumber,
           !(0.0...1.0).contains(progress.doubleValue)
        {
            throw fail("widget progress must be between 0 and 1")
        }
        if let value = snapshot["deep_link"] as? String {
            try validateWidgetDeepLink(value, label: "widget deep link")
        }
        guard let rawContent = snapshot["content"], !(rawContent is NSNull) else { return }
        let content = try dictionary(rawContent, "widget content")
        let kind = try string(content["kind"], "widget content kind")
        if kind == "text" {
            _ = try string(content["value"], "widget text")
            return
        }
        guard kind == "button" || kind == "link" else {
            throw fail("widget content kind \(kind) is unsupported by the generated iOS renderer")
        }
        _ = try string(content["label"], "widget action label")
        try validateWidgetDeepLink(
            try string(content["destination"], "widget action destination"),
            label: "widget action destination"
        )
    }

    private func validateWidgetDeepLink(_ value: String, label: String) throws {
        guard let url = URL(string: value), url.scheme != nil, isAllowedDeepLink(url) else {
            throw fail("\(label) is not allowed by the configured deep-link policy")
        }
    }

    private func setWidgetValue(_ value: Any?, key: String, defaults: UserDefaults) {
        if let value, !(value is NSNull) { defaults.set(value, forKey: key) }
        else { defaults.removeObject(forKey: key) }
    }

    private func liveActivitySupported() -> Bool {
        guard ferryLiveActivityEnabled else { return false }
        if #available(iOS 16.1, *) {
            return ActivityAuthorizationInfo().areActivitiesEnabled
        }
        return false
    }

    @available(iOS 16.1, *)
    private func activityState(_ state: Any, snapshot: [String: Any]?) throws
        -> FerryActivityAttributes.ContentState
    {
        FerryActivityAttributes.ContentState(
            stateJSON: try jsonString(state),
            title: snapshot?["title"] as? String ?? "",
            status: snapshot?["status"] as? String ?? "",
            progress: (snapshot?["progress"] as? NSNumber)?.doubleValue ?? 0,
            leadingText: snapshot?["leading_text"] as? String ?? "",
            trailingText: snapshot?["trailing_text"] as? String ?? "",
            deepLink: snapshot?["deep_link"] as? String
        )
    }

    private func startLiveActivity(_ request: [String: Any]) throws -> String {
        guard liveActivitySupported() else { throw fail("Live Activities are unavailable") }
        guard #available(iOS 16.1, *) else { throw fail("Live Activities require iOS 16.1") }
        let attributesValue = request["attributes"] ?? NSNull()
        let stateValue = request["state"] ?? NSNull()
        let snapshot = request["snapshot"] as? [String: Any]
        let attributes = FerryActivityAttributes(attributesJSON: try jsonString(attributesValue))
        let state = try activityState(stateValue, snapshot: snapshot)
        if #available(iOS 16.2, *) {
            let content = ActivityContent(state: state, staleDate: nil)
            return try Activity.request(attributes: attributes, content: content).id
        }
        return try Activity.request(attributes: attributes, contentState: state).id
    }

    private func updateLiveActivity(_ request: [String: Any]) throws -> NSNull {
        guard liveActivitySupported() else { throw fail("Live Activities are unavailable") }
        guard #available(iOS 16.1, *) else { throw fail("Live Activities require iOS 16.1") }
        let identifier = try string(request["id"], "activity id")
        guard let activity = Activity<FerryActivityAttributes>.activities.first(where: {
            $0.id == identifier
        }) else { throw fail("Live Activity was not found") }
        let state = try activityState(
            request["state"] ?? NSNull(),
            snapshot: request["snapshot"] as? [String: Any]
        )
        try awaitCallback { completion in
            Task.detached {
                if #available(iOS 16.2, *) {
                    await activity.update(ActivityContent(state: state, staleDate: nil))
                } else {
                    await activity.update(using: state)
                }
                completion(.success(()))
            }
        } as Void
        return NSNull()
    }

    private func endLiveActivity(_ request: [String: Any]) throws -> NSNull {
        guard liveActivitySupported() else { throw fail("Live Activities are unavailable") }
        guard #available(iOS 16.1, *) else { throw fail("Live Activities require iOS 16.1") }
        let identifier = try string(request["id"], "activity id")
        guard let activity = Activity<FerryActivityAttributes>.activities.first(where: {
            $0.id == identifier
        }) else { throw fail("Live Activity was not found") }
        let state = try activityState(
            request["state"] ?? NSNull(),
            snapshot: request["snapshot"] as? [String: Any]
        )
        try awaitCallback { completion in
            Task.detached {
                if #available(iOS 16.2, *) {
                    await activity.end(
                        ActivityContent(state: state, staleDate: nil),
                        dismissalPolicy: .immediate
                    )
                } else {
                    await activity.end(using: state, dismissalPolicy: .immediate)
                }
                completion(.success(()))
            }
        } as Void
        return NSNull()
    }

    private func listLiveActivities() throws -> [[String: Any]] {
        guard liveActivitySupported() else { throw fail("Live Activities are unavailable") }
        guard #available(iOS 16.1, *) else { throw fail("Live Activities require iOS 16.1") }
        return Activity<FerryActivityAttributes>.activities.compactMap { activity in
            guard let attributes = try? parseJSON(activity.attributes.attributesJSON),
                  let current = self.currentActivityState(activity),
                  let state = try? parseJSON(current.stateJSON)
            else { return nil }
            let snapshot: [String: Any] = [
                "title": current.title,
                "status": current.status,
                "progress": current.progress,
                "leading_text": current.leadingText,
                "trailing_text": current.trailingText,
                "deep_link": current.deepLink ?? NSNull(),
            ]
            return [
                "id": activity.id,
                "attributes": attributes,
                "state": state,
                "snapshot": snapshot,
            ]
        }
    }

    @available(iOS 16.1, *)
    private func currentActivityState(_ activity: Activity<FerryActivityAttributes>)
        -> FerryActivityAttributes.ContentState?
    {
        if #available(iOS 16.2, *) { return activity.content.state }
        return activity.contentState
    }
}

private typealias FerryUIApplicationInit = @convention(c) (
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer?
private var ferryOriginalUIApplicationInit: FerryUIApplicationInit?
private var ferryApplicationDelegateHookInstalled = false

/// Installs before `UIApplicationMain`; never asks UIKit to create its application singleton.
private func installApplicationDelegateHook() -> Bool {
    guard Thread.isMainThread else { return false }
    if ferryApplicationDelegateHookInstalled { return true }
    let originalSelector = NSSelectorFromString("init")
    guard let method = class_getInstanceMethod(UIApplication.self, originalSelector) else {
        return false
    }
    ferryOriginalUIApplicationInit = unsafeBitCast(
        method_getImplementation(method),
        to: FerryUIApplicationInit.self
    )
    let replacement: FerryUIApplicationInit = ferryBridgeUIApplicationInit
    method_setImplementation(method, unsafeBitCast(replacement, to: IMP.self))
    ferryApplicationDelegateHookInstalled = true
    return true
}

/// Exact Objective-C `-[UIApplication init]` ABI; preserves its retained return convention.
@_cdecl("ferry_bridge_init")
public func ferryBridgeUIApplicationInit(
    _ object: UnsafeMutableRawPointer?,
    _ selector: UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer? {
    guard let original = ferryOriginalUIApplicationInit,
          let initialized = original(object, selector)
    else { return nil }
    let value = Unmanaged<AnyObject>.fromOpaque(initialized).takeRetainedValue()
    guard let application = value as? UIApplication else {
        return Unmanaged.passRetained(value).toOpaque()
    }
    let delegate = FerryApplicationDelegate()
    FerryBridge.shared.captureApplication(application, delegate: delegate)
    application.delegate = delegate
    return Unmanaged.passRetained(application).toOpaque()
}

@_cdecl("ferry_bridge_call")
public func ferryBridgeCall(
    _ operationPointer: UnsafePointer<CChar>?,
    _ inputPointer: UnsafePointer<CChar>?,
    _ outputLength: UnsafeMutablePointer<Int>?
) -> UnsafeMutablePointer<CChar>? {
    let finish: (UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? = { pointer in
        outputLength?.pointee = pointer.map { Int(strlen($0)) } ?? 0
        return pointer
    }
    guard let operationPointer, let inputPointer else {
        return finish(responseCString(ok: false, error: "native bridge received a null request"))
    }
    let operation = String(cString: operationPointer)
    let input = String(cString: inputPointer)
    do {
        let value = try FerryBridge.shared.call(operation: operation, input: parseJSON(input))
        return finish(responseCString(ok: true, value: try jsonObject(value)))
    } catch {
        return finish(responseCString(ok: false, error: error.localizedDescription))
    }
}

@_cdecl("ferry_bridge_free")
public func ferryBridgeFree(_ pointer: UnsafeMutablePointer<CChar>?) {
    Darwin.free(pointer)
}

@_cdecl("ferry_bridge_install")
public func ferryBridgeInstall(_ callback: FerryEventCallback?) -> Int32 {
    FerryBridge.shared.install(callback: callback) ? 1 : 0
}

@_cdecl("ferry_bridge_with_application")
public func ferryBridgeWithApplication(
    _ context: UnsafeMutableRawPointer?,
    _ callback: FerryApplicationCallback?
) -> Int32 {
    guard let callback else { return 0 }
    return FerryBridge.shared.withApplication(context: context, callback: callback) ? 1 : 0
}
