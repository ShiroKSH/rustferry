import Foundation
import SwiftUI
import WidgetKit

private let ferryAppGroup = {{widget_app_group}}

private struct FerryWidgetAction {
    let label: String
    let destination: URL
}

private struct FerryWidgetEntry: TimelineEntry {
    let date: Date
    let title: String?
    let value: String?
    let caption: String?
    let progress: Double?
    let deepLink: URL?
    let contentText: String?
    let action: FerryWidgetAction?

    static let placeholder = FerryWidgetEntry(
        date: Date(),
        title: "RustFerry",
        value: "--",
        caption: nil,
        progress: nil,
        deepLink: nil,
        contentText: nil,
        action: nil
    )
}

private struct FerryWidgetProvider: TimelineProvider {
    func placeholder(in context: Context) -> FerryWidgetEntry {
        .placeholder
    }

    func getSnapshot(in context: Context, completion: @escaping (FerryWidgetEntry) -> Void) {
        completion(loadEntry())
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<FerryWidgetEntry>) -> Void) {
        completion(Timeline(
            entries: [loadEntry()],
            policy: .after(Date().addingTimeInterval(900))
        ))
    }

    private func loadEntry() -> FerryWidgetEntry {
        guard let encoded = UserDefaults(suiteName: ferryAppGroup)?
                .string(forKey: "rustferry.widget.snapshot"),
              let data = encoded.data(using: .utf8),
              let snapshot = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return .placeholder }

        let progress = (snapshot["progress"] as? NSNumber)?.doubleValue
        let deepLink = (snapshot["deep_link"] as? String).flatMap(URL.init(string:))
        let content = snapshot["content"] as? [String: Any]
        let contentText = content?["kind"] as? String == "text"
            ? content?["value"] as? String
            : nil
        let action: FerryWidgetAction?
        if let content,
           let kind = content["kind"] as? String,
           kind == "button" || kind == "link",
           let label = content["label"] as? String,
           let destination = (content["destination"] as? String).flatMap(URL.init(string:))
        {
            action = FerryWidgetAction(label: label, destination: destination)
        } else {
            action = nil
        }
        return FerryWidgetEntry(
            date: Date(),
            title: snapshot["title"] as? String,
            value: snapshot["value"] as? String,
            caption: snapshot["caption"] as? String,
            progress: progress,
            deepLink: deepLink,
            contentText: contentText,
            action: action
        )
    }
}

private struct FerryWidgetView: View {
    let entry: FerryWidgetEntry

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let title = entry.title { Text(title).font(.headline) }
            if let value = entry.value { Text(value).font(.title) }
            if let caption = entry.caption { Text(caption).font(.caption) }
            if let progress = entry.progress { ProgressView(value: progress) }
            if let contentText = entry.contentText { Text(contentText) }
            if let action = entry.action {
                Link(action.label, destination: action.destination)
            }
        }
        .widgetURL(entry.deepLink)
    }
}

@main
struct FerryWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "FerryWidget", provider: FerryWidgetProvider()) { entry in
            FerryWidgetView(entry: entry)
        }
        .configurationDisplayName("RustFerry Widget")
        .description("Displays the latest Rust-provided widget snapshot.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}
