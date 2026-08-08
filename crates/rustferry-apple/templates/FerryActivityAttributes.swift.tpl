@available(iOS 16.1, *)
public struct FerryActivityAttributes: ActivityAttributes {
    public struct ContentState: Codable, Hashable {
        public var stateJSON: String
        public var title: String
        public var status: String
        public var progress: Double
        public var leadingText: String
        public var trailingText: String
        public var deepLink: String?

        public init(
            stateJSON: String,
            title: String,
            status: String,
            progress: Double,
            leadingText: String,
            trailingText: String,
            deepLink: String?
        ) {
            self.stateJSON = stateJSON
            self.title = title
            self.status = status
            self.progress = progress
            self.leadingText = leadingText
            self.trailingText = trailingText
            self.deepLink = deepLink
        }
    }

    public var attributesJSON: String

    public init(attributesJSON: String) {
        self.attributesJSON = attributesJSON
    }
}
