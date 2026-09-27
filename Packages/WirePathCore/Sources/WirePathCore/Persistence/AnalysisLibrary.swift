import Foundation

public enum AnalysisState: Codable, Sendable, Equatable {
    case analyzing
    case ready
    case failed(String)
    case cancelled
}

/// Metadata for one analysis, small enough to load every analysis at launch for the sidebar.
public struct AnalysisManifest: Codable, Sendable, Identifiable, Equatable {
    public var id: UUID
    public var displayName: String
    public var originalFileName: String
    public var originalPath: String
    /// Bookmark to the original capture so it can be found after being moved or renamed.
    public var bookmark: Data?
    public var fileSize: Int64
    public var importedAt: Date
    public var state: AnalysisState
    public var summary: AnalysisSummaryInfo?
    public var engineVersion: Int
    /// Language of the engine-written text in the saved results (`AnalysisEngine.resultLanguage` when analyzed);
    /// nil in analyses saved before this was recorded, which were English.
    public var language: String?
    /// True for gzip captures, which are expanded into the analysis folder for random access.
    public var usesDecompressedCopy: Bool

    public init(id: UUID = UUID(), displayName: String, originalFileName: String, originalPath: String,
                bookmark: Data?, fileSize: Int64, importedAt: Date = Date(), state: AnalysisState,
                summary: AnalysisSummaryInfo? = nil, engineVersion: Int, language: String? = nil,
                usesDecompressedCopy: Bool = false) {
        self.id = id
        self.displayName = displayName
        self.originalFileName = originalFileName
        self.originalPath = originalPath
        self.bookmark = bookmark
        self.fileSize = fileSize
        self.importedAt = importedAt
        self.state = state
        self.summary = summary
        self.engineVersion = engineVersion
        self.language = language
        self.usesDecompressedCopy = usesDecompressedCopy
    }
}

/// Files stored per analysis inside `<root>/<uuid>/`.
public enum AnalysisArtifact: String, Sendable, CaseIterable {
    case manifest = "analysis.json"
    case result = "result.wpresult"
    case packetIndex = "packets.idx"
    case addressTable = "addresses.json"
    case sipTexts = "sip-messages.json"
    case flows = "flows.json"
    case decompressedCapture = "capture.pcap"
}

/// On-disk library of analyses (Application Support/WirePath/Analyses).
///
/// Only derived data is stored: metadata, results and a compact packet index. The original capture
/// stays where the user keeps it and is referenced through a bookmark; gzip captures are the one
/// exception because DEFLATE streams cannot be read at random offsets.
public final class AnalysisLibrary: Sendable {
    public let rootURL: URL

    public static var defaultRootURL: URL {
        URL.applicationSupportDirectory.appendingPathComponent("WirePath", isDirectory: true).appendingPathComponent("Analyses", isDirectory: true)
    }

    public init(rootURL: URL = AnalysisLibrary.defaultRootURL) {
        self.rootURL = rootURL
        try? FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: true)
    }

    public func directory(for id: UUID) -> URL {
        rootURL.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    public func url(_ artifact: AnalysisArtifact, for id: UUID) -> URL {
        directory(for: id).appendingPathComponent(artifact.rawValue)
    }

    /// Where the analysis engine writes the derived files of an analysis.
    public func artifacts(for id: UUID) -> AnalysisArtifactLocations {
        AnalysisArtifactLocations(packetIndex: url(.packetIndex, for: id), addressTable: url(.addressTable, for: id),
                                  sipTexts: url(.sipTexts, for: id), flows: url(.flows, for: id),
                                  decompressedCapture: url(.decompressedCapture, for: id))
    }

    /// Flows of an analysis (read on demand: large captures can hold many).
    public func loadFlows(for id: UUID) throws -> [FlowRecord] {
        try JSONDecoder().decode([FlowRecord].self, from: Data(contentsOf: url(.flows, for: id)))
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    // MARK: Manifests

    /// All analyses, newest first. Analyses interrupted while running are reported as cancelled.
    public func loadManifests() -> [AnalysisManifest] {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(at: rootURL, includingPropertiesForKeys: nil) else { return [] }
        var manifests: [AnalysisManifest] = []
        for entry in entries {
            let file = entry.appendingPathComponent(AnalysisArtifact.manifest.rawValue)
            guard let data = try? Data(contentsOf: file),
                  var manifest = try? Self.decoder.decode(AnalysisManifest.self, from: data),
                  let folderID = UUID(uuidString: entry.lastPathComponent) else { continue }
            // The folder name is authoritative: a damaged manifest must not point delete/duplicate at another analysis.
            manifest.id = folderID
            if manifest.state == .analyzing { manifest.state = .cancelled }
            manifests.append(manifest)
        }
        return manifests.sorted { $0.importedAt > $1.importedAt }
    }

    public func save(_ manifest: AnalysisManifest) throws {
        try FileManager.default.createDirectory(at: directory(for: manifest.id), withIntermediateDirectories: true)
        try Self.encoder.encode(manifest).write(to: url(.manifest, for: manifest.id), options: .atomic)
    }

    // MARK: Results

    /// Saves the result in chunks (`ResultArchive`), so memory stays near the size of the result itself.
    public func saveResult(_ result: AnalysisResult, for id: UUID) throws {
        try ResultArchive.write(result, to: url(.result, for: id), encoder: Self.encoder)
    }

    public func loadResult(for id: UUID) throws -> AnalysisResult {
        let result = try ResultArchive.read(from: url(.result, for: id), decoder: Self.decoder)
        guard result.schemaVersion == AnalysisResult.schemaVersion else {
            throw CocoaError(.fileReadCorruptFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "The saved results were created by an older version of WirePath. Re-analyze the capture.", bundle: CoreLocalization.bundle)])
        }
        guard result.isStructurallyValid else {
            throw CocoaError(.fileReadCorruptFile, userInfo: [NSLocalizedDescriptionKey: String(localized: "The saved results are damaged. Re-analyze the capture.", bundle: CoreLocalization.bundle)])
        }
        return result
    }

    public func hasResult(for id: UUID) -> Bool {
        FileManager.default.fileExists(atPath: url(.result, for: id).path)
    }

    /// Removes derived files (before a re-analysis), keeping the manifest.
    public func clearResults(for id: UUID) {
        for artifact in AnalysisArtifact.allCases where artifact != .manifest {
            try? FileManager.default.removeItem(at: url(artifact, for: id))
        }
    }

    // MARK: Library operations

    public func delete(_ id: UUID) throws {
        try FileManager.default.removeItem(at: directory(for: id))
    }

    /// Copies an analysis folder under a new identifier and name.
    public func duplicate(_ manifest: AnalysisManifest, newName: String) throws -> AnalysisManifest {
        var copy = manifest
        copy.id = UUID()
        copy.displayName = newName
        copy.importedAt = Date()
        try FileManager.default.copyItem(at: directory(for: manifest.id), to: directory(for: copy.id))
        try save(copy)
        return copy
    }

    /// Location of the capture to read packets from: the expanded copy for gzip captures, otherwise the
    /// original (resolving the bookmark if the file moved). Nil when the capture is no longer available.
    public func captureURL(for manifest: AnalysisManifest) -> URL? {
        if manifest.usesDecompressedCopy {
            let copy = url(.decompressedCapture, for: manifest.id)
            return FileManager.default.fileExists(atPath: copy.path) ? copy : nil
        }
        return originalURL(for: manifest)
    }

    /// The original capture, preferring the bookmark (which follows moves and renames and carries the
    /// security scope needed to read it again after relaunch) over the path recorded at import.
    public func originalURL(for manifest: AnalysisManifest) -> URL? {
        if let bookmark = manifest.bookmark, let resolved = CaptureBookmark.resolve(bookmark),
           Self.exists(resolved) {
            return resolved
        }
        let path = URL(fileURLWithPath: manifest.originalPath)
        return Self.exists(path) ? path : nil
    }

    public static func bookmark(for url: URL) -> Data? {
        CaptureBookmark.make(for: url)
    }

    private static func exists(_ url: URL) -> Bool {
        let access = SecurityScopedAccess(url)
        return withExtendedLifetime(access) { FileManager.default.isReadableFile(atPath: url.path) }
    }
}
