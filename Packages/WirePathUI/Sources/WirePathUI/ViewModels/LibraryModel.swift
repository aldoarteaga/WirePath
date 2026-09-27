import WirePathCore
#if os(macOS)
import AppKit
#endif
import Foundation
import Observation

/// One analysis in the sidebar: its manifest plus live state (progress, loaded results).
@Observable @MainActor
public final class AnalysisItem: Identifiable {
    public enum LoadState: Equatable { case idle, loading, loaded, failed(String) }

    public let id: UUID
    public var manifest: AnalysisManifest
    public var progress: AnalysisProgress?
    public var document: AnalysisDocument?
    public var loadState: LoadState = .idle
    public var isExpanded = false
    @ObservationIgnored var task: Task<Void, Never>?

    public init(manifest: AnalysisManifest) {
        self.id = manifest.id
        self.manifest = manifest
    }

    public var isAnalyzing: Bool { manifest.state == .analyzing }
    public var name: String { manifest.displayName }
}

/// Shared across windows: the analysis library, imports and running analyses.
@Observable @MainActor
public final class LibraryModel {
    public static let acceptedExtensions: Set<String> = ["pcap", "pcapng", "cap", "gz", "ntar", "dmp"]

    public let library: AnalysisLibrary
    public var items: [AnalysisItem] = []
    /// Most recently imported captures (Open Recent), resolved from bookmarks so they keep working after a
    /// capture is moved and, in the sandbox, after relaunch.
    public var recentCaptures: [URL] = []
    public var lastError: String?
    private let defaults: UserDefaults
    private static let recentsKey = "recentCaptureBookmarks"

    public init(library: AnalysisLibrary? = nil, defaults: UserDefaults = .standard) {
        self.library = library ?? AnalysisLibrary(rootURL: LaunchOptions.libraryRoot ?? AnalysisLibrary.defaultRootURL)
        self.defaults = defaults
        items = self.library.loadManifests().map(AnalysisItem.init)
        recentCaptures = (defaults.array(forKey: Self.recentsKey) as? [Data] ?? []).compactMap(CaptureBookmark.resolve)
    }

    public func item(_ id: UUID) -> AnalysisItem? { items.first { $0.id == id } }

    public static func isCapture(_ url: URL) -> Bool {
        let ext = url.pathExtension.lowercased()
        if ext == "gz" { return url.deletingPathExtension().pathExtension.lowercased().hasPrefix("pcap") || url.deletingPathExtension().pathExtension.lowercased() == "cap" }
        return acceptedExtensions.contains(ext)
    }

    /// Expands folders and keeps only capture files.
    public static func captureFiles(in urls: [URL]) -> [URL] {
        var result: [URL] = []
        for url in urls {
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory) else { continue }
            if isDirectory.boolValue {
                let enumerator = FileManager.default.enumerator(at: url, includingPropertiesForKeys: nil,
                                                                options: [.skipsHiddenFiles, .skipsPackageDescendants])
                while let file = enumerator?.nextObject() as? URL {
                    if isCapture(file) { result.append(file) }
                }
                continue
            }
            result.append(url)
        }
        return result
    }

    // MARK: Import & analysis

    /// Imports captures as new analyses and starts analysing them. Returns the new items.
    ///
    /// `urls` may be security-scoped (open panel, Finder drop, Files, iCloud Drive, USB storage) and may be
    /// folders; access to each is held while its captures are enumerated and bookmarked. Every analysis then
    /// reads its capture through the bookmark-resolved URL, which carries its own scope.
    @discardableResult
    public func importCaptures(_ urls: [URL]) -> [AnalysisItem] {
        var created: [AnalysisItem] = []
        for root in urls {
            let access = SecurityScopedAccess(root)
            withExtendedLifetime(access) {
                for url in Self.captureFiles(in: [root]) {
                    created.append(importCapture(url))
                }
            }
        }
        Log.ui.notice("Imported \(created.count) capture(s) from \(urls.count) location(s)")
        return created
    }

    /// Imports captures opened from outside any window (Finder, the Dock, the system Open Recent menu). The
    /// key window selects the first one (see `takeExternalSelection()`).
    public func openExternally(_ urls: [URL]) {
        if let first = importCaptures(urls).first { pendingExternalSelection = first.id }
    }

    /// The analysis opened from outside a window that no window has shown yet.
    public private(set) var pendingExternalSelection: UUID?

    public func takeExternalSelection() -> AnalysisItem? {
        defer { pendingExternalSelection = nil }
        return pendingExternalSelection.flatMap(item)
    }

    private func importCapture(_ url: URL) -> AnalysisItem {
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
        let bookmark = CaptureBookmark.make(for: url)
        let manifest = AnalysisManifest(displayName: url.lastPathComponent, originalFileName: url.lastPathComponent,
                                        originalPath: url.path, bookmark: bookmark,
                                        fileSize: size, state: .analyzing, engineVersion: AnalysisEngine.version)
        let item = AnalysisItem(manifest: manifest)
        items.insert(item, at: 0)
        addRecent(url, bookmark: bookmark)
        try? library.save(manifest)
        // Prefer the bookmark's URL: for a file inside an imported folder it carries its own security scope,
        // which outlives the folder's access above.
        startAnalysis(item, captureURL: bookmark.flatMap(CaptureBookmark.resolve) ?? url)
        return item
    }

    private func addRecent(_ url: URL, bookmark: Data?) {
        var entries = (defaults.array(forKey: Self.recentsKey) as? [Data] ?? [])
            .compactMap { data in CaptureBookmark.resolve(data).map { (url: $0, data: data) } }
            .filter { $0.url.standardizedFileURL != url.standardizedFileURL }
        if let bookmark { entries.insert((url, bookmark), at: 0) }
        entries = Array(entries.prefix(10))
        defaults.set(entries.map(\.data), forKey: Self.recentsKey)
        recentCaptures = entries.map(\.url)
        #if os(macOS)
        NSDocumentController.shared.noteNewRecentDocumentURL(url)
        #endif
    }

    public func clearRecentCaptures() {
        defaults.removeObject(forKey: Self.recentsKey)
        recentCaptures = []
        #if os(macOS)
        NSDocumentController.shared.clearRecentDocuments(nil)
        #endif
    }

    public func startAnalysis(_ item: AnalysisItem, captureURL: URL) {
        item.task?.cancel()
        item.manifest.state = .analyzing
        item.progress = AnalysisProgress(phase: .preparing, fraction: 0, packetsProcessed: 0)
        item.document = nil
        item.loadState = .idle
        let library = self.library
        let id = item.id
        library.clearResults(for: id)
        let artifacts = library.artifacts(for: id)
        let language = AnalysisEngine.resultLanguage
        item.task = Task {
            do {
                let output = try await AnalysisEngine.analyze(capture: captureURL, artifacts: artifacts) { progress in
                    Task { @MainActor in
                        guard item.isAnalyzing else { return }
                        item.progress = progress
                    }
                }
                try await Self.persist(output.result, id: id, library: library)
                item.manifest.state = .ready
                item.manifest.summary = AnalysisSummaryInfo(result: output.result)
                item.manifest.usesDecompressedCopy = output.usedDecompressedCopy
                item.manifest.engineVersion = AnalysisEngine.version
                item.manifest.language = language
                item.progress = nil
                try? library.save(item.manifest)
                item.document = AnalysisDocument(id: id, result: output.result, library: library, manifest: item.manifest)
                item.loadState = .loaded
            } catch {
                item.progress = nil
                if error is CancellationError || Task.isCancelled {
                    item.manifest.state = .cancelled
                } else {
                    item.manifest.state = .failed(error.localizedDescription)
                }
                library.clearResults(for: id)
                try? library.save(item.manifest)
            }
            item.task = nil
        }
    }

    nonisolated private static func persist(_ result: AnalysisResult, id: UUID, library: AnalysisLibrary) async throws {
        try library.saveResult(result, for: id)
    }

    public func cancelAnalysis(_ item: AnalysisItem) {
        item.task?.cancel()
    }

    public func reanalyze(_ item: AnalysisItem) {
        guard let url = library.originalURL(for: item.manifest) else {
            lastError = String(localized: "The capture “\(item.manifest.originalFileName)” can no longer be found at its original location.")
            return
        }
        startAnalysis(item, captureURL: url)
    }

    /// Loads persisted results for an analysis (off the main thread). Analyses saved by an older engine are
    /// re-analyzed when their capture is still reachable, since their results and index use an older format.
    /// So are analyses made in another language, whose findings and headlines would otherwise stay in it; when
    /// the capture is gone those are opened as saved.
    public func loadDocument(_ item: AnalysisItem) {
        guard item.manifest.state == .ready, item.document == nil, item.loadState != .loading else { return }
        if item.manifest.engineVersion == AnalysisEngine.version,
           (item.manifest.language ?? "en") != AnalysisEngine.resultLanguage,
           let url = library.originalURL(for: item.manifest) {
            Log.ui.notice("Re-analyzing a capture analyzed in another language")
            startAnalysis(item, captureURL: url)
            return
        }
        if item.manifest.engineVersion != AnalysisEngine.version {
            if let url = library.originalURL(for: item.manifest) {
                Log.ui.notice("Re-analyzing a capture saved by engine version \(item.manifest.engineVersion, privacy: .public)")
                startAnalysis(item, captureURL: url)
            } else {
                item.loadState = .failed(String(localized: "This analysis was made by an older version of WirePath and the capture “\(item.manifest.originalFileName)” can no longer be found. Import the capture again to analyze it."))
            }
            return
        }
        item.loadState = .loading
        let library = self.library
        let id = item.id
        Task {
            do {
                let result = try await Self.loadResult(id: id, library: library)
                item.document = AnalysisDocument(id: id, result: result, library: library, manifest: item.manifest)
                item.loadState = .loaded
                Log.pcap.info("Loaded saved analysis; capture reachable for packet details: \(library.captureURL(for: item.manifest) != nil, privacy: .public)")
            } catch {
                item.loadState = .failed(error.localizedDescription)
            }
        }
    }

    nonisolated private static func loadResult(id: UUID, library: AnalysisLibrary) async throws -> AnalysisResult {
        try library.loadResult(for: id)
    }

    // MARK: Library operations

    public func rename(_ item: AnalysisItem, to name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != item.manifest.displayName else { return }
        item.manifest.displayName = trimmed
        try? library.save(item.manifest)
    }

    public func duplicate(_ item: AnalysisItem) {
        guard !item.isAnalyzing else { return }
        let base = (item.name as NSString).deletingPathExtension
        let ext = (item.name as NSString).pathExtension
        let name = ext.isEmpty ? String(localized: "\(base) copy") : String(localized: "\(base) copy.\(ext)")
        do {
            let copy = try library.duplicate(item.manifest, newName: name)
            let newItem = AnalysisItem(manifest: copy)
            if let index = items.firstIndex(where: { $0.id == item.id }) { items.insert(newItem, at: index + 1) }
        } catch {
            lastError = String(localized: "Could not duplicate the analysis: \(error.localizedDescription)")
        }
    }

    public func delete(_ item: AnalysisItem, moveCaptureToTrash: Bool) {
        item.task?.cancel()
        if moveCaptureToTrash, let url = library.originalURL(for: item.manifest) {
            let access = SecurityScopedAccess(url)
            do {
                try withExtendedLifetime(access) { try FileManager.default.trashItem(at: url, resultingItemURL: nil) }
            } catch {
                lastError = String(localized: "The capture could not be moved to the Trash: \(error.localizedDescription)")
            }
        }
        try? library.delete(item.id)
        items.removeAll { $0.id == item.id }
    }

    #if os(macOS)
    public func showInFinder(_ item: AnalysisItem) {
        if let url = library.originalURL(for: item.manifest) {
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } else {
            lastError = String(localized: "The capture “\(item.manifest.originalFileName)” can no longer be found.")
        }
    }
    #endif
}
