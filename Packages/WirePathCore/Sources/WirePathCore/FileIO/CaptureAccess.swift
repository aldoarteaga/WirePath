import Foundation

/// Keeps a security-scoped URL accessible for the lifetime of the object.
///
/// Captures chosen by the user arrive as security-scoped URLs: from the macOS open panel or a Finder drop
/// in the sandboxed app, and from the iPadOS document picker or an open-in-place hand-off (Files, iCloud
/// Drive, USB storage, AirDrop, Share Sheet). Reading them requires `startAccessingSecurityScopedResource()`
/// while the bytes are mapped; the analysis and the Packet Inspector hold one of these while they read.
public final class SecurityScopedAccess: @unchecked Sendable {
    public let url: URL
    private let started: Bool

    public init(_ url: URL) {
        self.url = url
        started = url.startAccessingSecurityScopedResource()
    }

    deinit {
        if started { url.stopAccessingSecurityScopedResource() }
    }
}

/// Persistent references to captures outside the app container.
public enum CaptureBookmark {
    /// Creates a bookmark that restores access after relaunch (security-scoped on macOS when sandboxed).
    ///
    /// On iPadOS a plain bookmark of a document-picker or open-in-place URL already embeds its security
    /// scope; on macOS the sandbox requires `.withSecurityScope` (unsandboxed Debug builds fall back to a
    /// plain bookmark).
    public static func make(for url: URL) -> Data? {
        let access = SecurityScopedAccess(url)
        return withExtendedLifetime(access) {
            #if os(macOS)
            do {
                return try url.bookmarkData(options: [.withSecurityScope], includingResourceValuesForKeys: nil, relativeTo: nil)
            } catch {
                let nsError = error as NSError
                Log.pcap.error("Security-scoped bookmark unavailable (\(nsError.domain, privacy: .public) \(nsError.code, privacy: .public)); using a plain bookmark")
            }
            #endif
            return try? url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        }
    }

    /// Resolves a bookmark; returns nil when the file no longer exists.
    public static func resolve(_ data: Data) -> URL? {
        var stale = false
        #if os(macOS)
        if let url = try? URL(resolvingBookmarkData: data, options: [.withSecurityScope, .withoutUI], relativeTo: nil,
                              bookmarkDataIsStale: &stale) {
            return url
        }
        #endif
        return try? URL(resolvingBookmarkData: data, options: [.withoutUI], relativeTo: nil, bookmarkDataIsStale: &stale)
    }
}
