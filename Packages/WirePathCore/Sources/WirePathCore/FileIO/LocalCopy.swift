import Foundation

/// Decides when a capture must be copied into the analysis folder before it is memory-mapped, and copies it.
///
/// A mapped file that disappears (a USB drive unplugged, a network share dropped, an iCloud file evicted) makes the
/// next page fault raise SIGBUS, which cannot be recovered from. Reading with `read(2)` instead fails with an error,
/// so captures on such volumes are copied in chunks first — the copy fails cleanly if the volume goes away.
public enum LocalCopy {
    /// When the engine copies a capture before analysing it.
    public enum Policy: Sendable {
        /// Copy captures on removable/external, network or iCloud storage (the default).
        case automatic
        case always
        case never
    }

    /// True for files on removable/external, network or iCloud storage.
    public static func isNeeded(for url: URL) -> Bool {
        let access = SecurityScopedAccess(url)
        return withExtendedLifetime(access) {
            let keys: Set<URLResourceKey> = [.volumeIsLocalKey, .volumeIsInternalKey, .volumeIsRemovableKey,
                                             .volumeIsEjectableKey, .isUbiquitousItemKey]
            guard let values = try? url.resourceValues(forKeys: keys) else { return false }
            if values.isUbiquitousItem == true { return true }
            if values.volumeIsLocal == false { return true }
            if values.volumeIsRemovable == true || values.volumeIsEjectable == true { return true }
            return values.volumeIsInternal == false
        }
    }

    /// Whether `destination`'s volume has room for `bytes` plus a margin.
    public static func hasSpace(for bytes: Int64, at destination: URL) -> Bool {
        let directory = destination.deletingLastPathComponent()
        guard let values = try? directory.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]),
              let available = values.volumeAvailableCapacityForImportantUsage else { return true }
        return available > bytes + 512 * 1024 * 1024
    }

    /// Copies `source` to `destination` in 4 MiB chunks, reporting progress (0…1) and honouring cancellation.
    public static func copy(_ source: URL, to destination: URL, progress: (Double) -> Void = { _ in },
                            isCancelled: () -> Bool = { false }) throws {
        let access = SecurityScopedAccess(source)
        try withExtendedLifetime(access) {
            let input = try FileHandle(forReadingFrom: source)
            defer { try? input.close() }
            let total = (try? source.resourceValues(forKeys: [.fileSizeKey]).fileSize).map(Int64.init) ?? 0
            FileManager.default.createFile(atPath: destination.path, contents: nil)
            let output = try FileHandle(forWritingTo: destination)
            defer { try? output.close() }
            var copied: Int64 = 0
            while let chunk = try input.read(upToCount: 4 << 20), !chunk.isEmpty {
                if isCancelled() { throw CancellationError() }
                try output.write(contentsOf: chunk)
                copied += Int64(chunk.count)
                if total > 0 { progress(min(1, Double(copied) / Double(total))) }
            }
        }
    }
}
