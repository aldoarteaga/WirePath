import Foundation

/// File layout: 16-byte header ("WPIDX004", record count UInt64) followed by fixed-size records.
/// The magic changes whenever `PacketIndexRecord`'s layout does, so stale index files are rejected.
enum PacketIndexFormat {
    static let magic: UInt64 = 0x3430_3058_4449_5057  // "WPIDX004" little-endian
    static let headerSize = 16
    static var recordSize: Int { MemoryLayout<PacketIndexRecord>.stride }
}

/// Appends index records to disk in large sequential writes.
final class PacketIndexWriter {
    private let handle: FileHandle
    private var buffer: [PacketIndexRecord] = []
    private(set) var count = 0
    let url: URL

    init(url: URL) throws {
        self.url = url
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try FileHandle(forWritingTo: url)
        var header = [PacketIndexFormat.magic, 0]
        try handle.write(contentsOf: Data(bytes: &header, count: PacketIndexFormat.headerSize))
        buffer.reserveCapacity(65_536)
    }

    func append(_ record: PacketIndexRecord) throws {
        buffer.append(record)
        count += 1
        if buffer.count >= 65_536 { try flush() }
    }

    func flush() throws {
        guard !buffer.isEmpty else { return }
        let data = buffer.withUnsafeBytes { Data($0) }
        try handle.write(contentsOf: data)
        buffer.removeAll(keepingCapacity: true)
    }

    func finish() throws {
        try flush()
        try handle.seek(toOffset: 8)
        var total = UInt64(count)
        try handle.write(contentsOf: Data(bytes: &total, count: 8))
        try handle.close()
    }
}

/// Memory-mapped view of an index file. `writable` maps it shared so fix-ups land on disk.
final class MappedPacketIndex: @unchecked Sendable {
    let count: Int
    private let base: UnsafeMutableRawPointer
    private let length: Int

    init(url: URL, writable: Bool = false) throws {
        let fd = open(url.path, writable ? O_RDWR : O_RDONLY)
        guard fd >= 0 else { throw CocoaError(.fileReadNoSuchFile, userInfo: [NSFilePathErrorKey: url.path]) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw CocoaError(.fileReadUnknown) }
        length = Int(info.st_size)
        guard length >= PacketIndexFormat.headerSize else { throw CocoaError(.fileReadCorruptFile) }
        let protection = writable ? PROT_READ | PROT_WRITE : PROT_READ
        guard let pointer = mmap(nil, length, protection, writable ? MAP_SHARED : MAP_PRIVATE, fd, 0),
              pointer != MAP_FAILED else { throw CocoaError(.fileReadUnknown) }
        base = pointer
        guard base.load(as: UInt64.self) == PacketIndexFormat.magic else {
            munmap(base, length)
            throw CocoaError(.fileReadCorruptFile)
        }
        // Never trust the stored count beyond what the file actually holds.
        let declared = Int(clamping: base.load(fromByteOffset: 8, as: UInt64.self))
        let available = (length - PacketIndexFormat.headerSize) / PacketIndexFormat.recordSize
        count = max(0, min(declared, available))
    }

    deinit { munmap(base, length) }

    /// The record at `index`; an empty record outside `0 ..< count` (callers may hold stale positions).
    @inline(__always) func record(at index: Int) -> PacketIndexRecord {
        guard index >= 0, index < count else { return PacketIndexRecord() }
        return base.load(fromByteOffset: PacketIndexFormat.headerSize + index * PacketIndexFormat.recordSize,
                         as: PacketIndexRecord.self)
    }

    @inline(__always) func setRecord(_ record: PacketIndexRecord, at index: Int) {
        guard index >= 0, index < count else { return }
        base.storeBytes(of: record, toByteOffset: PacketIndexFormat.headerSize + index * PacketIndexFormat.recordSize,
                        as: PacketIndexRecord.self)
    }

    func sync() { msync(base, length, MS_SYNC) }
}
