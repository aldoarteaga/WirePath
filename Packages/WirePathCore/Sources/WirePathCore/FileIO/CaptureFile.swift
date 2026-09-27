import Foundation

public enum CaptureError: Error, Sendable, Equatable, LocalizedError {
    case cannotOpen(path: String, reason: String)
    case empty
    case unsupportedFormat(magic: UInt32)
    case compressedNotSupported
    case corrupt(reason: String, offset: Int)
    case decompressionFailed(reason: String)

    public var errorDescription: String? {
        switch self {
        case .cannotOpen(let path, let reason):
            return String(localized: "Could not open “\((path as NSString).lastPathComponent)”: \(reason)", bundle: CoreLocalization.bundle)
        case .empty:
            return String(localized: "The file is empty.", bundle: CoreLocalization.bundle)
        case .unsupportedFormat(let magic):
            return String(format: "Not a pcap or pcapng capture (file signature 0x%08X).", magic)
        case .compressedNotSupported:
            return String(localized: "This compressed format is not supported. Decompress the capture and import it again.", bundle: CoreLocalization.bundle)
        case .corrupt(let reason, let offset):
            return String(localized: "The capture is damaged at byte \(offset): \(reason).", bundle: CoreLocalization.bundle)
        case .decompressionFailed(let reason):
            return String(localized: "The compressed capture could not be decompressed: \(reason).", bundle: CoreLocalization.bundle)
        }
    }
}

/// A read-only, memory-mapped capture file. Pages are loaded lazily by the kernel, so opening a
/// multi-gigabyte capture costs almost nothing and bytes are shared across concurrent readers.
///
/// The file keeps security-scoped access to `url` while it is mapped, so captures chosen by the user
/// outside the sandbox (open panel, Finder, Files, iCloud Drive, USB storage) stay readable.
public final class CaptureFile: @unchecked Sendable {
    public let url: URL
    public let size: Int
    private let base: UnsafeRawPointer?
    private let mappedLength: Int
    private let access: SecurityScopedAccess

    public init(url: URL) throws {
        self.url = url
        access = SecurityScopedAccess(url)
        let fd = open(url.path, O_RDONLY)
        guard fd >= 0 else {
            throw CaptureError.cannotOpen(path: url.path, reason: String(cString: strerror(errno)))
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else {
            throw CaptureError.cannotOpen(path: url.path, reason: String(cString: strerror(errno)))
        }
        size = Int(info.st_size)
        guard size > 0 else {
            base = nil
            mappedLength = 0
            return
        }
        let pointer = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0)
        guard let pointer, pointer != MAP_FAILED else {
            throw CaptureError.cannotOpen(path: url.path, reason: String(cString: strerror(errno)))
        }
        madvise(pointer, size, MADV_SEQUENTIAL)
        base = UnsafeRawPointer(pointer)
        mappedLength = size
    }

    deinit {
        if let base { munmap(UnsafeMutableRawPointer(mutating: base), mappedLength) }
    }

    /// Bytes in `offset ..< offset + length`, clamped to the file. Valid while `self` is alive.
    public func bytes(offset: Int, length: Int) -> UnsafeRawBufferPointer {
        guard let base, offset >= 0, offset < size, length > 0 else {
            return UnsafeRawBufferPointer(start: nil, count: 0)
        }
        return UnsafeRawBufferPointer(start: base + offset, count: min(length, size - offset))
    }

    public var allBytes: UnsafeRawBufferPointer { bytes(offset: 0, length: size) }

    /// Copies the given range into an owned `Data`.
    public func data(offset: Int, length: Int) -> Data {
        let buffer = bytes(offset: offset, length: length)
        return buffer.isEmpty ? Data() : Data(buffer)
    }

    /// Hint that the range will be accessed randomly from now on (e.g. by the packet inspector).
    public func adviseRandomAccess() {
        if let base { madvise(UnsafeMutableRawPointer(mutating: base), mappedLength, MADV_RANDOM) }
    }
}

// MARK: - Byte helpers

// Integer reads used by every parser. `UnsafeRawBufferPointer` subscripts are not bounds-checked in release
// builds, so these helpers check the range themselves and read 0 outside the buffer: a parser that forgets a
// length check gets a wrong value, never an out-of-bounds read. Parsers still validate lengths first.
extension UnsafeRawBufferPointer {
    @inline(__always) public func u8(_ offset: Int) -> UInt8 {
        guard offset >= 0, offset < count else { return 0 }
        return self[offset]
    }

    @inline(__always) public func u16be(_ offset: Int) -> UInt16 {
        guard offset >= 0, offset <= count - 2 else { return 0 }
        return UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }

    @inline(__always) public func u16le(_ offset: Int) -> UInt16 {
        guard offset >= 0, offset <= count - 2 else { return 0 }
        return UInt16(self[offset + 1]) << 8 | UInt16(self[offset])
    }

    @inline(__always) public func u32be(_ offset: Int) -> UInt32 {
        guard offset >= 0, offset <= count - 4 else { return 0 }
        return UInt32(self[offset]) << 24 | UInt32(self[offset + 1]) << 16 | UInt32(self[offset + 2]) << 8 | UInt32(self[offset + 3])
    }

    @inline(__always) public func u32le(_ offset: Int) -> UInt32 {
        guard offset >= 0, offset <= count - 4 else { return 0 }
        return UInt32(self[offset + 3]) << 24 | UInt32(self[offset + 2]) << 16 | UInt32(self[offset + 1]) << 8 | UInt32(self[offset])
    }

    @inline(__always) public func u16(_ offset: Int, bigEndian: Bool) -> UInt16 {
        bigEndian ? u16be(offset) : u16le(offset)
    }

    @inline(__always) public func u32(_ offset: Int, bigEndian: Bool) -> UInt32 {
        bigEndian ? u32be(offset) : u32le(offset)
    }

    @inline(__always) public func u64(_ offset: Int, bigEndian: Bool) -> UInt64 {
        let first = UInt64(u32(offset, bigEndian: bigEndian))
        let second = UInt64(u32(offset + 4, bigEndian: bigEndian))
        return bigEndian ? first << 32 | second : second << 32 | first
    }

    /// The bytes in `start ..< start + length`, clamped to the buffer (empty when out of range).
    @inline(__always) public func slice(_ start: Int, _ length: Int) -> UnsafeRawBufferPointer {
        guard start >= 0, length > 0, start < count else { return UnsafeRawBufferPointer(start: nil, count: 0) }
        return UnsafeRawBufferPointer(rebasing: self[start..<(start + Swift.min(length, count - start))])
    }

    /// UTF-8 text in `start ..< start + length` (clamped), with trailing NULs removed.
    public func utf8String(_ start: Int, _ length: Int) -> String {
        var text = slice(start, length)
        while let last = text.last, last == 0 { text = UnsafeRawBufferPointer(rebasing: text.dropLast()) }
        return String(decoding: text, as: UTF8.self)
    }
}
