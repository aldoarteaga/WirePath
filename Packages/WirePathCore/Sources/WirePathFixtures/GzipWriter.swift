import Compression
import Foundation

/// Writes RFC 1952 gzip files in-process (Apple's `COMPRESSION_ZLIB` is raw DEFLATE), so compressed
/// fixtures can be produced on every platform — iOS has no `/usr/bin/gzip` to shell out to.
public enum GzipWriter {
    public enum Failure: Error { case compressionFailed }

    public static func gzip(_ data: Data) throws -> Data {
        var output = Data([0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 0xFF])  // magic, DEFLATE, no flags, no mtime, unknown OS
        output.append(try deflate(data))
        appendLE(UInt32(truncatingIfNeeded: crc32(data)), to: &output)
        appendLE(UInt32(truncatingIfNeeded: data.count), to: &output)
        return output
    }

    public static func gzipFile(at source: URL, to destination: URL) throws {
        try gzip(Data(contentsOf: source)).write(to: destination)
    }

    private static func deflate(_ data: Data) throws -> Data {
        let chunkSize = 1 << 16
        var result = Data()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
        defer { buffer.deallocate() }
        var stream = compression_stream(dst_ptr: buffer, dst_size: chunkSize, src_ptr: buffer, src_size: 0, state: nil)
        guard compression_stream_init(&stream, COMPRESSION_STREAM_ENCODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
            throw Failure.compressionFailed
        }
        defer { compression_stream_destroy(&stream) }
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            stream.src_ptr = raw.bindMemory(to: UInt8.self).baseAddress ?? UnsafePointer(buffer)
            stream.src_size = raw.count
            var status = COMPRESSION_STATUS_OK
            repeat {
                stream.dst_ptr = buffer
                stream.dst_size = chunkSize
                status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                guard status != COMPRESSION_STATUS_ERROR else { throw Failure.compressionFailed }
                result.append(buffer, count: chunkSize - stream.dst_size)
            } while status == COMPRESSION_STATUS_OK
        }
        return result
    }

    private static let crcTable: [UInt32] = (0..<256).map { n -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
        return c
    }

    public static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data { crc = crcTable[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8) }
        return crc ^ 0xFFFF_FFFF
    }

    private static func appendLE(_ value: UInt32, to data: inout Data) {
        withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) }
    }
}
