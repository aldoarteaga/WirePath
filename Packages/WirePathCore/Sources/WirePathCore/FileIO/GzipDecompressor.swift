import Compression
import Foundation

/// Streams a `.pcap.gz` (RFC 1952, possibly multi-member) into an uncompressed file.
///
/// The Packet Inspector needs random access to packet bytes, which a DEFLATE stream cannot
/// provide, so gzip captures are expanded once into the analysis cache.
public enum GzipDecompressor {
    public static func decompress(
        _ source: CaptureFile,
        to destination: URL,
        progress: (Double) -> Void = { _ in },
        isCancelled: () -> Bool = { false }
    ) throws {
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        guard let output = try? FileHandle(forWritingTo: destination) else {
            throw CaptureError.decompressionFailed(reason: String(localized: "cannot create \(destination.lastPathComponent)", bundle: CoreLocalization.bundle))
        }
        defer { try? output.close() }

        let input = source.allBytes
        guard let inputBase = input.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            throw CaptureError.decompressionFailed(reason: String(localized: "not a gzip file", bundle: CoreLocalization.bundle))
        }
        var offset = 0
        var members = 0
        let chunkSize = 1 << 20
        let outBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
        defer { outBuffer.deallocate() }

        while offset + 18 <= input.count, input[offset] == 0x1F, input[offset + 1] == 0x8B {
            let headerEnd = try parseHeader(input, at: offset)
            var stream = compression_stream(dst_ptr: outBuffer, dst_size: chunkSize, src_ptr: outBuffer,
                                            src_size: 0, state: nil)
            guard compression_stream_init(&stream, COMPRESSION_STREAM_DECODE, COMPRESSION_ZLIB) == COMPRESSION_STATUS_OK else {
                throw CaptureError.decompressionFailed(reason: String(localized: "cannot initialise DEFLATE decoder", bundle: CoreLocalization.bundle))
            }
            defer { compression_stream_destroy(&stream) }

            stream.src_ptr = inputBase + headerEnd
            stream.src_size = input.count - headerEnd
            var status = COMPRESSION_STATUS_OK
            var lastReport = 0
            repeat {
                stream.dst_ptr = outBuffer
                stream.dst_size = chunkSize
                status = compression_stream_process(&stream, Int32(COMPRESSION_STREAM_FINALIZE.rawValue))
                guard status != COMPRESSION_STATUS_ERROR else {
                    throw CaptureError.decompressionFailed(reason: "corrupt DEFLATE data")
                }
                let produced = chunkSize - stream.dst_size
                if produced > 0 { output.write(Data(bytesNoCopy: outBuffer, count: produced, deallocator: .none)) }
                let consumed = input.count - stream.src_size
                if consumed - lastReport > (4 << 20) {
                    lastReport = consumed
                    progress(Double(consumed) / Double(input.count))
                    if isCancelled() { throw CancellationError() }
                }
                if status == COMPRESSION_STATUS_OK && produced == 0 && stream.src_size == 0 {
                    throw CaptureError.decompressionFailed(reason: String(localized: "unexpected end of compressed data", bundle: CoreLocalization.bundle))
                }
            } while status == COMPRESSION_STATUS_OK

            // Skip the 8-byte trailer (CRC32 + ISIZE) and continue with the next member, if any.
            offset = (input.count - stream.src_size) + 8
            members += 1
        }
        guard members > 0 else { throw CaptureError.decompressionFailed(reason: String(localized: "not a gzip file", bundle: CoreLocalization.bundle)) }
        progress(1)
    }

    /// Returns the offset of the DEFLATE payload for the member starting at `offset`.
    private static func parseHeader(_ bytes: UnsafeRawBufferPointer, at offset: Int) throws -> Int {
        guard bytes[offset + 2] == 8 else { throw CaptureError.decompressionFailed(reason: String(localized: "unknown compression method", bundle: CoreLocalization.bundle)) }
        let flags = bytes[offset + 3]
        var p = offset + 10
        if flags & 0x04 != 0 {  // FEXTRA
            guard p + 2 <= bytes.count else { throw CaptureError.decompressionFailed(reason: String(localized: "truncated header", bundle: CoreLocalization.bundle)) }
            p += 2 + Int(bytes.u16le(p))
        }
        if flags & 0x08 != 0 {  // FNAME
            while p < bytes.count && bytes[p] != 0 { p += 1 }
            p += 1
        }
        if flags & 0x10 != 0 {  // FCOMMENT
            while p < bytes.count && bytes[p] != 0 { p += 1 }
            p += 1
        }
        if flags & 0x02 != 0 { p += 2 }  // FHCRC
        guard p < bytes.count else { throw CaptureError.decompressionFailed(reason: String(localized: "truncated header", bundle: CoreLocalization.bundle)) }
        return p
    }
}
