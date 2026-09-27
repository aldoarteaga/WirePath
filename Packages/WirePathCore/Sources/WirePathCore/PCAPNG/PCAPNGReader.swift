import Foundation

// pcapng (draft-ietf-opsawg-pcapng): Section Header, Interface Description, Enhanced/Simple/Obsolete Packet and
// Interface Statistics blocks. Every length is validated against the remaining bytes before it is used, the
// trailing block length must repeat the leading one, and metadata kept from the file is bounded by `Limits`.
extension CaptureReader {
    private enum BlockType {
        static let sectionHeader: UInt32 = 0x0A0D_0D0A
        static let interfaceDescription: UInt32 = 0x0000_0001
        static let obsoletePacket: UInt32 = 0x0000_0002
        static let simplePacket: UInt32 = 0x0000_0003
        static let interfaceStatistics: UInt32 = 0x0000_0005
        static let enhancedPacket: UInt32 = 0x0000_0006
    }

    private enum Option {
        static let comment: UInt16 = 1
        // Section Header Block
        static let hardware: UInt16 = 2
        static let operatingSystem: UInt16 = 3
        static let application: UInt16 = 4
        // Interface Description Block
        static let interfaceName: UInt16 = 2
        static let interfaceDescription: UInt16 = 3
        static let timestampResolution: UInt16 = 9
        static let timestampOffset: UInt16 = 14
        // Interface Statistics Block
        static let received: UInt16 = 4
        static let droppedByInterface: UInt16 = 5
        static let droppedByOS: UInt16 = 7
    }

    mutating func nextPCAPNG() throws -> CapturedFrame? {
        while true {
            let remaining = file.size - offset
            guard remaining > 0 else { return nil }
            let atStart = framesRead == 0 && interfaces.isEmpty
            guard remaining >= 12 else {
                if atStart { throw CaptureError.corrupt(reason: String(localized: "pcapng block is incomplete", bundle: CoreLocalization.bundle), offset: offset) }
                markTruncated(String(localized: "Capture ends inside a block header", bundle: CoreLocalization.bundle))
                return nil
            }
            let head = file.bytes(offset: offset, length: 12)
            let rawType = head.u32le(0)

            if rawType == BlockType.sectionHeader {
                // Section Header Block: byte-order magic decides endianness for the whole section.
                let bom = head.u32le(8)
                if bom == 0x1A2B_3C4D {
                    sectionBigEndian = false
                } else if bom == 0x4D3C_2B1A {
                    sectionBigEndian = true
                } else {
                    if atStart { throw CaptureError.corrupt(reason: String(localized: "invalid section byte-order magic", bundle: CoreLocalization.bundle), offset: offset) }
                    markTruncated(String(localized: "Invalid section header at byte \(offset)", bundle: CoreLocalization.bundle))
                    return nil
                }
                interfaces.removeAll()
            }

            let blockType = rawType == BlockType.sectionHeader ? rawType : head.u32(0, bigEndian: sectionBigEndian)
            let blockLength = Int(head.u32(4, bigEndian: sectionBigEndian))
            guard blockLength >= 12, blockLength % 4 == 0 else {
                if atStart { throw CaptureError.corrupt(reason: String(localized: "invalid block length \(blockLength)", bundle: CoreLocalization.bundle), offset: offset) }
                markTruncated(String(localized: "Invalid block length \(blockLength) at byte \(offset)", bundle: CoreLocalization.bundle))
                return nil
            }
            guard blockLength <= remaining else {
                if atStart { throw CaptureError.corrupt(reason: String(localized: "block extends past the end of the file", bundle: CoreLocalization.bundle), offset: offset) }
                markTruncated(String(localized: "Capture ends inside a block at byte \(offset)", bundle: CoreLocalization.bundle))
                return nil
            }
            let block = file.bytes(offset: offset, length: blockLength)
            guard Int(block.u32(blockLength - 4, bigEndian: sectionBigEndian)) == blockLength else {
                if atStart { throw CaptureError.corrupt(reason: String(localized: "block length fields disagree", bundle: CoreLocalization.bundle), offset: offset) }
                markTruncated(String(localized: "Damaged block at byte \(offset) (length fields disagree)", bundle: CoreLocalization.bundle))
                return nil
            }
            let blockStart = offset
            offset += blockLength

            switch blockType {
            case BlockType.sectionHeader:
                parseSectionHeader(block)
            case BlockType.interfaceDescription:
                parseInterfaceDescription(block)
            case BlockType.interfaceStatistics:
                parseInterfaceStatistics(block)
            case BlockType.enhancedPacket:
                guard blockLength >= 32 else { continue }
                let interfaceID = Int(block.u32(8, bigEndian: sectionBigEndian))
                let timestamp = UInt64(block.u32(12, bigEndian: sectionBigEndian)) << 32
                    | UInt64(block.u32(16, bigEndian: sectionBigEndian))
                let capLen = Int(block.u32(20, bigEndian: sectionBigEndian))
                let origLen = Int(block.u32(24, bigEndian: sectionBigEndian))
                guard capLen <= blockLength - 32 else {
                    warn(String(localized: "Packet block at byte \(blockStart) declares more data than it contains", bundle: CoreLocalization.bundle))
                    continue
                }
                let frame = makeFrame(interfaceID: interfaceID, rawTimestamp: timestamp, dataOffset: blockStart + 28,
                                      capLen: capLen, origLen: origLen)
                parsePacketComments(block, optionsStart: 28 + Self.padded(capLen), frameNumber: frame.number)
                return frame
            case BlockType.simplePacket:
                // Interface 0, no timestamp; the captured length is implied by the block length.
                guard blockLength >= 16 else { continue }
                let origLen = Int(block.u32(8, bigEndian: sectionBigEndian))
                var capLen = min(origLen, blockLength - 16)
                if let snap = interfaces.first?.snapLength, snap > 0 { capLen = min(capLen, snap) }
                return makeFrame(interfaceID: 0, rawTimestamp: nil, dataOffset: blockStart + 12, capLen: capLen, origLen: origLen)
            case BlockType.obsoletePacket:
                guard blockLength >= 32 else { continue }
                let interfaceID = Int(block.u16(8, bigEndian: sectionBigEndian))
                let timestamp = UInt64(block.u32(12, bigEndian: sectionBigEndian)) << 32
                    | UInt64(block.u32(16, bigEndian: sectionBigEndian))
                let capLen = Int(block.u32(20, bigEndian: sectionBigEndian))
                let origLen = Int(block.u32(24, bigEndian: sectionBigEndian))
                guard capLen <= blockLength - 32 else { continue }
                return makeFrame(interfaceID: interfaceID, rawTimestamp: timestamp, dataOffset: blockStart + 28,
                                 capLen: capLen, origLen: origLen)
            default:
                // Name resolution, decryption secrets, custom blocks… not used by the analysis.
                continue
            }
        }
    }

    static func padded(_ length: Int) -> Int { (length + 3) & ~3 }

    /// Calls `body` for each option in `block[start ..< count - 4]` until opt_endofopt or malformed data.
    func forEachOption(in block: UnsafeRawBufferPointer, from start: Int, _ body: (UInt16, UnsafeRawBufferPointer) -> Void) {
        var p = start
        let end = block.count - 4
        while p >= 0, p + 4 <= end {
            let code = block.u16(p, bigEndian: sectionBigEndian)
            let length = Int(block.u16(p + 2, bigEndian: sectionBigEndian))
            if code == 0 { return }
            let valueStart = p + 4
            guard valueStart + length <= end else { return }
            body(code, block.slice(valueStart, length))
            p = valueStart + Self.padded(length)
        }
    }

    static func text(_ value: UnsafeRawBufferPointer) -> String? {
        let string = value.utf8String(0, min(value.count, Limits.maxTextLength))
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return string.isEmpty ? nil : string
    }

    mutating func parseSectionHeader(_ block: UnsafeRawBufferPointer) {
        guard block.count >= 28 else { return }
        formatVersion = "\(block.u16(12, bigEndian: sectionBigEndian)).\(block.u16(14, bigEndian: sectionBigEndian))"
        var info = sectionInfo ?? CaptureSectionInfo(comments: [])
        forEachOption(in: block, from: 24) { code, value in
            switch code {
            case Option.comment:
                if info.comments.count < Limits.maxSectionComments, let text = Self.text(value) { info.comments.append(text) }
            case Option.hardware: info.hardware = info.hardware ?? Self.text(value)
            case Option.operatingSystem: info.operatingSystem = info.operatingSystem ?? Self.text(value)
            case Option.application: info.application = info.application ?? Self.text(value)
            default: break
            }
        }
        sectionInfo = info
    }

    mutating func parseInterfaceDescription(_ block: UnsafeRawBufferPointer) {
        guard block.count >= 20 else { return }
        guard interfaceInfos.count < Limits.maxInterfaces else {
            if interfaceInfos.count == Limits.maxInterfaces { warn(String(localized: "More than \(Limits.maxInterfaces) interfaces; the rest are ignored", bundle: CoreLocalization.bundle)) }
            return
        }
        let linkType = LinkType(rawValue: UInt32(block.u16(8, bigEndian: sectionBigEndian)))
        let snap = Int(block.u32(12, bigEndian: sectionBigEndian))
        var interface = Interface(linkType: linkType, snapLength: snap, tsDecimal: true, tsExponent: 6,
                                  tsOffsetSeconds: 0, globalID: interfaceInfos.count)
        var info = CaptureInterfaceInfo(id: interface.globalID, linkType: linkType.rawValue, linkTypeName: linkType.description,
                                        snapLength: snap, timestampResolution: "µs", packetCount: 0)
        let bigEndian = sectionBigEndian
        forEachOption(in: block, from: 16) { code, value in
            switch code {
            case Option.interfaceName: info.name = Self.text(value)
            case Option.interfaceDescription: info.interfaceDescription = Self.text(value)
            case Option.timestampResolution where value.count >= 1:
                let raw = value[0]
                interface.tsDecimal = raw & 0x80 == 0
                interface.tsExponent = Int(raw & 0x7F)
            case Option.timestampOffset where value.count >= 8:
                interface.tsOffsetSeconds = Int64(bitPattern: value.u64(0, bigEndian: bigEndian))
            default: break
            }
        }
        info.timestampResolution = Self.resolutionName(decimal: interface.tsDecimal, exponent: interface.tsExponent)
        interfaces.append(interface)
        interfaceInfos.append(info)
        if !linkTypes.contains(linkType) { linkTypes.append(linkType) }
    }

    mutating func parseInterfaceStatistics(_ block: UnsafeRawBufferPointer) {
        guard block.count >= 24 else { return }
        let localID = Int(block.u32(8, bigEndian: sectionBigEndian))
        guard localID < interfaces.count else { return }
        let global = interfaces[localID].globalID
        let bigEndian = sectionBigEndian
        var info = interfaceInfos[global]
        forEachOption(in: block, from: 20) { code, value in
            guard value.count >= 8 else { return }
            let number = value.u64(0, bigEndian: bigEndian)
            switch code {
            case Option.received: info.packetsReceived = number
            case Option.droppedByInterface: info.packetsDroppedByInterface = number
            case Option.droppedByOS: info.packetsDroppedByOS = number
            default: break
            }
        }
        interfaceInfos[global] = info
    }

    mutating func parsePacketComments(_ block: UnsafeRawBufferPointer, optionsStart: Int, frameNumber: Int) {
        guard optionsStart + 4 <= block.count - 4, packetComments.count < Limits.maxPacketComments else { return }
        var found: [String] = []
        forEachOption(in: block, from: optionsStart) { code, value in
            if code == Option.comment, let text = Self.text(value) { found.append(text) }
        }
        for text in found where packetComments.count < Limits.maxPacketComments {
            packetComments.append(PacketComment(frameNumber: frameNumber, text: text))
        }
    }

    mutating func makeFrame(interfaceID: Int, rawTimestamp: UInt64?, dataOffset: Int, capLen: Int, origLen: Int) -> CapturedFrame {
        let interface = interfaceID < interfaces.count ? interfaces[interfaceID] : nil
        if interface == nil && !warnings.contains(where: { $0.hasPrefix("Packet references unknown interface") }) {
            warn(String(localized: "Packet references unknown interface \(interfaceID)", bundle: CoreLocalization.bundle))
        }
        var nanos: Int64 = 0
        if let raw = rawTimestamp {
            nanos = Self.nanoseconds(raw, decimal: interface?.tsDecimal ?? true, exponent: interface?.tsExponent ?? 6)
            // if_tsoffset is attacker-controlled: wrap instead of trapping on overflow.
            nanos = nanos &+ (interface?.tsOffsetSeconds ?? 0) &* 1_000_000_000
        }
        if let interface, capLen > interface.snapLength, interface.snapLength > 0, !warnedAboutSnapLength {
            warnedAboutSnapLength = true
            warn(String(localized: "Packet \(framesRead + 1) is longer than its interface's snapshot length (\(capLen) > \(interface.snapLength) bytes)", bundle: CoreLocalization.bundle))
        }
        framesRead += 1
        if let interface { interfaceInfos[interface.globalID].packetCount += 1 }
        return CapturedFrame(number: framesRead, timestampNanos: nanos, linkType: interface?.linkType ?? .ethernet,
                             interfaceID: interface?.globalID ?? interfaceID, dataOffset: dataOffset, capturedLength: capLen,
                             originalLength: max(origLen, capLen))
    }

    static func resolutionName(decimal: Bool, exponent: Int) -> String {
        if decimal {
            switch exponent {
            case 0: return "s"
            case 3: return "ms"
            case 6: return "µs"
            case 9: return "ns"
            default: return "10^-\(exponent) s"
            }
        }
        return "2^-\(exponent) s"
    }

    /// Converts a raw pcapng timestamp to nanoseconds. `exponent` comes from the file (0…127), so shifts are
    /// clamped and multiplication wraps rather than trapping.
    static func nanoseconds(_ raw: UInt64, decimal: Bool, exponent: Int) -> Int64 {
        if decimal {
            let e = min(max(exponent, 0), 127)
            if e == 9 { return Int64(bitPattern: raw) }
            if e < 9 {
                var multiplier: UInt64 = 1
                for _ in 0..<(9 - e) { multiplier *= 10 }
                return Int64(bitPattern: raw &* multiplier)
            }
            var divisor: UInt64 = 1
            for _ in 0..<min(e - 9, 19) { divisor *= 10 }
            return Int64(bitPattern: raw / divisor)
        }
        // Binary resolution: units of 2^-exponent seconds.
        let e = min(max(exponent, 0), 63)
        guard e > 0 else { return Int64(bitPattern: raw &* 1_000_000_000) }
        let unit = UInt64(1) << UInt64(e)
        let seconds = raw >> UInt64(e)
        let fraction = raw & (unit - 1)
        let fractionalNanos = Int64((Double(fraction) / Double(unit) * 1e9).rounded())
        return Int64(bitPattern: seconds &* 1_000_000_000) &+ fractionalNanos
    }
}
