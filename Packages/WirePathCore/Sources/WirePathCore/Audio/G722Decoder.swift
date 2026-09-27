import Foundation

/// ITU-T G.722 sub-band ADPCM decoder, 64 kbit/s (mode 1: 6-bit lower band, 2-bit higher band), 16 kHz output.
///
/// Follows the fixed-point algorithm of the Recommendation (blocks 2–6 L/H and the receive QMF), so the output is
/// bit-exact with reference decoders. G.722 is royalty-free. RTP carries it with an 8 kHz timestamp clock
/// (RFC 3551) although audio is sampled at 16 kHz: every payload byte yields two samples.
public final class G722Decoder: AudioDecoder {
    public let sampleRate = 16000

    private struct Band {
        var s = 0, sp = 0, sz = 0
        var r = [0, 0, 0]
        var a = [0, 0, 0], ap = [0, 0, 0]
        var p = [0, 0, 0]
        var d = [0, 0, 0, 0, 0, 0, 0]
        var b = [0, 0, 0, 0, 0, 0, 0], bp = [0, 0, 0, 0, 0, 0, 0]
        var nb = 0
        var det: Int
    }

    private var low = Band(det: 32)
    private var high = Band(det: 8)
    private var x = [Int](repeating: 0, count: 24)

    public init() {}

    public func decode(_ payload: UnsafeRawBufferPointer) throws(AudioDecodeError) -> [Int16] {
        var output = [Int16]()
        output.reserveCapacity(payload.count * 2)
        for code in payload {
            // Lower sub-band: 6-bit code, of which the top 4 bits drive the predictor adaptation.
            let ilow = Int(code & 0x3F)
            let ihigh = Int(code >> 6)
            var rlow = low.s + ((low.det * Self.qm6[ilow]) >> 15)
            rlow = min(16383, max(-16384, rlow))
            let dlowt = (low.det * Self.qm4[ilow >> 2]) >> 15
            low.nb = min(18432, max(0, ((low.nb * 127) >> 7) + Self.wl[Self.rl42[ilow >> 2]]))
            low.det = Self.scale(low.nb, shiftBase: 8)
            Self.adapt(&low, dlowt)

            // Higher sub-band: 2-bit code.
            let dhigh = (high.det * Self.qm2[ihigh]) >> 15
            let rhigh = min(16383, max(-16384, dhigh + high.s))
            high.nb = min(22528, max(0, ((high.nb * 127) >> 7) + Self.wh[Self.rh2[ihigh]]))
            high.det = Self.scale(high.nb, shiftBase: 10)
            Self.adapt(&high, dhigh)

            // Receive QMF: two 16 kHz samples from the two sub-band samples.
            x.removeFirst(2)
            x.append(rlow + rhigh)
            x.append(rlow - rhigh)
            var xout1 = 0, xout2 = 0
            for i in 0..<12 {
                xout2 += x[2 * i] * Self.qmf[i]
                xout1 += x[2 * i + 1] * Self.qmf[11 - i]
            }
            output.append(Self.saturate(xout1 >> 11))
            output.append(Self.saturate(xout2 >> 11))
        }
        return output
    }

    // MARK: Algorithm blocks

    private static func saturate(_ value: Int) -> Int16 { Int16(clamping: value) }
    private static func sat(_ value: Int) -> Int { Int(Int16(clamping: value)) }

    /// SCALEL / SCALEH: quantizer scale factor from the log scale factor.
    private static func scale(_ nb: Int, shiftBase: Int) -> Int {
        let wd1 = (nb >> 6) & 31
        let wd2 = shiftBase - (nb >> 11)
        let wd3 = wd2 < 0 ? ilb[wd1] << -wd2 : ilb[wd1] >> wd2
        return wd3 << 2
    }

    /// Block 4: reconstruction, pole/zero predictor adaptation and prediction for the next sample.
    private static func adapt(_ band: inout Band, _ dx: Int) {
        band.d[0] = dx
        band.r[0] = sat(band.s + dx)
        band.p[0] = sat(band.sz + dx)

        // UPPOL2
        var sg = [0, 0, 0, 0, 0, 0, 0]
        for i in 0..<3 { sg[i] = band.p[i] >> 15 }
        let wd1 = sat(band.a[1] << 2)
        let wd2 = min(32767, sg[0] == sg[1] ? -wd1 : wd1)
        var wd3 = (sg[0] == sg[2] ? 128 : -128) + (wd2 >> 7) + ((band.a[2] * 32512) >> 15)
        wd3 = min(12288, max(-12288, wd3))
        band.ap[2] = wd3

        // UPPOL1
        sg[0] = band.p[0] >> 15
        sg[1] = band.p[1] >> 15
        band.ap[1] = sat((sg[0] == sg[1] ? 192 : -192) + ((band.a[1] * 32640) >> 15))
        let limit = sat(15360 - band.ap[2])
        band.ap[1] = min(limit, max(-limit, band.ap[1]))

        // UPZERO
        let step = dx == 0 ? 0 : 128
        sg[0] = dx >> 15
        for i in 1..<7 {
            sg[i] = band.d[i] >> 15
            band.bp[i] = sat((sg[i] == sg[0] ? step : -step) + ((band.b[i] * 32640) >> 15))
        }

        // DELAYA
        for i in stride(from: 6, to: 0, by: -1) {
            band.d[i] = band.d[i - 1]
            band.b[i] = band.bp[i]
        }
        for i in stride(from: 2, to: 0, by: -1) {
            band.r[i] = band.r[i - 1]
            band.p[i] = band.p[i - 1]
            band.a[i] = band.ap[i]
        }

        // FILTEP
        let pole1 = (band.a[1] * sat(band.r[1] + band.r[1])) >> 15
        let pole2 = (band.a[2] * sat(band.r[2] + band.r[2])) >> 15
        band.sp = sat(pole1 + pole2)

        // FILTEZ
        var sz = 0
        for i in stride(from: 6, to: 0, by: -1) { sz += (band.b[i] * sat(band.d[i] + band.d[i])) >> 15 }
        band.sz = sat(sz)

        // PREDIC
        band.s = sat(band.sp + band.sz)
    }

    // MARK: Tables (ITU-T G.722)

    private static let qmf = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11]
    private static let qm4 = [0, -20456, -12896, -8968, -6288, -4240, -2584, -1200,
                              20456, 12896, 8968, 6288, 4240, 2584, 1200, 0]
    private static let qm6 = [-136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192,
                              -10232, -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576,
                              -3168, -2776, -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704,
                              14984, 13512, 12280, 11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944,
                              4464, 4008, 3576, 3168, 2776, 2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136]
    private static let ilb = [2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774,
                              2834, 2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838,
                              3922, 4008]
    private static let wl = [-60, -30, 58, 172, 334, 538, 1198, 3042]
    private static let rl42 = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0]
    private static let wh = [0, -214, 798]
    private static let rh2 = [2, 1, 2, 1]
    private static let qm2 = [-7408, -1616, 7408, 1616]
}
