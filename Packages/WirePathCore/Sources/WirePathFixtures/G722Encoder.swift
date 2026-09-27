import Foundation

/// ITU-T G.722 sub-band ADPCM encoder, 64 kbit/s (mode 1), for generating fixture audio. Its output decodes with
/// any reference decoder (ffmpeg's included), which is how the fixtures were checked.
public final class G722Encoder {
    private struct Band {
        var s = 0, sp = 0, sz = 0
        var r = [0, 0, 0], a = [0, 0, 0], ap = [0, 0, 0], p = [0, 0, 0]
        var d = [0, 0, 0, 0, 0, 0, 0], b = [0, 0, 0, 0, 0, 0, 0], bp = [0, 0, 0, 0, 0, 0, 0]
        var nb = 0
        var det: Int
    }

    private var low = Band(det: 32)
    private var high = Band(det: 8)
    private var x = [Int](repeating: 0, count: 24)

    public init() {}

    /// Encodes 16 kHz samples (an even count) to one byte per pair of samples.
    public func encode(_ samples: [Int16]) -> [UInt8] {
        var output = [UInt8]()
        output.reserveCapacity(samples.count / 2)
        var j = 0
        while j + 1 < samples.count {
            x.removeFirst(2)
            x.append(Int(samples[j]))
            x.append(Int(samples[j + 1]))
            j += 2
            var sumEven = 0, sumOdd = 0
            for i in 0..<12 {
                sumOdd += x[2 * i] * Self.qmf[i]
                sumEven += x[2 * i + 1] * Self.qmf[11 - i]
            }
            let xlow = (sumEven + sumOdd) >> 14
            let xhigh = (sumEven - sumOdd) >> 14

            // Lower band: quantize the prediction error to 6 bits.
            let el = Self.sat(xlow - low.s)
            let magnitude = el >= 0 ? el : -(el + 1)
            var level = 1
            while level < 30, magnitude >= (Self.q6[level] * low.det) >> 12 { level += 1 }
            let ilow = el < 0 ? Self.iln[level] : Self.ilp[level]
            let ril = ilow >> 2
            let dlow = (low.det * Self.qm4[ril]) >> 15
            low.nb = min(18432, max(0, ((low.nb * 127) >> 7) + Self.wl[Self.rl42[ril]]))
            low.det = Self.scale(low.nb, shiftBase: 8)
            Self.adapt(&low, dlow)

            // Higher band: 2 bits.
            let eh = Self.sat(xhigh - high.s)
            let highMagnitude = eh >= 0 ? eh : -(eh + 1)
            let mih = highMagnitude >= (564 * high.det) >> 12 ? 2 : 1
            let ihigh = eh < 0 ? Self.ihn[mih] : Self.ihp[mih]
            let dhigh = (high.det * Self.qm2[ihigh]) >> 15
            high.nb = min(22528, max(0, ((high.nb * 127) >> 7) + Self.wh[Self.rh2[ihigh]]))
            high.det = Self.scale(high.nb, shiftBase: 10)
            Self.adapt(&high, dhigh)

            output.append(UInt8((ihigh << 6) | ilow))
        }
        return output
    }

    private static func sat(_ value: Int) -> Int { Int(Int16(clamping: value)) }

    private static func scale(_ nb: Int, shiftBase: Int) -> Int {
        let wd1 = (nb >> 6) & 31
        let wd2 = shiftBase - (nb >> 11)
        return (wd2 < 0 ? ilb[wd1] << -wd2 : ilb[wd1] >> wd2) << 2
    }

    /// Block 4, shared with the decoder (the encoder tracks the decoder's state).
    private static func adapt(_ band: inout Band, _ dx: Int) {
        band.d[0] = dx
        band.r[0] = sat(band.s + dx)
        band.p[0] = sat(band.sz + dx)
        var sg = [0, 0, 0, 0, 0, 0, 0]
        for i in 0..<3 { sg[i] = band.p[i] >> 15 }
        let wd1 = sat(band.a[1] << 2)
        let wd2 = min(32767, sg[0] == sg[1] ? -wd1 : wd1)
        band.ap[2] = min(12288, max(-12288, (sg[0] == sg[2] ? 128 : -128) + (wd2 >> 7) + ((band.a[2] * 32512) >> 15)))
        sg[0] = band.p[0] >> 15
        sg[1] = band.p[1] >> 15
        band.ap[1] = sat((sg[0] == sg[1] ? 192 : -192) + ((band.a[1] * 32640) >> 15))
        let limit = sat(15360 - band.ap[2])
        band.ap[1] = min(limit, max(-limit, band.ap[1]))
        let step = dx == 0 ? 0 : 128
        sg[0] = dx >> 15
        for i in 1..<7 {
            sg[i] = band.d[i] >> 15
            band.bp[i] = sat((sg[i] == sg[0] ? step : -step) + ((band.b[i] * 32640) >> 15))
        }
        for i in stride(from: 6, to: 0, by: -1) {
            band.d[i] = band.d[i - 1]
            band.b[i] = band.bp[i]
        }
        for i in stride(from: 2, to: 0, by: -1) {
            band.r[i] = band.r[i - 1]
            band.p[i] = band.p[i - 1]
            band.a[i] = band.ap[i]
        }
        band.sp = sat(((band.a[1] * sat(band.r[1] + band.r[1])) >> 15) + ((band.a[2] * sat(band.r[2] + band.r[2])) >> 15))
        var sz = 0
        for i in stride(from: 6, to: 0, by: -1) { sz += (band.b[i] * sat(band.d[i] + band.d[i])) >> 15 }
        band.sz = sat(sz)
        band.s = sat(band.sp + band.sz)
    }

    private static let qmf = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11]
    private static let q6 = [0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940, 1023,
                             1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0]
    private static let iln = [0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                              10, 9, 8, 7, 6, 5, 4, 0]
    private static let ilp = [0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
                              38, 37, 36, 35, 34, 33, 32, 0]
    private static let qm4 = [0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584, 1200, 0]
    private static let ilb = [2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
                              2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008]
    private static let wl = [-60, -30, 58, 172, 334, 538, 1198, 3042]
    private static let rl42 = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0]
    private static let ihn = [0, 1, 0]
    private static let ihp = [0, 3, 2]
    private static let wh = [0, -214, 798]
    private static let rh2 = [2, 1, 2, 1]
    private static let qm2 = [-7408, -1616, 7408, 1616]
}
