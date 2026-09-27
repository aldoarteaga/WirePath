// Renders WirePath's app icon from the design's delete alert (dark teal tile, cyan waveform) into the
// Xcode asset catalogs of both apps.   Usage: swift scripts/make-icon.swift
import AppKit

/// `fullBleed` renders the opaque square iPadOS expects (the system applies the mask).
func render(size: Int, fullBleed: Bool = false) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let context = NSGraphicsContext.current!.cgContext
    let scale = CGFloat(size) / 1024
    context.scaleBy(x: scale, y: scale)
    // macOS icon grid: 824 pt tile centred on a 1024 canvas; iPadOS: full-bleed square.
    let tile = fullBleed ? CGRect(x: 0, y: 0, width: 1024, height: 1024) : CGRect(x: 100, y: 100, width: 824, height: 824)
    let radius: CGFloat = fullBleed ? 0 : 185
    let path = CGPath(roundedRect: tile, cornerWidth: radius, cornerHeight: radius, transform: nil)
    context.saveGState()
    context.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: NSColor.black.withAlphaComponent(0.35).cgColor)
    context.addPath(path)
    context.setFillColor(NSColor(srgbRed: 0x16 / 255, green: 0x32 / 255, blue: 0x3A / 255, alpha: 1).cgColor)
    context.fillPath()
    context.restoreGState()
    context.saveGState()
    context.addPath(path)
    context.clip()
    let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(), colors: [
        NSColor(srgbRed: 0x1E / 255, green: 0x45 / 255, blue: 0x4F / 255, alpha: 1).cgColor,
        NSColor(srgbRed: 0x10 / 255, green: 0x26 / 255, blue: 0x2C / 255, alpha: 1).cgColor,
    ] as CFArray, locations: [0, 1])!
    context.drawLinearGradient(gradient, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
    context.restoreGState()
    if !fullBleed {
        context.addPath(path)
        context.setStrokeColor(NSColor.white.withAlphaComponent(0.12).cgColor)
        context.setLineWidth(6)
        context.strokePath()
    }

    // Waveform from the design (viewBox 36): M4 22h5l3-9 5 15 4-19 3 13h8, dot at (31, 22).
    let unit: CGFloat = (fullBleed ? 1024 : 824) / 56   // the 36-unit glyph sat in a 56 pt tile
    let origin = CGPoint(x: 512 - 18 * unit, y: 512 + 18 * unit)
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: origin.x + x * unit, y: origin.y - y * unit) }
    let points = [p(4, 22), p(9, 22), p(12, 13), p(17, 28), p(21, 9), p(24, 22), p(32, 22)]
    context.setStrokeColor(NSColor(srgbRed: 0x6F / 255, green: 0xD6 / 255, blue: 0xDB / 255, alpha: 1).cgColor)
    context.setLineWidth(2.4 * unit)
    context.setLineCap(.round)
    context.setLineJoin(.round)
    context.addLines(between: Array(points.dropLast()) + [p(29.8, 22)])
    context.strokePath()
    context.setFillColor(NSColor(srgbRed: 0x6F / 255, green: 0xD6 / 255, blue: 0xDB / 255, alpha: 1).cgColor)
    let dot = p(31, 22)
    context.fillEllipse(in: CGRect(x: dot.x - 2.2 * unit, y: dot.y - 2.2 * unit, width: 4.4 * unit, height: 4.4 * unit))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

func writeSet(_ directory: String, images: [(file: String, size: Int, json: String)], fullBleed: Bool) throws {
    let url = URL(fileURLWithPath: directory)
    try? FileManager.default.removeItem(at: url)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    for image in images { try render(size: image.size, fullBleed: fullBleed).write(to: url.appendingPathComponent(image.file)) }
    let entries = images.map(\.json).joined(separator: ",\n    ")
    try "{\n  \"images\" : [\n    \(entries)\n  ],\n  \"info\" : { \"author\" : \"xcode\", \"version\" : 1 }\n}\n"
        .write(to: url.appendingPathComponent("Contents.json"), atomically: true, encoding: .utf8)
    let catalog = url.deletingLastPathComponent().appendingPathComponent("Contents.json")
    try "{\n  \"info\" : { \"author\" : \"xcode\", \"version\" : 1 }\n}\n".write(to: catalog, atomically: true, encoding: .utf8)
}

var macImages: [(file: String, size: Int, json: String)] = []
for (points, scales) in [(16, [1, 2]), (32, [1, 2]), (128, [1, 2]), (256, [1, 2]), (512, [1, 2])] {
    for scale in scales {
        let file = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        macImages.append((file, points * scale, "{ \"filename\" : \"\(file)\", \"idiom\" : \"mac\", \"scale\" : \"\(scale)x\", \"size\" : \"\(points)x\(points)\" }"))
    }
}
try writeSet("WirePathMac/Assets.xcassets/AppIcon.appiconset", images: macImages, fullBleed: false)
try writeSet("WirePathiPad/Assets.xcassets/AppIcon.appiconset",
             images: [("icon_1024.png", 1024, "{ \"filename\" : \"icon_1024.png\", \"idiom\" : \"universal\", \"platform\" : \"ios\", \"size\" : \"1024x1024\" }")],
             fullBleed: true)
print("wrote app icons")
