import SwiftUI
import ImageIO
import UniformTypeIdentifiers

#if os(macOS)
import AppKit
public typealias PlatformColor = NSColor
public typealias PlatformFont = NSFont
#else
import UIKit
public typealias PlatformColor = UIColor
public typealias PlatformFont = UIFont
#endif

/// Small platform adapters. Everything else in WirePathUI is plain SwiftUI shared by macOS and iPadOS.
public enum Platform {
    #if os(macOS)
    public static let isMac = true
    #else
    public static let isMac = false
    #endif
}

extension PlatformColor {
    /// Colour that resolves differently in dark and light appearance.
    static func dynamic(dark: PlatformColor, light: PlatformColor) -> PlatformColor {
        #if os(macOS)
        NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        }
        #else
        UIColor { traits in traits.userInterfaceStyle == .dark ? dark : light }
        #endif
    }

    static func srgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> PlatformColor {
        PlatformColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                      blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
    }

    static func srgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat) -> PlatformColor {
        PlatformColor(red: r / 255, green: g / 255, blue: b / 255, alpha: a)
    }
}

extension Color {
    init(platform color: PlatformColor) {
        #if os(macOS)
        self.init(nsColor: color)
        #else
        self.init(uiColor: color)
        #endif
    }
}

extension PlatformFont {
    /// SF Pro Text with tabular digits (design: `font-variant-numeric: tabular-nums`).
    static func wp(_ size: CGFloat, _ weight: PlatformFont.Weight = .regular) -> PlatformFont {
        PlatformFont.monospacedDigitSystemFont(ofSize: size, weight: weight)
    }

    /// SF Mono.
    static func wpMono(_ size: CGFloat, _ weight: PlatformFont.Weight = .regular) -> PlatformFont {
        PlatformFont.monospacedSystemFont(ofSize: size, weight: weight)
    }
}

/// System clipboard.
public enum Clipboard {
    public static func copy(_ text: String) {
        #if os(macOS)
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #else
        UIPasteboard.general.string = text
        #endif
    }
}

/// A file prepared for export through the system save panel (`.fileExporter`).
public struct ExportFile: Identifiable, Sendable {
    public var id = UUID()
    public var filename: String
    public var contentType: UTType
    /// Temporary file holding the exported bytes (written off the main thread for large exports).
    public var url: URL

    public init(filename: String, contentType: UTType, url: URL) {
        self.filename = filename
        self.contentType = contentType
        self.url = url
    }

    /// Writes `data` to a temporary file and wraps it for export.
    public static func temporary(_ data: Data, filename: String, contentType: UTType) throws -> ExportFile {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            .appendingPathExtension(contentType.preferredFilenameExtension ?? "dat")
        try data.write(to: url, options: .atomic)
        return ExportFile(filename: filename, contentType: contentType, url: url)
    }
}

/// FileDocument that streams an existing temporary file into the user's chosen location.
struct ExportDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }
    var url: URL

    init(url: URL) { self.url = url }

    init(configuration: ReadConfiguration) throws {
        throw CocoaError(.featureUnsupported)
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        try FileWrapper(url: url, options: [])
    }
}

/// Makes a region behave like a title bar on macOS (drag to move, double-click to zoom/minimise per
/// the user's setting). On iPadOS the system owns window movement, so it is an inert background.
struct WindowDragArea: View {
    var body: some View {
        #if os(macOS)
        Color.clear
            .contentShape(Rectangle())
            .gesture(WindowDragGesture())
            .onTapGesture(count: 2) {
                let action = UserDefaults.standard.string(forKey: "AppleActionOnDoubleClick") ?? "Maximize"
                if action == "Minimize" { NSApp.keyWindow?.performMiniaturize(nil) } else if action != "None" { NSApp.keyWindow?.performZoom(nil) }
            }
            .allowsWindowActivationEvents(true)
        #else
        Color.clear
        #endif
    }
}



/// PNG encoding through ImageIO (available on every Apple platform).
enum PNGEncoder {
    static func data(for image: CGImage) -> Data? {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(data, UTType.png.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(destination, image, nil)
        return CGImageDestinationFinalize(destination) ? data as Data : nil
    }
}
