import Foundation

/// Where WirePathCore's own strings (diagnostics, headlines, call states, warnings) are looked up: the package's
/// resource bundle, which carries the English and Spanish catalog with plural rules.
///
/// SwiftPM's generated `Bundle.module` stops the process when the bundle is missing (a command-line tool copied
/// on its own). This lookup falls back to the main bundle instead, where strings still read in English.
enum CoreLocalization {
    private final class Token {}

    static let bundle: Bundle = {
        let name = "WirePathCore_WirePathCore.bundle"
        let owner = Bundle(for: Token.self)
        let places = [Bundle.main.resourceURL, Bundle.main.bundleURL, owner.resourceURL, owner.bundleURL,
                      owner.bundleURL.deletingLastPathComponent(), Bundle.main.executableURL?.deletingLastPathComponent()]
        for place in places.compactMap({ $0 }) {
            if let bundle = Bundle(url: place.appendingPathComponent(name)) { return bundle }
        }
        return .main
    }()
}
