@testable import WirePathCore
import Foundation
import Testing

/// The core's string catalog: English plurals, Spanish translations and plurals, and that every key translates.
@Suite("Localization")
struct LocalizationTests {
    static func bundle(_ language: String) throws -> Bundle {
        let path = try #require(CoreLocalization.bundle.path(forResource: language, ofType: "lproj"), "no \(language).lproj in the core bundle")
        return try #require(Bundle(path: path))
    }

    @Test func englishPlurals() {
        #expect(String(localized: "One-way audio · \(1) calls", bundle: CoreLocalization.bundle) == "One-way audio · 1 call")
        #expect(String(localized: "One-way audio · \(3) calls", bundle: CoreLocalization.bundle) == "One-way audio · 3 calls")
        #expect(String(localized: "\(1) SIP errors", bundle: CoreLocalization.bundle) == "1 SIP error")
    }

    @Test func spanishTranslationsAndPlurals() throws {
        let es = try Self.bundle("es")
        #expect(String(localized: "One-way audio · \(1) calls", bundle: es) == "Audio en un solo sentido · 1 llamada")
        #expect(String(localized: "One-way audio · \(4) calls", bundle: es) == "Audio en un solo sentido · 4 llamadas")
        let endpoints = "10.0.0.1:5060 → 10.0.0.2:5060"
        #expect(String(localized: "\(endpoints) · \(1) retransmitted segments of \(12) packets", bundle: es)
                == "10.0.0.1:5060 → 10.0.0.2:5060 · 1 segmento retransmitido de 12 paquetes")
        #expect(String(localized: "Good", bundle: es) == "Buena")
        #expect(QualityRating.good.localizedName == "Good")  // tests run in English
    }

    /// A plural variant that mixes `%arg` with a later argument must index it (`%2$@`): a bare `%@` reads argument 1,
    /// the integer, as an object and crashes (SIP retransmissions outside calls crashed the analysis on device).
    @Test func pluralVariantWithASecondArgument() throws {
        let es = try Self.bundle("es")
        #expect(String(localized: "\(3) retransmitted \("OPTIONS, REGISTER") messages outside calls (signalling loss or slow responses)", bundle: CoreLocalization.bundle)
                == "3 retransmitted OPTIONS, REGISTER messages outside calls (signalling loss or slow responses)")
        #expect(String(localized: "\(1) retransmitted \("OPTIONS") messages outside calls (signalling loss or slow responses)", bundle: es)
                == "1 mensaje OPTIONS retransmitido fuera de llamadas (pérdida de señalización o respuestas lentas)")
    }

    @Test func pluralVariantsIndexEveryFormatArgument() throws {
        let strings = try Self.catalogStrings()
        let bare = /%(?!\d+\$|#@|arg|%)[-+ #0]*\d*(?:\.\d+)?(?:lld|ld|lu|llu|@|d|i|u|f|g|e|s|x|X|c)/
        func values(_ node: Any) -> [String] {
            guard let dict = node as? [String: Any] else { return [] }
            let own = (dict["stringUnit"] as? [String: Any])?["value"] as? String
            return (own.map { [$0] } ?? []) + dict.filter { $0.key != "stringUnit" }.flatMap { values($0.value) }
        }
        let offenders = strings.flatMap { key, value in
            ((value["localizations"] as? [String: [String: Any]]) ?? [:]).values
                .flatMap { values($0["substitutions"] ?? [:]) }
                .filter { $0.contains(bare) }
                .map { "\(key) → \($0)" }
        }
        #expect(offenders.isEmpty, "unindexed format arguments in plural variants: \(offenders)")
    }

    static func catalogStrings() throws -> [String: [String: Any]] {
        let url = try #require(CoreLocalization.bundle.url(forResource: "Localizable", withExtension: "xcstrings")
            ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Sources/WirePathCore/Resources/Localizable.xcstrings"))
        let catalog = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        return try #require(catalog?["strings"] as? [String: [String: Any]])
    }

    @Test func everyKeyHasASpanishTranslation() throws {
        let strings = try Self.catalogStrings()
        #expect(strings.count > 150)
        let untranslated = strings.filter { key, value in
            value["extractionState"] as? String != "stale" && ((value["localizations"] as? [String: Any])?["es"] == nil)
        }.map(\.key)
        #expect(untranslated.isEmpty, "untranslated: \(untranslated.prefix(10))")
    }
}
