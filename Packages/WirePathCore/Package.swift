// swift-tools-version: 6.0
import PackageDescription

// WirePathCore — the platform-independent analysis engine shared by the macOS and iPadOS apps.
// It depends only on Foundation (plus Compression, OSLog and AVFAudio for audio), never on SwiftUI/AppKit/UIKit.
let package = Package(
    name: "WirePathCore",
    defaultLocalization: "en",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "WirePathCore", targets: ["WirePathCore"]),
        .library(name: "WirePathFixtures", targets: ["WirePathFixtures"]),
        .executable(name: "wpcli", targets: ["wpcli"]),
        .executable(name: "wpsamplegen", targets: ["wpsamplegen"]),
        .executable(name: "wpbench", targets: ["wpbench"]),
    ],
    targets: [
        // Resources: the string catalog (English, Spanish) for diagnostics, headlines and call states.
        .target(name: "WirePathCore", resources: [.process("Resources")]),
        // Synthetic capture generator: deterministic fixtures for tests, samples and benchmarks.
        .target(name: "WirePathFixtures"),
        .executableTarget(name: "wpcli", dependencies: ["WirePathCore"]),
        .executableTarget(name: "wpsamplegen", dependencies: ["WirePathFixtures"]),
        // Engine benchmarks on large generated captures (build with -c release).
        .executableTarget(name: "wpbench", dependencies: ["WirePathCore", "WirePathFixtures"]),
        .testTarget(name: "WirePathCoreTests", dependencies: ["WirePathCore", "WirePathFixtures"]),
    ]
)
