// swift-tools-version: 6.0
import PackageDescription

// WirePathUI — SwiftUI views, view models, theme and components shared by the macOS and iPadOS apps.
// All analysis comes from WirePathCore; platform differences are isolated in small adapters (Platform/).
let package = Package(
    name: "WirePathUI",
    defaultLocalization: "en",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "WirePathUI", targets: ["WirePathUI"]),
    ],
    dependencies: [
        .package(path: "../WirePathCore"),
    ],
    targets: [
        .target(name: "WirePathUI", dependencies: [.product(name: "WirePathCore", package: "WirePathCore")]),
        .testTarget(name: "WirePathUITests", dependencies: [
            "WirePathUI",
            .product(name: "WirePathFixtures", package: "WirePathCore"),
        ]),
    ]
)
