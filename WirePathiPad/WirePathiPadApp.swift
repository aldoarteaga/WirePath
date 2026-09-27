import SwiftUI
import WirePathCore
import WirePathUI

@main
struct WirePathiPadApp: App {
    @State private var library = LibraryModel()

    var body: some Scene {
        // One scene per window: Stage Manager and Split View can show several analyses side by side,
        // each with its own navigation state; the analysis library is shared.
        WindowGroup(for: UUID.self) { $analysisID in
            IPadRootView(library: library, initialAnalysis: analysisID)
                .environment(library)
        }
        .commands { WirePathCommands(library: library) }
    }
}
