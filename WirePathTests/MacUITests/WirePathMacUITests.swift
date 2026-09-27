import XCTest

/// End-to-end UI tests for WirePath on macOS. They launch the app with an isolated library and a small
/// fixture capture (WIREPATH_LIBRARY_ROOT / WIREPATH_IMPORT, see LaunchOptions).
final class WirePathMacUITests: XCTestCase {
    private var app: XCUIApplication!

    private static var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        let library = FileManager.default.temporaryDirectory.appendingPathComponent("wirepath-uitests-\(UUID().uuidString)")
        app.launchEnvironment["WIREPATH_LIBRARY_ROOT"] = library.path
        // WebRTC and audio tests open their fixtures; everything else the SIP call.
        let capture = name.contains("WebRTC") ? "webrtc-session.pcap" : name.contains("Audio") ? "audio-codecs.pcap" : "sip-call.pcap"
        app.launchEnvironment["WIREPATH_IMPORT"] = Self.repositoryRoot.appendingPathComponent("Fixtures/\(capture)").path
        app.launch()
    }

    override func tearDownWithError() throws {
        app.terminate()
    }

    func testOpeningACaptureShowsTheOverview() throws {
        let title = app.staticTexts["header.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 30))
        XCTAssertEqual(title.label, "sip-call.pcap")
        XCTAssertTrue(app.staticTexts["Overview"].exists)
    }

    func testNavigatingToPacketsAndFiltering() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        app.buttons["sidebar.packets"].click()
        let filter = app.textFields["packets.filter"]
        XCTAssertTrue(filter.waitForExistence(timeout: 10))
        filter.click()
        filter.typeText("sip\r")
        XCTAssertTrue(app.staticTexts["Displayed 14 of 1,011"].waitForExistence(timeout: 10))
    }

    func testFlowsShowTheirPackets() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        app.buttons["sidebar.flows"].click()
        let show = app.buttons["Show Packets"]
        XCTAssertTrue(show.waitForExistence(timeout: 10))
        show.click()
        XCTAssertTrue(app.textFields["packets.filter"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["header.title"].label, "Packets")
    }

    func testWebRTCSessionShowsItsPath() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        app.buttons["sidebar.webrtc"].click()
        // The path is one accessibility element reading the state, both candidates and the checks (on macOS the
        // combined text is the static text's value rather than its label).
        let path = app.descendants(matching: .any)["webrtc.path"]
        XCTAssertTrue(path.waitForExistence(timeout: 10))
        XCTAssertTrue(((path.value as? String) ?? path.label).contains("Selected candidate pair"), path.debugDescription)
        XCTAssertTrue(app.staticTexts["Candidate Pairs"].exists)
        app.buttons["webrtc.showPackets"].click()
        XCTAssertTrue(app.textFields["packets.filter"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["header.title"].label, "Packets")
    }

    func testAudioOfACallPlays() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        app.buttons["sidebar.calls"].click()
        let row = app.descendants(matching: .any)["calls.row.0"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.doubleClick()
        let card = app.descendants(matching: .any)["audio.card"]
        XCTAssertTrue(card.waitForExistence(timeout: 10))
        let play = app.buttons["audio.play"]
        for _ in 0..<10 where !play.isHittable { app.scrollViews.firstMatch.scroll(byDeltaX: 0, deltaY: -400) }
        play.click()
        XCTAssertTrue(app.buttons["Pause"].waitForExistence(timeout: 5))
    }

    func testDiagnosticsReportsACleanCapture() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        app.buttons["sidebar.diagnostics"].click()
        XCTAssertTrue(app.staticTexts["No problems detected in this capture"].waitForExistence(timeout: 10))
    }

    func testCallNavigation() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        app.buttons["sidebar.calls"].click()
        let row = app.descendants(matching: .any)["calls.row.0"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.doubleClick()
        let title = app.staticTexts["header.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10))
        let investigating = NSPredicate(format: "label BEGINSWITH 'Call '")
        XCTAssertEqual(XCTWaiter.wait(for: [expectation(for: investigating, evaluatedWith: title)], timeout: 10), .completed)
        XCTAssertTrue(app.staticTexts["SIP Flow"].exists)
    }
}
