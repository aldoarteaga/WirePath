import XCTest

/// End-to-end UI tests for WirePath on iPadOS (run on an iPad simulator).
final class WirePathiPadUITests: XCTestCase {
    private var app: XCUIApplication!

    private static var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchEnvironment["WIREPATH_LIBRARY_ROOT"] = NSTemporaryDirectory() + "wirepath-uitests-\(UUID().uuidString)"
        // WebRTC and audio tests open their fixtures; everything else the SIP call.
        let capture = name.contains("WebRTC") ? "webrtc-session.pcap" : name.contains("Audio") ? "audio-codecs.pcap" : "sip-call.pcap"
        app.launchEnvironment["WIREPATH_IMPORT"] = Self.repositoryRoot.appendingPathComponent("Fixtures/\(capture)").path
        app.launch()
    }

    func testOpeningACaptureShowsTheOverview() throws {
        let title = app.staticTexts["header.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 30))
        XCTAssertEqual(title.label, "sip-call.pcap")
    }

    func testPacketSelectionShowsDetails() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        let packets = app.buttons["sidebar.packets"]
        if !packets.exists { app.buttons["Back to Analyses"].tap() }
        XCTAssertTrue(packets.waitForExistence(timeout: 10))
        packets.tap()
        let list = app.tables["packets.list"]
        XCTAssertTrue(list.waitForExistence(timeout: 10))
        list.cells.element(boundBy: 0).tap()
        XCTAssertTrue(app.staticTexts["Session Initiation Protocol"].waitForExistence(timeout: 10))
    }

    func testFlowsShowTheirPackets() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        let flows = app.buttons["sidebar.flows"]
        if !flows.exists { app.buttons["Back to Analyses"].tap() }
        XCTAssertTrue(flows.waitForExistence(timeout: 10))
        flows.tap()
        let title = app.staticTexts["header.title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["Show Packets"].waitForExistence(timeout: 10))
        app.buttons["Show Packets"].tap()
        XCTAssertTrue(app.tables["packets.list"].waitForExistence(timeout: 10))
        XCTAssertEqual(title.label, "Packets")
    }

    func testWebRTCSessionShowsItsPath() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        let webrtc = app.buttons["sidebar.webrtc"]
        if !webrtc.exists { app.buttons["Back to Analyses"].tap() }
        XCTAssertTrue(webrtc.waitForExistence(timeout: 10))
        webrtc.tap()
        XCTAssertTrue(app.descendants(matching: .any)["webrtc.path"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Candidate Pairs"].exists)
        app.buttons["webrtc.showPackets"].tap()
        XCTAssertTrue(app.tables["packets.list"].waitForExistence(timeout: 10))
        XCTAssertEqual(app.staticTexts["header.title"].label, "Packets")
    }

    func testAudioOfACallPlays() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        let calls = app.buttons["sidebar.calls"]
        if !calls.exists { app.buttons["Back to Analyses"].tap() }
        XCTAssertTrue(calls.waitForExistence(timeout: 10))
        calls.tap()
        let row = app.descendants(matching: .any)["calls.row.0"]
        XCTAssertTrue(row.waitForExistence(timeout: 10))
        row.doubleTap()
        let play = app.buttons["audio.play"]
        XCTAssertTrue(play.waitForExistence(timeout: 10))
        for _ in 0..<12 where !play.isHittable { app.swipeUp() }
        play.tap()
        XCTAssertTrue(app.buttons["Pause"].waitForExistence(timeout: 5))
    }

    func testDiagnosticsReportsACleanCapture() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        let diagnostics = app.buttons["sidebar.diagnostics"]
        if !diagnostics.exists { app.buttons["Back to Analyses"].tap() }
        XCTAssertTrue(diagnostics.waitForExistence(timeout: 10))
        diagnostics.tap()
        XCTAssertTrue(app.staticTexts["No problems detected in this capture"].waitForExistence(timeout: 10))
    }

    func testLayoutAdaptsToPortraitAndLandscape() throws {
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 30))
        XCUIDevice.shared.orientation = .portrait
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 5))
        XCUIDevice.shared.orientation = .landscapeLeft
        XCTAssertTrue(app.staticTexts["header.title"].waitForExistence(timeout: 5))
    }
}
