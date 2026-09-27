import WirePathCore
import Foundation

/// Number and time formats used by the design (24-hour clock, tabular durations).
enum Formatters {
    /// What the analysis is doing, for progress rows.
    static func phase(_ phase: AnalysisProgress.Phase?) -> String {
        switch phase {
        case .preparing?: return String(localized: "Preparing")
        case .copying?: return String(localized: "Copying")
        case .decompressing?: return String(localized: "Decompressing")
        case .correlating?: return String(localized: "Correlating calls")
        case .finishing?: return String(localized: "Finishing")
        case .reading?, nil: return String(localized: "Analyzing")
        }
    }

    /// 09:42:15
    static let clockTime = Date.VerbatimFormatStyle(
        format: "\(hour: .twoDigits(clock: .twentyFourHour, hourCycle: .zeroBased)):\(minute: .twoDigits):\(second: .twoDigits)",
        timeZone: .current, calendar: .current)

    private static let millisFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter
    }()

    private static let dayTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d, HH:mm:ss"
        return formatter
    }()

    private static let shortDayFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d"
        return formatter
    }()

    private static let hourMinuteFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        return formatter
    }()

    static func clock(_ timestamp: Timestamp) -> String { timestamp.date.formatted(clockTime) }
    static func clockMillis(_ timestamp: Timestamp) -> String { millisFormatter.string(from: timestamp.date) }
    static func dayTime(_ timestamp: Timestamp) -> String { dayTimeFormatter.string(from: timestamp.date) }

    /// "Sep 26, 09:14:02 – 11:48:20"
    static func range(_ start: Timestamp?, _ end: Timestamp?) -> String {
        guard let start else { return "" }
        guard let end else { return dayTime(start) }
        let sameDay = Calendar.current.isDate(start.date, inSameDayAs: end.date)
        return "\(dayTime(start)) – \(sameDay ? clock(end) : dayTime(end))"
    }

    /// Sidebar relative date: "Today, 09:14", "Yesterday, 16:40", "Sep 24".
    static func relativeDay(_ date: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDateInToday(date) { return String(localized: "Today, \(hourMinuteFormatter.string(from: date))") }
        if calendar.isDateInYesterday(date) { return String(localized: "Yesterday, \(hourMinuteFormatter.string(from: date))") }
        return shortDayFormatter.string(from: date)
    }

    /// 02:34:18 (always h:mm:ss)
    static func hms(_ seconds: Double) -> String {
        let total = Int(seconds.rounded(.down))
        return String(format: "%02d:%02d:%02d", total / 3600, (total % 3600) / 60, total % 60)
    }

    /// 03:12 for durations under an hour, otherwise 1:03:12.
    static func duration(_ seconds: Double) -> String {
        let total = Int(seconds.rounded())
        if total >= 3600 { return String(format: "%d:%02d:%02d", total / 3600, (total % 3600) / 60, total % 60) }
        return String(format: "%02d:%02d", total / 60, total % 60)
    }

    /// 01:17.386
    static func durationMillis(_ seconds: Double) -> String {
        let millis = Int((seconds * 1000).rounded())
        let minutes = millis / 60_000
        let rest = Double(millis % 60_000) / 1000
        return String(format: "%02d:%06.3f", minutes, rest)
    }

    /// "2 h 34 min", "12 min", "45 s"
    static func spoken(_ seconds: Double) -> String {
        let total = Int(seconds.rounded())
        if total >= 3600 { return "\(total / 3600) h \((total % 3600) / 60) min" }
        if total >= 60 { return "\(total / 60) min" }
        return "\(total) s"
    }

    static func count(_ value: Int) -> String { value.formatted(.number) }

    /// 1.2M, 842K, 7,447
    static func compact(_ value: Int) -> String {
        if value >= 1_000_000 { return String(format: "%.1fM", Double(value) / 1_000_000) }
        if value >= 100_000 { return "\(value / 1000)K" }
        return value.formatted(.number)
    }

    static func bytes(_ value: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .file
        formatter.allowsNonnumericFormatting = false  // "0 bytes", not "Zero KB"
        return formatter.string(fromByteCount: value)
    }

    /// Bit rates in decimal units (kbit/s, Mbit/s), as network rates are quoted.
    static func bits(_ bitsPerSecond: Double) -> String {
        guard bitsPerSecond.isFinite, bitsPerSecond >= 0 else { return "—" }
        switch bitsPerSecond {
        case ..<1_000: return String(format: "%.0f bit", bitsPerSecond)
        case ..<1_000_000: return String(format: "%.1f kbit", bitsPerSecond / 1_000)
        case ..<1_000_000_000: return String(format: "%.2f Mbit", bitsPerSecond / 1_000_000)
        default: return String(format: "%.2f Gbit", bitsPerSecond / 1_000_000_000)
        }
    }

    static func mos(_ value: Double?) -> String { value.map { String(format: "%.2f", $0) } ?? "—" }
    static func ms(_ value: Double?) -> String { value.map { String(format: "%.1f ms", $0) } ?? "—" }
    static func percent(_ value: Double?) -> String { value.map { String(format: "%.2f%%", $0) } ?? "—" }
}
