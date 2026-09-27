# UI architecture

Code: `Packages/WirePathUI/Sources/WirePathUI`, `WirePathMac/`, `WirePathiPad/`.

## Structure

```
App (WirePathMacApp / WirePathiPadApp)
 └─ LibraryModel (@Observable, @MainActor)   shared: analysis library, imports, running analyses, recents
     └─ Window root (MacRootView / IPadRootView)
         └─ WindowModel (@Observable)          per window: selection, navigation history, inspector, exports
             └─ AnalysisDocument               per capture: results, filters, selection, inspector models
                 └─ PacketInspectorModel       per call scope: filter, positions, selection, dissection
```

Screens (`Screens/…`) read these models and call their methods. They never touch capture files.

## Shared screens, adaptive layout

Every screen is shared by macOS and iPadOS. Layout follows the width actually available, measured with
`onGeometryChange` (`LayoutWidth`: compact < 760 pt ≤ regular < 1180 pt ≤ wide). The measurement is taken where the
content is laid out, so for example the Overview measures its card area without the inspector. This covers iPad
mini portrait, Split View, Slide Over, Stage Manager windows and large Mac windows without device checks.

- Compact width: one column, essential table columns, details presented as sheets. The iPad split view collapses
  into a stack with a back affordance in the header.
- Regular width: stacked cards and two-column arrangements where they fit.
- Wide: the full desktop layout of the design.

## Platform specifics

| | macOS | iPadOS |
|---|---|---|
| Root | Custom sidebar + detail, design title-bar band with repositioned traffic lights (`WindowChrome`) | `NavigationSplitView` with the same sidebar and screens |
| Packet list | `NSTableView` | `UITableView` |
| Menus & shortcuts | Menu bar (`WirePathCommands`), full shortcut set | Hardware-keyboard shortcuts that don't clash with system ones (`macKeyboardShortcut` elsewhere) |
| Opening files | Open…, drag & drop, Finder, Dock, Open Recent (bookmarks) | Files picker, drag & drop, `onOpenURL` (Files, iCloud Drive, USB, AirDrop, Open In) |
| Inspector | Trailing panel | Trailing panel, or a sheet in compact width |

## Design identity

Colours, type and spacing come from `Theme` (tokens for dark and light, `.dynamic(dark:light:)`), icons from
`Icons` (paths from the design), and components from `Components/` (cards, data tables, segmented controls, metric
strips). The design canvas in `design/` is the source of truth. New screens reuse these components rather than
system defaults, so both platforms feel like the same product.

## Accessibility and localization

- Interactive rows are accessibility elements with button traits and named actions (for example, call rows expose
  "Investigate" and "Show Packets"). Icon-only controls have labels as well as tooltips. Status is conveyed with icons
  and text, never colour alone.
- Every animation goes through `withAnimationIfAllowed`, which applies changes without motion when Reduce Motion is
  on.
- Every table: ↑↓ move, ↩ opens, a context menu holds the row's actions, and Edit ▸ Copy (⌘C) copies the selected row
  as tab-separated text. Menu commands cover sections (⌘1…), navigation (⌘[ ⌘], ⌘↑ ⌘↓ between calls), search,
  display filter, export and re-analysis.
- Text uses the design's fixed point sizes on both platforms, because the dense tables and cards are laid out for
  them. iPadOS Dynamic Type does not scale WirePath's text yet.
- English and Spanish. App strings live in `Localization/Localizable.xcstrings` (shared by both app targets);
  WirePathCore's own strings (findings, headlines, call states, errors) in its package resource catalog, looked up
  through `CoreLocalization.bundle`. Plurals use catalog variations. Words that translate differently by context use
  keyed strings (`String(localized: "ice.pair.selected", defaultValue: "Selected")`).
- `scripts/localize.sh` re-extracts strings from both packages and syncs the catalogs;
  `scripts/check-localization.py` fails on stale keys or missing Spanish translations.
- Core text is persisted in the analysis language (`AnalysisManifest.language`); `LibraryModel.loadDocument`
  re-analyzes on a mismatch when the capture is reachable, and otherwise opens the analysis as saved.

## Testing

- View models: `Packages/WirePathUI/Tests` (Swift Testing) with synthetic captures.
- End to end: `WirePathTests/MacUITests` and `WirePathTests/iPadUITests` (XCUITest) launch the app with
  `WIREPATH_LIBRARY_ROOT` and `WIREPATH_IMPORT` (Debug only). macOS UI tests need an unlocked screen.
- Visual: `scripts/snapshot.sh` (macOS, rendered in the app) and `scripts/ipad-snapshot.sh` (simulator screenshots),
  compared against the design boards.
