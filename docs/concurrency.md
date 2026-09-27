# Concurrency

WirePath builds with Swift 6 strict concurrency. The rules are:
- UI state lives on the main actor.
- Analysis runs in structured tasks off the main actor.
- Shared engine objects are either immutable or confined to one task.

## Analysis pipeline

```
LibraryModel (@MainActor)
   └─ Task { AnalysisEngine.analyze(...) }            one task per analysis, cancellable
         CaptureReader.readBatch (32,768 frames)       sequential
         FrameDecoding.decodeBatch                      withTaskGroup: 4,096-frame chunks on every core
         CaptureAnalyzer.ingest                         sequential, single task (stateful)
         progress callback  ──▶ Task { @MainActor in item.progress = … }   throttled to 10 per second
```

- `CaptureFile` is immutable after init (`@unchecked Sendable`: the mapping is read-only), so the parallel decode
  reads it without locks.
- `CaptureAnalyzer` is a class used from exactly one task at a time and is never shared.
- Cancellation is checked between batches, and inside gzip expansion and local copies (`Task.isCancelled`).
  `LibraryModel.cancelAnalysis` cancels the task, and the analysis ends as `.cancelled` with its partial files
  removed.
- Results are persisted and loaded in `nonisolated` async functions, so JSON work stays off the main actor.

## Packet Inspector

- `PacketInspectorModel` (@MainActor) owns a `PacketStore`. The store is `@unchecked Sendable`: the index and
  capture mappings are read-only, and the lazily loaded flow list is guarded by a lock.
- Filtering runs in a task that awaits `PacketStore.filter`, a nonisolated `async` function. Swift 6 language mode
  without `NonisolatedNonsendingByDefault` runs such functions on the global concurrent executor, so the scan of the
  mapped index never blocks the main actor. If that upcoming feature is ever enabled, these functions must be marked
  `@concurrent`. The task is cancelled when the filter changes and checks for cancellation every 65,536 packets. The
  list reloads when the result arrives.
- Rows are decoded only for visible cells. The protocol tree and hex view are decoded for the selected packet only.

## Rules for new code

- Prefer `async/await`, `Task`, `TaskGroup` and `AsyncSequence`. `DispatchQueue` appears only where AppKit requires
  a main-queue hop (window chrome).
- Never block the main actor on file I/O or parsing. View models start a task and publish the result.
- Engine types are `Sendable` value types, or classes whose mutable state is confined to one task or protected by
  a lock. Use `@unchecked Sendable` only with a comment explaining why it is safe.
- No global mutable singletons. Dependencies (library, defaults) are passed in, which is also what the tests do.
