# Phase 5-6: Frontend Playback Refactor + Provider Reduction

> Continuation of codebase simplification plan. Phase 4 should be complete before starting.

**Goal:** Split monolithic audio playback into independent notifiers. Consolidate 59 providers → ~30.

---

## Phase 5: Playback Refactor

### Current State

The audio playback system has these files:
- `audio_handler.dart` — core audio handler
- `audio_persistence_notifier.dart` — progress save
- `audio_playback_rate_notifier.dart` — playback speed
- `audio_playback_selectors.dart` — Riverpod selectors
- `audio_server_sync_notifier.dart` — server sync
- `audio_sleep_timer_notifier.dart` — sleep timer
- `podcast_playback_helpers.dart` — helper functions
- `podcast_playback_queue_controller.dart` — queue controller
- `podcast_player_host_layout_provider.dart` — UI layout
- `podcast_player_ui_state.dart` — UI state model

Plus supporting models in `data/models/audio_player_state_model.dart`.

### Task 5.1: Map current playback architecture

**Files:**
- Read all 10 audio/playback files listed above
- Read: `frontend/lib/features/podcast/data/models/audio_player_state_model.dart`

- [ ] **Step 1: Read all playback files**

Document:
- Which notifier depends on which other notifier via `ref.watch` / `ref.read`
- What state each notifier holds
- How they communicate (shared state, method calls, events)

- [ ] **Step 2: Draw dependency graph**

Map out the notifier dependency graph. Identify cycles or tight coupling points.

- [ ] **Step 3: Design the 4-notifier split**

Based on the design doc target:
| Notifier | Responsibility | Source Files |
|----------|---------------|--------------|
| `AudioPlayerNotifier` | Core playback + state | `audio_handler.dart` + parts of `podcast_playback_helpers.dart` |
| `PlaybackQueueNotifier` | Queue management | `podcast_playback_queue_controller.dart` |
| `PlaybackPersistenceNotifier` | Progress save + server sync | `audio_persistence_notifier.dart` + `audio_server_sync_notifier.dart` |
| `SleepTimerNotifier` | Sleep timer | `audio_sleep_timer_notifier.dart` |

---

### Task 5.2: Create `AudioPlayerNotifier` (core playback)

**Files:**
- Create: `frontend/lib/features/podcast/presentation/providers/audio_player_notifier.dart`
- Modify: `frontend/lib/features/podcast/data/models/audio_player_state_model.dart` — keep/simplify

- [ ] **Step 1: Extract core playback state and logic**

Create `AudioPlayerNotifier` that owns:
- Current episode, position, duration
- Play/pause/seek/stop methods
- Playback state enum (playing, paused, loading, completed)

The notifier should use `ref` to communicate with other notifiers rather than sharing private state.

- [ ] **Step 2: Write tests**

```dart
// test/unit/providers/audio_player_notifier_test.dart
void main() {
  test('initial state is idle', () {
    // ...
  });

  test('play sets state to playing', () {
    // ...
  });
}
```

- [ ] **Step 3: Implement the notifier**

- [ ] **Step 4: Run tests**

```bash
cd frontend && flutter test test/unit/providers/audio_player_notifier_test.dart
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: create independent AudioPlayerNotifier"
```

---

### Task 5.3: Create `PlaybackQueueNotifier`

**Files:**
- Create: `frontend/lib/features/podcast/presentation/providers/playback_queue_notifier.dart`

- [ ] **Step 1: Extract queue logic from `podcast_playback_queue_controller.dart`**

The queue notifier should own:
- Queue list, current index
- Add/remove/reorder methods
- Next/previous navigation

- [ ] **Step 2: Write tests**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run tests**

```bash
cd frontend && flutter test test/unit/providers/playback_queue_notifier_test.dart
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: create independent PlaybackQueueNotifier"
```

---

### Task 5.4: Create `PlaybackPersistenceNotifier` (merge persistence + server sync)

**Files:**
- Create: `frontend/lib/features/podcast/presentation/providers/playback_persistence_notifier.dart`

- [ ] **Step 1: Merge `audio_persistence_notifier.dart` and `audio_server_sync_notifier.dart`**

The persistence notifier should own:
- Local progress save (periodic)
- Server sync (debounced)
- Offline queue for pending syncs

- [ ] **Step 2: Write tests**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: create PlaybackPersistenceNotifier merging persistence and sync"
```

---

### Task 5.5: Create `SleepTimerNotifier`

**Files:**
- Create: `frontend/lib/features/podcast/presentation/providers/sleep_timer_notifier.dart`

- [ ] **Step 1: Extract from `audio_sleep_timer_notifier.dart`**

The sleep timer notifier should own:
- Timer countdown state
- Set/cancel timer methods
- Callback when timer expires (pause playback via `ref.read(audioPlayerNotifierProvider.notifier).pause()`)

- [ ] **Step 2: Write tests**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Run tests**

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: create independent SleepTimerNotifier"
```

---

### Task 5.6: Wire new notifiers into UI, delete old files

**Files:**
- Modify: All widget files that import old audio providers
- Delete: Old notifier files that have been replaced
- Modify: `podcast_playback_providers.dart` — update provider registrations

- [ ] **Step 1: Update all UI imports**

Search for imports of old providers:
```bash
cd frontend && grep -rn "audio_persistence_notifier\|audio_server_sync_notifier\|audio_sleep_timer_notifier\|podcast_playback_queue_controller\|podcast_playback_helpers" lib/ --include="*.dart"
```

Replace with imports of new notifier files.

- [ ] **Step 2: Update `podcast_playback_providers.dart`**

Register the new 4 notifiers. Remove old provider registrations.

- [ ] **Step 3: Delete old files**

```bash
rm frontend/lib/features/podcast/presentation/providers/audio_persistence_notifier.dart
rm frontend/lib/features/podcast/presentation/providers/audio_server_sync_notifier.dart
rm frontend/lib/features/podcast/presentation/providers/audio_sleep_timer_notifier.dart
rm frontend/lib/features/podcast/presentation/providers/podcast_playback_queue_controller.dart
rm frontend/lib/features/podcast/presentation/providers/podcast_playback_helpers.dart
```

Keep: `audio_handler.dart` (may still be needed as bridge to audio_service package), `audio_playback_rate_notifier.dart` (if still useful), `audio_playback_selectors.dart` (if still useful).

- [ ] **Step 4: Run build_runner, analyze, and test**

```bash
cd frontend && dart run build_runner build --delete-conflicting-outputs && flutter analyze && flutter test
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: wire new playback notifiers into UI, remove old files"
```

---

## Phase 6: Provider Reduction (59 → ~30)

### Task 6.1: Audit all podcast providers

**Files:**
- Read: All 32 files in `frontend/lib/features/podcast/presentation/providers/`

- [ ] **Step 1: List all providers and their sizes**

```bash
cd frontend && wc -l lib/features/podcast/presentation/providers/*.dart | sort -n
```

- [ ] **Step 2: Classify each provider**

| Category | Action |
|----------|--------|
| Trivial (< 20 lines) | Merge into related provider file |
| Barrel export only | Delete, import directly |
| Generated `.g.dart` | Keep, but check if source is needed |
| Substantial standalone | Keep |

---

### Task 6.2: Merge trivial providers

**Files:**
- Delete: `podcast_core_providers.dart` (26 lines) — merge into a parent
- Delete: `episode_providers_cache.dart` (16 lines) — merge into episode providers
- Merge any other providers < 30 lines into related files

- [ ] **Step 1: Read each trivial provider file**

- [ ] **Step 2: Move content to related provider files**

For each trivial provider:
1. Move its provider definitions to the most closely related larger provider file
2. Update all imports that reference the trivial file
3. Delete the trivial file

- [ ] **Step 3: Run build_runner and tests**

```bash
cd frontend && dart run build_runner build --delete-conflicting-outputs && flutter analyze && flutter test
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: merge trivial podcast providers into related files"
```

---

### Task 6.3: Remove barrel export files

**Files:**
- Check: `podcast_providers.dart` — if it only re-exports, replace consumers with direct imports

- [ ] **Step 1: Identify barrel files**

```bash
cd frontend && grep -l "export '" lib/features/podcast/presentation/providers/*.dart
```

- [ ] **Step 2: Replace barrel imports with direct imports**

For each barrel file:
1. Find all files that import it
2. Replace with direct imports of the specific providers needed
3. Delete the barrel file

- [ ] **Step 3: Run build_runner, analyze, and test**

```bash
cd frontend && dart run build_runner build --delete-conflicting-outputs && flutter analyze && flutter test
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: remove barrel export files, use direct imports"
```

---

### Task 6.4: Final cleanup pass

- [ ] **Step 1: Count remaining provider files**

```bash
find frontend/lib/features/podcast/presentation/providers -name "*.dart" ! -name "*.g.dart" | wc -l
```
Target: ~30 non-generated files.

- [ ] **Step 2: Verify no unused providers**

Check each remaining provider is actually watched/read somewhere:
```bash
cd frontend && for f in lib/features/podcast/presentation/providers/*.dart; do
  name=$(basename "$f" .dart)
  if [ "$name" != "__" ]; then
    count=$(grep -r "$name" lib/ --include="*.dart" | grep -v "^[^:]*$f:" | grep -v ".g.dart" | wc -l)
    if [ "$count" -lt 2 ]; then
      echo "LOW USAGE: $name ($count references)"
    fi
  fi
done
```

- [ ] **Step 3: Final flutter test run**

```bash
cd frontend && flutter analyze && flutter test
```

- [ ] **Step 4: Final commit**

```bash
git add -A && git commit -m "refactor: finalize provider reduction, cleanup unused providers"
```

---

## Phase 5-6 Verification

- [ ] **Full frontend verification**

```bash
cd frontend
dart run build_runner build --delete-conflicting-outputs
flutter analyze
flutter test
```

Verify:
- 4 independent playback notifiers exist
- Old monolithic files deleted
- ~30 provider files (non-generated)
- No barrel exports
- All tests pass

---

## Final Verification (All Phases)

- [ ] **Backend**
```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Frontend**
```bash
cd frontend && flutter analyze && flutter test
```

- [ ] **Docker (if applicable)**
```bash
cd docker && docker compose up -d && sleep 10 && curl http://localhost:8000/api/v1/health
```
