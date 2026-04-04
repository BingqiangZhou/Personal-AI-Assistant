# Phase 4: Frontend Dead Code Cleanup + Model Consolidation

> Continuation of codebase simplification plan. Phase 4 is independent of Phases 1-3 (backend/Docker).

**Goal:** Remove unused frontend code, drop `dartz` dependency, merge duplicate models.

---

## Part A: Dead Code Deletion

### Task 4.1: Remove unused shared widgets

**Files:**
- Delete: `frontend/lib/shared/widgets/async_value_widget.dart`
- Delete: `frontend/lib/shared/widgets/lazy_indexed_stack.dart`
- Modify: `frontend/pubspec.yaml` — remove `dartz` dependency

- [ ] **Step 1: Verify zero imports**

```bash
cd frontend
grep -r "async_value_widget\|AsyncValueWidget" lib/ --include="*.dart"
grep -r "lazy_indexed_stack\|LazyIndexedStack" lib/ --include="*.dart"
grep -r "dartz" lib/ --include="*.dart"
```
All three should return no results.

- [ ] **Step 2: Delete the files**

```bash
rm frontend/lib/shared/widgets/async_value_widget.dart
rm frontend/lib/shared/widgets/lazy_indexed_stack.dart
```

- [ ] **Step 3: Remove `dartz` from pubspec.yaml**

Remove the line:
```yaml
  dartz: ^0.10.1
```

- [ ] **Step 4: Run flutter analyze and test**

```bash
cd frontend && flutter pub get && flutter analyze && flutter test
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: remove unused async_value_widget, lazy_indexed_stack, dartz dependency"
```

---

### Task 4.2: Simplify offline indicator and clean up debug logging

**Files:**
- Modify: `frontend/lib/core/offline/` — remove unused widgets
- Search and clean: debug `print()` statements across lib/

- [ ] **Step 1: Read offline indicator files**

```bash
find frontend/lib/core/offline -name "*.dart" -exec wc -l {} +
```

- [ ] **Step 2: Identify and remove unused widgets in offline/**

Read each file, check which classes/widgets are actually imported elsewhere. Remove unused ones.

- [ ] **Step 3: Clean up debug logging**

```bash
cd frontend && grep -rn "print(" lib/ --include="*.dart" | grep -v "// ignore" | grep -v "sprint"
```
Remove or convert to proper debug-only logging. Target: ~300 lines saved.

- [ ] **Step 4: Run flutter analyze and test**

```bash
cd frontend && flutter analyze && flutter test
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: remove unused offline widgets and clean up debug logging"
```

---

## Part B: Model Consolidation

### Task 4.3: Consolidate episode models

**Files:**
- Modify: `frontend/lib/features/podcast/data/models/podcast_episode_model.dart`
- Read: `frontend/lib/features/podcast/data/services/podcast_api_service.dart` — check response types

- [ ] **Step 1: Read the episode model and API service**

Understand the relationship between `PodcastEpisodeModel` and any duplicate response types like `PodcastEpisodeDetailResponse`.

- [ ] **Step 2: Merge duplicate response types into the model**

If `PodcastEpisodeDetailResponse` duplicates 30+ fields from `PodcastEpisodeModel`, consolidate to a single model with optional fields or a `copyWith` variant.

- [ ] **Step 3: Update all consumers**

Update imports and usage across providers, widgets, and services.

- [ ] **Step 4: Run build_runner and tests**

```bash
cd frontend && dart run build_runner build --delete-conflicting-outputs && flutter test
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: consolidate duplicate episode models"
```

---

### Task 4.4: Extract generic `PaginatedState<T>` base class

**Files:**
- Read: `frontend/lib/shared/models/paginated_state.dart` — may already exist
- Modify: `frontend/lib/features/podcast/data/models/podcast_state_models.dart`
- Modify: All state classes that share pagination structure

- [ ] **Step 1: Read existing paginated state and podcast state models**

Check if `PaginatedState<T>` already exists in shared/models/. If yes, verify podcast state models use it.

- [ ] **Step 2: Create or update `PaginatedState<T>`**

```dart
class PaginatedState<T> {
  final List<T> items;
  final bool isLoading;
  final bool hasMore;
  final String? error;
  final int? nextPageToken;

  const PaginatedState({
    this.items = const [],
    this.isLoading = false,
    this.hasMore = true,
    this.error,
    this.nextPageToken,
  });

  PaginatedState<T> copyWith({...}) => ...;
}
```

- [ ] **Step 3: Update podcast state models to extend PaginatedState**

Replace `PodcastFeedState`, `PodcastEpisodesState`, `PodcastSubscriptionState` with typed instances or subclasses.

- [ ] **Step 4: Run build_runner and tests**

```bash
cd frontend && dart run build_runner build --delete-conflicting-outputs && flutter test
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: extract generic PaginatedState<T>, consolidate podcast states"
```

---

## Phase 4 Verification

- [ ] **Final Phase 4 check**

```bash
cd frontend && flutter analyze && flutter test
```

Verify:
- No `dartz` in pubspec.yaml or imports
- No `async_value_widget.dart` or `lazy_indexed_stack.dart`
- `PaginatedState<T>` used by podcast state models
- No duplicate episode model fields

---

<!-- Phase 5-6: Frontend Playback Refactor + Provider Reduction — see next file -->
