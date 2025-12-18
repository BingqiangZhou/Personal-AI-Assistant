import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:meta/meta.dart';

import '../../../core/constants/app_constants.dart';
import '../../../core/providers/core_providers.dart';
import '../models/knowledge_item_model.dart';

// Knowledge Items State
@immutable
class KnowledgeItemsState {
  final bool isLoading;
  final List<KnowledgeItemModel> items;
  final int totalCount;
  final int currentPage;
  final bool hasMorePages;
  final String? error;
  final String? searchQuery;
  final String? selectedCategory;
  final List<String> selectedTags;

  const KnowledgeItemsState({
    this.isLoading = false,
    this.items = const [],
    this.totalCount = 0,
    this.currentPage = 1,
    this.hasMorePages = true,
    this.error,
    this.searchQuery,
    this.selectedCategory,
    this.selectedTags = const [],
  });

  KnowledgeItemsState copyWith({
    bool? isLoading,
    List<KnowledgeItemModel>? items,
    int? totalCount,
    int? currentPage,
    bool? hasMorePages,
    String? error,
    String? searchQuery,
    String? selectedCategory,
    List<String>? selectedTags,
  }) {
    return KnowledgeItemsState(
      isLoading: isLoading ?? this.isLoading,
      items: items ?? this.items,
      totalCount: totalCount ?? this.totalCount,
      currentPage: currentPage ?? this.currentPage,
      hasMorePages: hasMorePages ?? this.hasMorePages,
      error: error ?? this.error,
      searchQuery: searchQuery ?? this.searchQuery,
      selectedCategory: selectedCategory ?? this.selectedCategory,
      selectedTags: selectedTags ?? this.selectedTags,
    );
  }
}

// Knowledge Categories State
@immutable
class KnowledgeCategoriesState {
  final bool isLoading;
  final List<KnowledgeCategoryModel> categories;
  final String? error;

  const KnowledgeCategoriesState({
    this.isLoading = false,
    this.categories = const [],
    this.error,
  });

  KnowledgeCategoriesState copyWith({
    bool? isLoading,
    List<KnowledgeCategoryModel>? categories,
    String? error,
  }) {
    return KnowledgeCategoriesState(
      isLoading: isLoading ?? this.isLoading,
      categories: categories ?? this.categories,
      error: error ?? this.error,
    );
  }
}

// Knowledge Items Provider
final knowledgeItemsProvider = StateNotifierProvider<KnowledgeItemsNotifier, KnowledgeItemsState>((ref) {
  return KnowledgeItemsNotifier(ref);
});

class KnowledgeItemsNotifier extends StateNotifier<KnowledgeItemsState> {
  final Ref _ref;

  KnowledgeItemsNotifier(this._ref) : super(const KnowledgeItemsState()) {
    _loadKnowledgeItems();
  }

  // Load knowledge items
  Future<void> _loadKnowledgeItems({
    bool loadMore = false,
    String? searchQuery,
    String? category,
    List<String>? tags,
  }) async {
    try {
      final nextPage = loadMore ? state.currentPage + 1 : 1;

      if (!loadMore) {
        state = state.copyWith(
          isLoading: true,
          error: null,
          searchQuery: searchQuery,
          selectedCategory: category,
          selectedTags: tags ?? [],
        );
      }

      final apiService = _ref.read(apiServiceProvider);
      final response = await apiService.getKnowledgeItems(
        page: nextPage,
        limit: AppConstants.defaultPageSize,
        category: category ?? state.selectedCategory,
        search: searchQuery ?? state.searchQuery,
      );

      final allItems = loadMore ? [...state.items, ...response.items] : response.items;

      state = state.copyWith(
        isLoading: false,
        items: allItems,
        totalCount: response.totalCount,
        currentPage: response.currentPage,
        hasMorePages: response.hasNextPage,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  // Load more items
  Future<void> loadMoreItems() {
    if (state.hasMorePages && !state.isLoading) {
      return _loadKnowledgeItems(loadMore: true);
    }
    return Future.value();
  }

  // Search knowledge items
  Future<void> searchItems(String query) {
    return _loadKnowledgeItems(searchQuery: query);
  }

  // Filter by category
  Future<void> filterByCategory(String category) {
    return _loadKnowledgeItems(category: category);
  }

  // Filter by tags
  Future<void> filterByTags(List<String> tags) {
    return _loadKnowledgeItems(tags: tags);
  }

  // Clear filters
  Future<void> clearFilters() {
    return _loadKnowledgeItems(searchQuery: '', category: null, tags: []);
  }

  // Create knowledge item
  Future<KnowledgeItemModel> createKnowledgeItem({
    required String title,
    String? description,
    required String content,
    String? summary,
    required String category,
    List<String>? tags,
    String? author,
    String? source,
    String? sourceUrl,
    required KnowledgeItemType type,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      final apiService = _ref.read(apiServiceProvider);
      final newItem = await apiService.createKnowledgeItem({
        'title': title,
        'description': description,
        'content': content,
        'summary': summary,
        'category': category,
        'tags': tags ?? [],
        'author': author,
        'source': source,
        'source_url': sourceUrl,
        'type': type.name,
        'metadata': metadata ?? {},
      });

      final updatedItems = [newItem, ...state.items];
      state = state.copyWith(
        items: updatedItems,
        totalCount: state.totalCount + 1,
      );

      return newItem;
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Update knowledge item
  Future<void> updateKnowledgeItem({
    required String itemId,
    String? title,
    String? description,
    String? content,
    String? summary,
    String? category,
    List<String>? tags,
    String? author,
    String? source,
    String? sourceUrl,
    KnowledgeItemType? type,
    KnowledgeItemStatus? status,
    Map<String, dynamic>? metadata,
  }) async {
    try {
      final apiService = _ref.read(apiServiceProvider);
      final updatedItem = await apiService.updateKnowledgeItem(itemId, {
        'title': title,
        'description': description,
        'content': content,
        'summary': summary,
        'category': category,
        'tags': tags,
        'author': author,
        'source': source,
        'source_url': sourceUrl,
        'type': type?.name,
        'status': status?.name,
        'metadata': metadata,
      });

      final updatedItems = state.items.map((item) {
        return item.id == itemId ? updatedItem : item;
      }).toList();

      state = state.copyWith(items: updatedItems);
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Delete knowledge item
  Future<void> deleteKnowledgeItem(String itemId) async {
    try {
      final apiService = _ref.read(apiServiceProvider);
      await apiService.deleteKnowledgeItem(itemId);

      final updatedItems = state.items.where((item) => item.id != itemId).toList();
      state = state.copyWith(
        items: updatedItems,
        totalCount: state.totalCount - 1,
      );
    } catch (e) {
      state = state.copyWith(error: e.toString());
      rethrow;
    }
  }

  // Refresh items
  Future<void> refreshItems() {
    return _loadKnowledgeItems();
  }

  // Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Knowledge Categories Provider
final knowledgeCategoriesProvider = StateNotifierProvider<KnowledgeCategoriesNotifier, KnowledgeCategoriesState>((ref) {
  return KnowledgeCategoriesNotifier(ref);
});

class KnowledgeCategoriesNotifier extends StateNotifier<KnowledgeCategoriesState> {
  final Ref _ref;

  KnowledgeCategoriesNotifier(this._ref) : super(const KnowledgeCategoriesState()) {
    _loadCategories();
  }

  // Load categories
  Future<void> _loadCategories() async {
    try {
      state = state.copyWith(isLoading: true);

      final apiService = _ref.read(apiServiceProvider);
      final categoriesData = await apiService.getKnowledgeCategories();

      final categories = categoriesData.map((data) => KnowledgeCategoryModel.fromJson(data)).toList();

      state = state.copyWith(
        isLoading: false,
        categories: categories,
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  // Refresh categories
  Future<void> refreshCategories() {
    return _loadCategories();
  }

  // Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

// Individual Knowledge Item Provider
final knowledgeItemProvider = FutureProvider.family<KnowledgeItemModel?, String>((ref, itemId) async {
  try {
    final apiService = ref.read(apiServiceProvider);
    return await apiService.getKnowledgeItem(itemId);
  } catch (e) {
    return null;
  }
});

// Search knowledge provider
final searchKnowledgeProvider = FutureProvider.family<List<KnowledgeItemModel>, String>((ref, query) async {
  if (query.trim().isEmpty) return [];

  try {
    final apiService = ref.read(apiServiceProvider);
    final response = await apiService.searchKnowledge({
      'query': query,
      'limit': 10,
      'use_semantic_search': true,
    });

    return response.results;
  } catch (e) {
    return [];
  }
});