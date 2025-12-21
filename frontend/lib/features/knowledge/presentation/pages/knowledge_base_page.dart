import 'package:flutter/material.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';

/// Material Design 3自适应Knowledge页面
class KnowledgeBasePage extends StatefulWidget {
  const KnowledgeBasePage({super.key});

  @override
  State<KnowledgeBasePage> createState() => _KnowledgeBasePageState();
}

class _KnowledgeBasePageState extends State<KnowledgeBasePage> {
  final TextEditingController _searchController = TextEditingController();
  String _selectedCategory = 'All';
  String _sortBy = 'Recently Updated';

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题和操作区域
          Row(
            children: [
              Expanded(
                child: Text(
                  'Knowledge Base',
                  style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                ),
              ),
              const SizedBox(width: 16),
              Row(
                children: [
                  // 导入按钮
                  FilledButton.tonal(
                    onPressed: () {
                      _showImportDialog(context);
                    },
                    child: const Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.upload, size: 16),
                        SizedBox(width: 4),
                        Text('Import'),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),
                  // 创建按钮
                  FilledButton.icon(
                    onPressed: () {
                      _showCreateDialog(context);
                    },
                    icon: const Icon(Icons.add),
                    label: const Text('Create'),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 24),

          // 搜索和筛选栏
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Column(
              children: [
                // 搜索框
                TextFormField(
                  controller: _searchController,
                  decoration: InputDecoration(
                    hintText: 'Search knowledge base...',
                    prefixIcon: const Icon(Icons.search),
                    suffixIcon: IconButton(
                      onPressed: () {
                        _searchController.clear();
                        _performSearch('');
                      },
                      icon: const Icon(Icons.clear),
                    ),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(8),
                    ),
                    contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  ),
                ),
                const SizedBox(height: 16),

                // 筛选和排序选项
                Row(
                  children: [
                    // 分类筛选
                    Expanded(
                      child: DropdownButtonFormField<String>(
                        value: _selectedCategory,
                        decoration: InputDecoration(
                          labelText: 'Category',
                          prefixIcon: const Icon(Icons.category),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                        ),
                        items: const [
                          DropdownMenuItem(value: 'All', child: Text('All Categories')),
                          DropdownMenuItem(value: 'Documents', child: Text('Documents')),
                          DropdownMenuItem(value: 'Articles', child: Text('Articles')),
                          DropdownMenuItem(value: 'Notes', child: Text('Notes')),
                          DropdownMenuItem(value: 'Code', child: Text('Code Snippets')),
                          DropdownMenuItem(value: 'References', child: Text('References')),
                          DropdownMenuItem(value: 'Resources', child: Text('Resources')),
                        ],
                        onChanged: (value) {
                          setState(() {
                            _selectedCategory = value!;
                            _filterKnowledge();
                          });
                        },
                      ),
                    ),
                    const SizedBox(width: 16),
                    // 排序选项
                    Expanded(
                      child: DropdownButtonFormField<String>(
                        value: _sortBy,
                        decoration: InputDecoration(
                          labelText: 'Sort by',
                          prefixIcon: const Icon(Icons.sort),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(8),
                          ),
                          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                        ),
                        items: const [
                          DropdownMenuItem(value: 'Recently Updated', child: Text('Recently Updated')),
                          DropdownMenuItem(value: 'Most Viewed', child: Text('Most Viewed')),
                          DropdownMenuItem(value: 'Name (A-Z)', child: Text('Name (A-Z)')),
                          DropdownMenuItem(value: 'Name (Z-A)', child: Text('Name (Z-A)')),
                          DropdownMenuItem(value: 'Size', child: Text('File Size')),
                        ],
                        onChanged: (value) {
                          setState(() {
                            _sortBy = value!;
                            _sortKnowledge();
                          });
                        },
                      ),
                    ),
                    const SizedBox(width: 16),
                    // 视图切换按钮
                    SegmentedButton<String>(
                      segments: const [
                        ButtonSegment(value: 'grid', icon: Icon(Icons.grid_view), tooltip: 'Grid View'),
                        ButtonSegment(value: 'list', icon: Icon(Icons.list), tooltip: 'List View'),
                      ],
                      selected: const {'grid'},
                      onSelectionChanged: (Set<String> selection) {
                        // TODO: 实现视图切换
                      },
                    ),
                  ],
                ),
              ],
            ),
          ),

          const SizedBox(height: 24),

          // 统计卡片
          _buildStatsCards(context),

          const SizedBox(height: 24),

          // 知识库内容
          Expanded(
            child: _buildKnowledgeContent(context),
          ),
        ],
      ),
    );
  }

  /// 构建统计卡片
  Widget _buildStatsCards(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.description,
                    color: Theme.of(context).colorScheme.primary,
                    size: 24,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Total Documents',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '1,234',
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.folder_special,
                    color: Theme.of(context).colorScheme.secondary,
                    size: 24,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Categories',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '12',
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(width: 16),
        Expanded(
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.storage,
                    color: Theme.of(context).colorScheme.tertiary,
                    size: 24,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Storage Used',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    '2.3 GB',
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }

  /// 构建知识库内容
  Widget _buildKnowledgeContent(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // 暂时显示静态数据
    return _buildMockKnowledge(context, isMobile);
  }

  /// 模拟知识库内容
  Widget _buildMockKnowledge(BuildContext context, bool isMobile) {
    // 模拟数据
    final mockKnowledge = [
      {
        'title': 'Getting Started with Flutter',
        'category': 'Documents',
        'description': 'Comprehensive guide to Flutter development, including setup, basic concepts, and best practices.',
        'size': '2.1 MB',
        'modified': '2 days ago',
        'type': 'PDF',
        'icon': Icons.picture_as_pdf,
      },
      {
        'title': 'API Documentation',
        'category': 'References',
        'description': 'Complete API reference for all backend services and endpoints.',
        'size': '856 KB',
        'modified': '1 week ago',
        'type': 'MD',
        'icon': Icons.code,
      },
      {
        'title': 'Database Schema',
        'category': 'Code',
        'description': 'Database structure diagrams and entity relationships for the application.',
        'size': '4.3 MB',
        'modified': '3 days ago',
        'type': 'SQL',
        'icon': Icons.storage,
      },
      {
        'title': 'Project Guidelines',
        'category': 'Articles',
        'description': 'Team coding standards, review process, and project management best practices.',
        'size': '1.2 MB',
        'modified': '5 days ago',
        'type': 'DOC',
        'icon': Icons.article,
      },
      {
        'title': 'Meeting Notes',
        'category': 'Notes',
        'description': 'Important decisions and action items from team meetings and stakeholder discussions.',
        'size': '234 KB',
        'modified': '1 day ago',
        'type': 'TXT',
        'icon': Icons.note,
      },
      {
        'title': 'Security Protocols',
        'category': 'Resources',
        'description': 'Security guidelines, encryption standards, and compliance requirements.',
        'size': '1.8 MB',
        'modified': '2 weeks ago',
        'type': 'PDF',
        'icon': Icons.security,
      },
    ];

    if (isMobile) {
      return ListView.builder(
        padding: const EdgeInsets.symmetric(vertical: 16),
        itemCount: mockKnowledge.length,
        itemBuilder: (context, index) {
          final item = mockKnowledge[index];
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
            child: Card(
              child: ListTile(
                leading: CircleAvatar(
                  backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                  child: Icon(
                    item['icon'] as IconData,
                    color: Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                ),
                title: Text(item['title'] as String),
                subtitle: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      item['category'] as String,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.primary,
                            fontWeight: FontWeight.w500,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      item['description'] as String,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 4),
                    Wrap(
                      spacing: 16,
                      runSpacing: 4,
                      children: [
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.schedule,
                              size: 14,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              item['modified'] as String,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.storage,
                              size: 14,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              item['size'] as String,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ],
                ),
                trailing: const Icon(Icons.more_vert),
                onTap: () {
                  _openKnowledgeItem(item);
                },
              ),
            ),
          );
        },
      );
    } else {
      // 桌面端网格布局
      return ResponsiveGrid(
        crossAxisSpacing: 16,
        mainAxisSpacing: 16,
        childAspectRatio: 1.8,
        children: mockKnowledge.map((item) {
          return Card(
            child: InkWell(
              onTap: () {
                _openKnowledgeItem(item);
              },
              borderRadius: BorderRadius.circular(12),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Container(
                          width: 40,
                          height: 40,
                          decoration: BoxDecoration(
                            color: Theme.of(context).colorScheme.primaryContainer,
                            shape: BoxShape.circle,
                          ),
                          child: Icon(
                            item['icon'] as IconData,
                            color: Theme.of(context).colorScheme.onPrimaryContainer,
                            size: 20,
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            item['type'] as String,
                            style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                  color: Theme.of(context).colorScheme.primary,
                                  fontWeight: FontWeight.w500,
                                ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Text(
                      item['title'] as String,
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w600,
                          ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      item['description'] as String,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Theme.of(context).colorScheme.onSurfaceVariant,
                          ),
                      maxLines: 3,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const Spacer(),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          item['category'] as String,
                          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                color: Theme.of(context).colorScheme.secondary,
                              ),
                        ),
                        Row(
                          children: [
                            Icon(
                              Icons.schedule,
                              size: 12,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 4),
                            Text(
                              item['modified'] as String,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          );
        }).toList(),
      );
    }
  }

  /// 执行搜索
  void _performSearch(String query) {
    // TODO: 实现搜索逻辑
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Searching for: $query')),
    );
  }

  /// 筛选知识库
  void _filterKnowledge() {
    // TODO: 实现筛选逻辑
  }

  /// 排序知识库
  void _sortKnowledge() {
    // TODO: 实现排序逻辑
  }

  /// 打开知识项
  void _openKnowledgeItem(Map<String, dynamic> item) {
    // TODO: 实现打开逻辑
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Opening: ${item['title'] as String}')),
    );
  }

  /// 显示导入对话框
  void _showImportDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Import Knowledge'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Choose import method:'),
            const SizedBox(height: 16),
            ListTile(
              leading: const Icon(Icons.file_upload),
              title: const Text('Upload File'),
              subtitle: const Text('Import from local device'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 实现文件上传
              },
            ),
            ListTile(
              leading: const Icon(Icons.link),
              title: const Text('Import from URL'),
              subtitle: const Text('Import from web link'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 实现URL导入
              },
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }

  /// 显示创建对话框
  void _showCreateDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Create Knowledge'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Choose creation type:'),
            const SizedBox(height: 16),
            ListTile(
              leading: const Icon(Icons.article),
              title: const Text('Document'),
              subtitle: const Text('Create rich text document'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 创建文档
              },
            ),
            ListTile(
              leading: const Icon(Icons.note),
              title: const Text('Note'),
              subtitle: const Text('Create quick note'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 创建笔记
              },
            ),
            ListTile(
              leading: const Icon(Icons.folder),
              title: const Text('Folder'),
              subtitle: const Text('Create new folder'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: 创建文件夹
              },
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }
}