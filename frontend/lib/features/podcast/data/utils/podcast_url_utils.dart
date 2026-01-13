/// Feed URL 规范化和比较工具类
///
/// 提供用于比较和规范化 Podcast Feed URL 的工具函数
class PodcastUrlUtils {
  PodcastUrlUtils._();

  /// 规范化 Feed URL 用于比较
  ///
  /// 处理以下常见差异：
  /// - 协议差异 (http vs https)
  /// - 尾部斜杠
  /// - 大小写差异
  /// - 查询参数顺序
  ///
  /// [url] 原始 Feed URL
  /// 返回规范化后的 URL
  static String normalizeFeedUrl(String url) {
    var normalized = url.trim();

    // 移除尾部斜杠
    if (normalized.endsWith('/')) {
      normalized = normalized.substring(0, normalized.length - 1);
    }

    // 统一转小写 (域名部分不区分大小写)
    normalized = normalized.toLowerCase();

    // 统一协议为 https (如果原URL是 http)
    if (normalized.startsWith('http://')) {
      normalized = normalized.replaceFirst('http://', 'https://');
    }

    return normalized;
  }

  /// 比较两个 Feed URL 是否相同
  ///
  /// 使用规范化比较，处理常见的 URL 格式差异
  ///
  /// [url1] 第一个 URL
  /// [url2] 第二个 URL
  /// 返回如果两个 URL 指向同一 Feed 则返回 true
  static bool feedUrlMatches(String? url1, String? url2) {
    if (url1 == null || url2 == null) return false;

    // 直接比较（快速路径）
    if (url1 == url2) return true;

    // 规范化比较
    return normalizeFeedUrl(url1) == normalizeFeedUrl(url2);
  }

  /// 从多个 URL 中查找匹配的 Feed URL
  ///
  /// [targetUrl] 目标 URL
  /// [candidateUrls] 候选 URL 列表
  /// 返回第一个匹配的 URL，如果没有匹配则返回 null
  static String? findMatchingFeedUrl(
    String? targetUrl,
    List<String> candidateUrls,
  ) {
    if (targetUrl == null || candidateUrls.isEmpty) return null;

    try {
      return candidateUrls.firstWhere(
        (url) => feedUrlMatches(targetUrl, url),
      );
    } catch (e) {
      // firstWhere throws if no match found
      return null;
    }
  }

  /// 验证 URL 是否为有效的 Feed URL
  ///
  /// 基本检查：
  /// - 是否为有效的 URL 格式
  /// - 是否使用 http 或 https 协议
  ///
  /// [url] 要验证的 URL
  /// 返回如果 URL 有效则返回 true
  static bool isValidFeedUrl(String? url) {
    if (url == null || url.trim().isEmpty) return false;

    final uri = Uri.tryParse(url);
    if (uri == null) return false;

    // 必须是 http 或 https 协议
    if (!uri.hasScheme || (!uri.isScheme('http') && !uri.isScheme('https'))) {
      return false;
    }

    // 必须有主机名
    if (!uri.hasAuthority || uri.host.isEmpty) {
      return false;
    }

    return true;
  }

  /// 从 URL 中提取 Feed ID (用于唯一标识)
  ///
  /// 使用规范化 URL 作为 ID
  ///
  /// [url] Feed URL
  /// 返回 Feed ID
  static String extractFeedId(String url) {
    return normalizeFeedUrl(url);
  }
}
