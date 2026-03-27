import 'package:intl/intl.dart';

class TimeFormatter {
  /// 将 API 返回的 UTC 时间字符串转换为本地 DateTime
  /// API 返回的时间通常是 ISO 8601 格式（如 "2025-12-26T14:16:36+00:00"）
  ///
  /// 重要：DateTime.parse() 对于带时区信息的字符串（如 +00:00 或 Z）会返回 UTC 时间（isUtc=true）
  /// 我们必须显式调用 toLocal() 来获取本地时间，否则后续比较会出现错误
  static DateTime parseUtcTime(String utcTimeString) {
    final dateTime = DateTime.parse(utcTimeString);
    // 无论输入是什么，都转换为本地时间
    // 如果是 UTC 时间（isUtc=true），toLocal() 会正确转换
    // 如果已经是本地时间，toLocal() 返回自身
    return dateTime.toLocal();
  }

  /// 将 DateTime 转换为本地时间的 DateTime（如果是 UTC 时间）
  ///
  /// 这个方法确保 DateTime 对象是本地时间，可以安全地与 DateTime.now() 进行比较
  static DateTime toLocalTime(DateTime dateTime) {
    if (dateTime.isUtc) {
      return dateTime.toLocal();
    }
    return dateTime;
  }

  static String formatRelativeTime(dynamic dateTimeInput) {
    // 支持两种输入：DateTime 或 String
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return '未知时间';
    }

    final now = DateTime.now();
    final difference = now.difference(dateTime);

    if (difference.inDays > 0) {
      if (difference.inDays == 1) {
        return '昨天';
      } else if (difference.inDays < 7) {
        return '${difference.inDays}天前';
      } else if (difference.inDays < 30) {
        return '${(difference.inDays / 7).floor()}周前';
      } else if (difference.inDays < 365) {
        return '${(difference.inDays / 30).floor()}个月前';
      } else {
        return DateFormat('yyyy-MM-dd').format(dateTime);
      }
    } else if (difference.inHours > 0) {
      return '${difference.inHours}小时前';
    } else if (difference.inMinutes > 0) {
      return '${difference.inMinutes}分钟前';
    } else {
      return '刚刚';
    }
  }

  /// 格式化完整日期时间
  static String formatFullDateTime(dynamic dateTimeInput) {
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return '未知时间';
    }

    return DateFormat('yyyy-MM-dd HH:mm').format(dateTime);
  }

  /// 格式化短日期
  static String formatShortDate(dynamic dateTimeInput) {
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return '未知时间';
    }

    return DateFormat('MM-dd').format(dateTime);
  }

  /// 格式化时间（时分）
  static String formatTime(dynamic dateTimeInput) {
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return '未知时间';
    }

    return DateFormat('HH:mm').format(dateTime);
  }

  /// 格式化日期（年月日）
  ///
  /// 返回格式: yyyy-MM-dd
  /// 自动处理 UTC 时间转换为本地时间
  static String formatDate(dynamic dateTimeInput) {
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return '未知日期';
    }

    return DateFormat('yyyy-MM-dd').format(dateTime);
  }

  /// Compares two nullable DateTimes by their calendar date (year, month, day).
  ///
  /// Returns `true` if both are `null`, `false` if exactly one is `null`,
  /// and `true` if both represent the same calendar date.
  static bool sameDate(DateTime? left, DateTime? right) {
    if (left == null && right == null) return true;
    if (left == null || right == null) return false;
    return left.year == right.year &&
        left.month == right.month &&
        left.day == right.day;
  }

  /// 格式化时长为 mm:ss 或 hh:mm:ss。
  static String formatDuration(
    Duration duration, {
    bool padHours = true,
    bool alwaysShowHours = false,
  }) {
    final safeDuration = duration.isNegative ? Duration.zero : duration;
    final hours = safeDuration.inHours;
    final minutes = safeDuration.inMinutes.remainder(60);
    final seconds = safeDuration.inSeconds.remainder(60);

    final minutePart = minutes.toString().padLeft(2, '0');
    final secondPart = seconds.toString().padLeft(2, '0');

    if (hours > 0 || alwaysShowHours) {
      final hourPart = padHours ? hours.toString().padLeft(2, '0') : '$hours';
      return '$hourPart:$minutePart:$secondPart';
    }

    return '$minutePart:$secondPart';
  }

  /// 按秒格式化时钟文本。
  static String formatSecondsClock(
    int seconds, {
    bool padHours = true,
    bool alwaysShowHours = false,
  }) {
    final safeSeconds = seconds < 0 ? 0 : seconds;
    return formatDuration(
      Duration(seconds: safeSeconds),
      padHours: padHours,
      alwaysShowHours: alwaysShowHours,
    );
  }
}
