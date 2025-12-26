import 'package:intl/intl.dart';

class TimeFormatter {
  /// 将 API 返回的 UTC 时间字符串转换为本地 DateTime
  /// API 返回的时间通常是 ISO 8601 格式（如 "2025-12-26T14:16:36+00:00"）
  static DateTime parseUtcTime(String utcTimeString) {
    final dateTime = DateTime.parse(utcTimeString);
    // DateTime.parse() 会自动处理带时区信息的字符串
    // 如果字符串有时区信息（如 +00:00），解析后自动转换为本地时间
    // 如果字符串没有时区信息，假设它是本地时间
    return dateTime.toLocal();
  }

  /// 将 DateTime 转换为本地时间的 DateTime（如果是 UTC 时间）
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

  static String formatDuration(int seconds) {
    final duration = Duration(seconds: seconds);
    final hours = duration.inHours;
    final minutes = duration.inMinutes.remainder(60);

    if (hours > 0) {
      return '${hours.toString().padLeft(2, '0')}:${minutes.toString().padLeft(2, '0')}';
    } else {
      return '${minutes.toString().padLeft(2, '0')}分钟';
    }
  }

  /// 判断是否为今天
  static bool isToday(dynamic dateTimeInput) {
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return false;
    }

    final now = DateTime.now();
    return dateTime.year == now.year &&
        dateTime.month == now.month &&
        dateTime.day == now.day;
  }

  /// 判断是否为昨天
  static bool isYesterday(dynamic dateTimeInput) {
    DateTime dateTime;
    if (dateTimeInput is String) {
      dateTime = parseUtcTime(dateTimeInput);
    } else if (dateTimeInput is DateTime) {
      dateTime = toLocalTime(dateTimeInput);
    } else {
      return false;
    }

    final yesterday = DateTime.now().subtract(const Duration(days: 1));
    return dateTime.year == yesterday.year &&
        dateTime.month == yesterday.month &&
        dateTime.day == yesterday.day;
  }
}