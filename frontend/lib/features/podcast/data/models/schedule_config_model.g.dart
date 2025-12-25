// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'schedule_config_model.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ScheduleConfigUpdateRequest _$ScheduleConfigUpdateRequestFromJson(
  Map<String, dynamic> json,
) => ScheduleConfigUpdateRequest(
  updateFrequency: json['update_frequency'] as String,
  updateTime: json['update_time'] as String?,
  updateDayOfWeek: (json['update_day_of_week'] as num?)?.toInt(),
  fetchInterval: (json['fetch_interval'] as num?)?.toInt(),
);

Map<String, dynamic> _$ScheduleConfigUpdateRequestToJson(
  ScheduleConfigUpdateRequest instance,
) => <String, dynamic>{
  'update_frequency': instance.updateFrequency,
  'update_time': instance.updateTime,
  'update_day_of_week': instance.updateDayOfWeek,
  'fetch_interval': instance.fetchInterval,
};

ScheduleConfigResponse _$ScheduleConfigResponseFromJson(
  Map<String, dynamic> json,
) => ScheduleConfigResponse(
  id: (json['id'] as num).toInt(),
  title: json['title'] as String,
  updateFrequency: json['update_frequency'] as String,
  updateTime: json['update_time'] as String?,
  updateDayOfWeek: (json['update_day_of_week'] as num?)?.toInt(),
  fetchInterval: (json['fetch_interval'] as num?)?.toInt(),
  nextUpdateAt: json['next_update_at'] == null
      ? null
      : DateTime.parse(json['next_update_at'] as String),
  lastUpdatedAt: json['last_updated_at'] == null
      ? null
      : DateTime.parse(json['last_updated_at'] as String),
);

Map<String, dynamic> _$ScheduleConfigResponseToJson(
  ScheduleConfigResponse instance,
) => <String, dynamic>{
  'id': instance.id,
  'title': instance.title,
  'update_frequency': instance.updateFrequency,
  'update_time': instance.updateTime,
  'update_day_of_week': instance.updateDayOfWeek,
  'fetch_interval': instance.fetchInterval,
  'next_update_at': instance.nextUpdateAt?.toIso8601String(),
  'last_updated_at': instance.lastUpdatedAt?.toIso8601String(),
};
