"""
存储清理服务 / Storage Cleanup Service

提供存储信息查询和缓存文件清理功能
Provides storage information query and cache file cleanup functionality
"""

import logging
import os
import shutil
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.models import SystemSettings
from app.core.config import settings


logger = logging.getLogger(__name__)


class StorageCleanupService:
    """存储清理服务 / Storage cleanup service"""

    def __init__(self, db: AsyncSession):
        self.db = db

    def _get_directory_size(self, directory_path: str) -> tuple[int, int]:
        """
        获取目录大小和文件数量

        Args:
            directory_path: 目录路径

        Returns:
            (文件数量, 总大小(字节))
        """
        file_count = 0
        total_size = 0

        try:
            # 使用 os.scandir() 提高性能
            with os.scandir(directory_path) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False):
                        file_count += 1
                        try:
                            total_size += entry.stat().st_size
                        except (OSError, AttributeError) as e:
                            logger.debug(f"无法获取文件大小: {entry.path}, 错误: {e}")
                    elif entry.is_dir(follow_symlinks=False):
                        # 递归处理子目录
                        sub_count, sub_size = self._get_directory_size(entry.path)
                        file_count += sub_count
                        total_size += sub_size
        except (FileNotFoundError, PermissionError) as e:
            logger.warning(f"无法访问目录 {directory_path}: {e}")
        except Exception as e:
            logger.error(f"扫描目录 {directory_path} 时发生错误: {e}")

        return file_count, total_size

    def _get_disk_usage(self, path: str) -> dict:
        """
        获取磁盘使用情况

        Args:
            path: 路径

        Returns:
            磁盘使用信息字典
        """
        try:
            usage = shutil.disk_usage(path)
            return {
                "free": usage.free,
                "free_human": self._format_bytes(usage.free),
                "total": usage.total,
                "total_human": self._format_bytes(usage.total),
                "used": usage.used,
                "used_human": self._format_bytes(usage.used),
                "usage_percent": round((usage.used / usage.total) * 100, 2) if usage.total > 0 else 0
            }
        except Exception as e:
            logger.error(f"获取磁盘使用情况失败: {e}")
            return {
                "free": 0,
                "free_human": "未知",
                "total": 0,
                "total_human": "未知",
                "used": 0,
                "used_human": "未知",
                "usage_percent": 0
            }

    def _format_bytes(self, bytes_size: int) -> str:
        """
        格式化字节大小为人类可读格式

        Args:
            bytes_size: 字节大小

        Returns:
            格式化后的字符串 (例如: "1.5 GB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} PB"

    async def get_storage_info(self) -> dict:
        """
        获取存储信息

        Returns:
            存储信息字典，包含 storage、temp 和 disk 信息
        """
        logger.info("📊 开始获取存储信息...")

        # 获取 storage 目录信息
        storage_path = settings.TRANSCRIPTION_STORAGE_DIR
        storage_count, storage_size = self._get_directory_size(storage_path)

        # 获取 temp 目录信息
        temp_path = settings.TRANSCRIPTION_TEMP_DIR
        temp_count, temp_size = self._get_directory_size(temp_path)

        # 获取磁盘使用情况
        disk_info = self._get_disk_usage(storage_path)

        result = {
            "storage": {
                "file_count": storage_count,
                "total_size": storage_size,
                "total_size_human": self._format_bytes(storage_size),
                "path": storage_path,
                "last_updated": datetime.now(timezone.utc).isoformat()
            },
            "temp": {
                "file_count": temp_count,
                "total_size": temp_size,
                "total_size_human": self._format_bytes(temp_size),
                "path": temp_path,
                "last_updated": datetime.now(timezone.utc).isoformat()
            },
            "disk": disk_info
        }

        logger.info(
            f"📊 存储信息: Storage={storage_count}文件/{self._format_bytes(storage_size)}, "
            f"Temp={temp_count}文件/{self._format_bytes(temp_size)}, "
            f"磁盘剩余={disk_info['free_human']}"
        )

        return result

    async def get_cleanup_config(self) -> dict:
        """
        获取自动清理配置

        Returns:
            配置字典
        """
        try:
            stmt = select(SystemSettings).where(
                SystemSettings.key == "auto_cache_cleanup"
            )
            result = await self.db.execute(stmt)
            setting = result.scalar_one_or_none()

            if setting and setting.value:
                value = setting.value
                return {
                    "enabled": value.get("enabled", False),
                    "last_cleanup": value.get("last_cleanup")
                }

            return {
                "enabled": False,
                "last_cleanup": None
            }
        except Exception as e:
            logger.error(f"获取自动清理配置失败: {e}")
            return {
                "enabled": False,
                "last_cleanup": None
            }

    async def update_cleanup_config(self, enabled: bool) -> dict:
        """
        更新自动清理配置

        Args:
            enabled: 是否启用自动清理

        Returns:
            更新结果
        """
        try:
            stmt = select(SystemSettings).where(
                SystemSettings.key == "auto_cache_cleanup"
            )
            result = await self.db.execute(stmt)
            setting = result.scalar_one_or_none()

            current_time = datetime.now(timezone.utc).isoformat()

            if setting:
                # 更新现有配置
                setting.value = {
                    "enabled": enabled,
                    "last_cleanup": setting.value.get("last_cleanup") if setting.value else None
                }
                setting.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            else:
                # 创建新配置
                setting = SystemSettings(
                    key="auto_cache_cleanup",
                    value={
                        "enabled": enabled,
                        "last_cleanup": None
                    },
                    description="自动清理缓存配置",
                    category="storage"
                )
                self.db.add(setting)

            await self.db.commit()

            logger.info(f"✅ 自动清理配置已更新: enabled={enabled}")

            return {
                "success": True,
                "message": "配置已更新" if enabled else "自动清理已禁用",
                "enabled": enabled
            }
        except Exception as e:
            await self.db.rollback()
            logger.error(f"更新自动清理配置失败: {e}")
            return {
                "success": False,
                "message": f"更新失败: {str(e)}"
            }

    def _cleanup_directory(self, directory_path: str, keep_days: int = 1) -> dict:
        """
        清理指定目录中的旧文件

        Args:
            directory_path: 目录路径
            keep_days: 保留天数（默认1天，即仅保留今天）

        Returns:
            清理结果字典
        """
        deleted_count = 0
        freed_space = 0
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=keep_days)

        logger.info(f"🧹 开始清理目录: {directory_path} (保留 {keep_days} 天)")

        try:
            # 遍历目录树
            for root, dirs, files in os.walk(directory_path, topdown=False):
                for filename in files:
                    file_path = os.path.join(root, filename)

                    try:
                        # 获取文件修改时间
                        file_mtime = datetime.fromtimestamp(
                            os.path.getmtime(file_path),
                            tz=timezone.utc
                        )

                        # 如果文件早于截止时间，删除它
                        if file_mtime < cutoff_time:
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            deleted_count += 1
                            freed_space += file_size
                            logger.debug(
                                f"删除文件: {file_path} "
                                f"(修改时间: {file_mtime.strftime('%Y-%m-%d %H:%M:%S')}, "
                                f"大小: {self._format_bytes(file_size)})"
                            )

                    except PermissionError as e:
                        logger.warning(f"权限不足，无法删除文件: {file_path}, 错误: {e}")
                    except FileNotFoundError:
                        # 文件已被删除，跳过
                        pass
                    except Exception as e:
                        logger.error(f"删除文件时发生错误: {file_path}, 错误: {e}")

                # 尝试删除空目录
                try:
                    if root != directory_path:  # 不删除根目录
                        os.rmdir(root)
                except OSError:
                    # 目录不为空或其他错误，跳过
                    pass

            logger.info(
                f"✅ 目录清理完成: {directory_path} - "
                f"删除 {deleted_count} 个文件, 释放 {self._format_bytes(freed_space)}"
            )

        except Exception as e:
            logger.error(f"清理目录失败: {directory_path}, 错误: {e}")

        return {
            "deleted_count": deleted_count,
            "freed_space": freed_space,
            "freed_space_human": self._format_bytes(freed_space)
        }

    async def execute_cleanup(self, keep_days: int = 1) -> dict:
        """
        执行清理操作

        Args:
            keep_days: 保留天数（默认1天，即仅保留今天）

        Returns:
            清理结果字典
        """
        logger.info("=" * 70)
        logger.info("🧹 开始清理缓存文件...")
        logger.info(f"保留策略: 保留最近 {keep_days} 天的文件（删除昨天及之前的文件）")
        logger.info("=" * 70)

        # 清理 storage 目录
        storage_path = settings.TRANSCRIPTION_STORAGE_DIR
        storage_result = self._cleanup_directory(storage_path, keep_days)

        # 清理 temp 目录
        temp_path = settings.TRANSCRIPTION_TEMP_DIR
        temp_result = self._cleanup_directory(temp_path, keep_days)

        # 汇总结果
        total_deleted = storage_result["deleted_count"] + temp_result["deleted_count"]
        total_freed = storage_result["freed_space"] + temp_result["freed_space"]

        logger.info("-" * 70)
        logger.info("📊 清理统计:")
        logger.info(f"  Storage 目录: {storage_result['deleted_count']} 文件, {self._format_bytes(storage_result['freed_space'])}")
        logger.info(f"  Temp 目录: {temp_result['deleted_count']} 文件, {self._format_bytes(temp_result['freed_space'])}")
        logger.info("-" * 70)
        logger.info(f"✅ 清理完成: 总计删除 {total_deleted} 个文件, 释放 {self._format_bytes(total_freed)} 空间")
        logger.info("=" * 70)

        # 更新最后清理时间
        await self._update_last_cleanup_time()

        return {
            "success": True,
            "storage": storage_result,
            "temp": temp_result,
            "total": {
                "deleted_count": total_deleted,
                "freed_space": total_freed,
                "freed_space_human": self._format_bytes(total_freed)
            }
        }

    async def _update_last_cleanup_time(self):
        """更新最后清理时间"""
        try:
            stmt = select(SystemSettings).where(
                SystemSettings.key == "auto_cache_cleanup"
            )
            result = await self.db.execute(stmt)
            setting = result.scalar_one_or_none()

            current_time = datetime.now(timezone.utc).isoformat()

            if setting:
                setting.value["last_cleanup"] = current_time
                setting.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
            else:
                # 创建配置记录
                setting = SystemSettings(
                    key="auto_cache_cleanup",
                    value={
                        "enabled": False,
                        "last_cleanup": current_time
                    },
                    description="自动清理缓存配置",
                    category="storage"
                )
                self.db.add(setting)

            await self.db.commit()
            logger.debug(f"更新最后清理时间: {current_time}")
        except Exception as e:
            logger.error(f"更新最后清理时间失败: {e}")
