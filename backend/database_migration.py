"""
数据库迁移脚本 - 添加播客功能支持

无需Alembic的快速迁移方式（适合开发阶段）
"""

import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from app.core.config import settings
from app.core.database import Base, engine
from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState

async def create_tables():
    """创建播客相关表"""
    async with engine.begin() as conn:
        # 创建播客单集表
        await conn.run_sync(lambda sync_conn: PodcastEpisode.__table__.create(bind=sync_conn, checkfirst=True))
        # 创建播放状态表
        await conn.run_sync(lambda sync_conn: PodcastPlaybackState.__table__.create(bind=sync_conn, checkfirst=True))

        print("✅ 播客相关表已创建")

async def add_indexes():
    """添加特定索引（如果需要）"""
    async with engine.begin() as conn:
        # 添加外键约束
        try:
            await conn.execute(text("""
                ALTER TABLE podcast_episodes
                ADD CONSTRAINT fk_podcast_subscription
                FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
                ON DELETE CASCADE
            """))
        except Exception as e:
            print(f"外键约束可能已存在: {e}")

        try:
            await conn.execute(text("""
                ALTER TABLE podcast_playback_states
                ADD CONSTRAINT fk_playback_user
                FOREIGN KEY (user_id) REFERENCES users(id)
                ON DELETE CASCADE
            """))
        except Exception as e:
            print(f"外键约束可能已存在: {e}")

        try:
            await conn.execute(text("""
                ALTER TABLE podcast_playback_states
                ADD CONSTRAINT fk_playback_episode
                FOREIGN KEY (episode_id) REFERENCES podcast_episodes(id)
                ON DELETE CASCADE
            """))
        except Exception as e:
            print(f"外键约束可能已存在: {e}")

    print("✅ 外键约束已添加")

async def verify_migration():
    """验证迁移结果"""
    async with AsyncSession(engine) as session:
        # 检查表是否存在
        result = await session.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_name IN ('podcast_episodes', 'podcast_playback_states')
        """))
        tables = [row[0] for row in result.fetchall()]

        if 'podcast_episodes' in tables and 'podcast_playback_states' in tables:
            print("✅ 验证通过: 表已存在")
        else:
            print("❌ 验证失败: 表不存在")
            return False

        # 检查列
        result = await session.execute(text("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'podcast_episodes'
            ORDER BY ordinal_position
        """))
        columns = result.fetchall()
        print(f"\n📊 podcast_episodes 列 ({len(columns)}):")
        for col in columns:
            print(f"  - {col[0]}: {col[1]}")

        result = await session.execute(text("""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = 'podcast_playback_states'
            ORDER BY ordinal_position
        """))
        columns = result.fetchall()
        print(f"\n📊 podcast_playback_states 列 ({len(columns)}):")
        for col in columns:
            print(f"  - {col[0]}: {col[1]}")

        return True

async def rollback():
    """回滚（删除播客表，慎用）"""
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS podcast_playback_states"))
        await conn.execute(text("DROP TABLE IF EXISTS podcast_episodes"))
        print("✅ 已删播客表")

async def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="播客数据库迁移工具")
    parser.add_argument("--rollback", action="store_true", help="回滚操作，删除播客表")

    args = parser.parse_args()

    if args.rollback:
        confirm = input("⚠️  确认删除播客表？(yes/no): ")
        if confirm.lower() == "yes":
            await rollback()
        else:
            print("已取消")
        return

    print("开始播客数据库迁移...")
    # 隐藏密码中的敏感信息
    db_url = str(settings.DATABASE_URL)
    if "@" in db_url:
        # 隐藏密码部分
        parts = db_url.split("@")
        if len(parts) == 2:
            auth_part = parts[0]
            if ":" in auth_part and "//" in auth_part:
                host_part = parts[1]
                # 保留协议和用户名，隐藏密码
                protocol_end = auth_part.find("//")
                protocol = auth_part[:protocol_end + 2]
                credentials = auth_part[protocol_end + 2:]
                if ":" in credentials:
                    username = credentials.split(":")[0]
                    masked_db_url = f"{protocol}{username}:***@{host_part}"
                else:
                    masked_db_url = f"{protocol}{credentials}@{host_part}"
            else:
                masked_db_url = db_url
        else:
            masked_db_url = db_url
    else:
        masked_db_url = db_url
    print(f"数据库URL: {masked_db_url}")

    try:
        await create_tables()
        await add_indexes()
        await verify_migration()
        print("\n🎉 迁移完成！")
    except Exception as e:
        print(f"\n❌ 迁移失败: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
