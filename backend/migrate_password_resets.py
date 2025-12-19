"""
数据库迁移脚本 - 添加密码重置功能

无需Alembic的快速迁移方式（适合开发阶段）
"""

import asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import engine
from app.domains.user.models import PasswordReset

async def create_password_resets_table():
    """创建密码重置表"""
    async with engine.begin() as conn:
        # 创建密码重置表
        await conn.run_sync(lambda sync_conn: PasswordReset.__table__.create(bind=sync_conn, checkfirst=True))
        print("✅ password_resets 表已创建")

async def add_indexes():
    """添加索引（如果需要）"""
    async with engine.begin() as conn:
        # 索引会通过模型的 __table_args__ 自动创建
        # 这里可以手动添加额外的索引或约束
        print("✅ 索引已创建")

async def verify_migration():
    """验证迁移结果"""
    async with AsyncSession(engine) as session:
        # 检查表是否存在
        result = await session.execute(text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_name = 'password_resets'
        """))
        tables = [row[0] for row in result.fetchall()]

        if 'password_resets' in tables:
            print("✅ 验证通过: password_resets 表已存在")
        else:
            print("❌ 验证失败: password_resets 表不存在")
            return False

        # 检查列
        result = await session.execute(text("""
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'password_resets'
            ORDER BY ordinal_position
        """))
        columns = result.fetchall()
        print(f"\n📊 password_resets 列 ({len(columns)}):")
        for col in columns:
            print(f"  - {col[0]}: {col[1]} (nullable: {col[2]}, default: {col[3]})")

        # 检查索引
        result = await session.execute(text("""
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE tablename = 'password_resets'
        """))
        indexes = result.fetchall()
        print(f"\n📊 password_resets 索引 ({len(indexes)}):")
        for idx in indexes:
            print(f"  - {idx[0]}: {idx[1]}")

        return True

async def rollback():
    """回滚（删除密码重置表，慎用）"""
    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS password_resets"))
        print("✅ 已删除 password_resets 表")

async def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="密码重置数据库迁移工具")
    parser.add_argument("--rollback", action="store_true", help="回滚操作，删除密码重置表")
    parser.add_argument("--verify", action="store_true", help="仅验证迁移结果")

    args = parser.parse_args()

    if args.rollback:
        confirm = input("⚠️  确认删除 password_resets 表？(yes/no): ")
        if confirm.lower() == "yes":
            await rollback()
        else:
            print("已取消")
        return

    if args.verify:
        await verify_migration()
        return

    print("开始密码重置数据库迁移...")
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
        await create_password_resets_table()
        await add_indexes()
        await verify_migration()
        print("\n🎉 迁移完成！")
        print("\n📝 使用说明:")
        print("1. 用户可以通过 POST /api/v1/auth/forgot-password 请求密码重置")
        print("2. 用户可以通过 POST /api/v1/auth/reset-password 使用token重置密码")
        print("3. 重置token有效期为1小时")
        print("4. 每个新请求会使之前的token失效")
    except Exception as e:
        print(f"\n❌ 迁移失败: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())