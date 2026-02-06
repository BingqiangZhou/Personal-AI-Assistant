import asyncio
import os
import sys


# Set Mock Env Vars for Pydantic
os.environ["DATABASE_URL"] = "postgresql+asyncpg://admin:MySecurePass2024!@localhost:5432/personal_ai"
os.environ["REDIS_URL"] = "redis://localhost:6379"

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__)))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.domains.user.models import User


# from app.core.config import settings # Avoid importing if possible, or import after env set


async def check_users():
    # Use credentials from docker-compose.yml
    # POSTGRES_USER=${POSTGRES_USER} -> needs actual value, usually 'postgres' or 'admin'
    # Checking Dockerfile or assume defaults if not found. 
    # Wait, the docker-compose uses vars. I need to find where they are defined. 
    # Usually in .env. But I can't read .env. 
    # I'll try to guess 'postgres:postgres' or 'admin:admin' or look for .env.dev.
    
    # Let's try to read .env.dev first since .env was blocked.
    database_url = "postgresql+asyncpg://admin:MySecurePass2024!@localhost:5432/personal_ai"
    print(f"Connecting to: {database_url}")

    engine = create_async_engine(database_url)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        print(f"Total users found: {len(users)}")
        for user in users:
            print(f"User ID: {user.id}, Email: {user.email}, Is Active: {user.is_active}")
            
    await engine.dispose()

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(check_users())
