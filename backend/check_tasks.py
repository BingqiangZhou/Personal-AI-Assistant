import asyncio
import os
import sys


# Add the backend directory to sys.path
sys.path.append(os.getcwd())

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Use a workaround to import without knowing the exact structure if needed,
# but we are in the backend folder, so app should be available.
from app.domains.podcast.models import TranscriptionTask


# Inside the container, DATABASE_URL is already defined in the environment.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "postgresql+asyncpg://admin:MySecurePass2024!@postgres:5432/personal_ai"
else:
    # Ensure it uses asyncpg
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

async def check_tasks():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    try:
        async with async_session() as session:
            stmt = select(TranscriptionTask).order_by(TranscriptionTask.updated_at.desc()).limit(10)
            result = await session.execute(stmt)
            tasks = result.scalars().all()
            
            print("--- Recent Transcription Tasks ---")
            print(f"Total tasks found (last 10): {len(tasks)}")
            for task in tasks:
                print(f"ID: {task.id} | EpID: {task.episode_id} | Status: {task.status} | Progress: {task.progress_percentage}% | Updated: {task.updated_at}")
                if task.error_message:
                    print(f"  Error: {task.error_message}")
                if task.chunk_info and isinstance(task.chunk_info, dict) and 'debug_message' in task.chunk_info:
                    print(f"  Debug: {task.chunk_info['debug_message']}")
            print("----------------------------------")
    except Exception as e:
        print(f"Error checking tasks: {e}")
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(check_tasks())
