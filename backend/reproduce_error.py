
import asyncio
import os
import sys
from sqlalchemy import Column, Integer, String, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()

class SimpleModel(Base):
    __tablename__ = "simple_model"
    id = Column(Integer, primary_key=True)
    name = Column(String)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://admin:MySecurePass2024!@postgres:5432/personal_ai")

async def run_test():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    # Ensure table exists for test
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    try:
        async with async_session() as session:
            # Create a sample record
            session.add(SimpleModel(name="test"))
            await session.commit()
            
            # Fetch it
            stmt = select(SimpleModel)
            result = await session.execute(stmt)
            items = result.scalars().all()
            print(f"Fetched {len(items)} items")
            # Loop is still active here
    finally:
        print("Disposing engine...")
        await engine.dispose()
        print("Engine disposed.")

if __name__ == "__main__":
    try:
        asyncio.run(run_test())
        print("Test completed successfully.")
    except Exception as e:
        print(f"Test failed with: {e}")
        import traceback
        traceback.print_exc()
