
import asyncio
import os
import sys
from datetime import datetime

# Add the backend directory to sys.path
sys.path.append(os.getcwd())

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.domains.subscription.models import Subscription

# Use a workaround to import without knowing the exact structure if needed
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "postgresql+asyncpg://admin:MySecurePass2024!@postgres:5432/personal_ai"
else:
    # Ensure it uses asyncpg
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")

async def check_subscriptions():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    try:
        async with async_session() as session:
            stmt = select(Subscription).order_by(Subscription.last_fetched_at.desc())
            result = await session.execute(stmt)
            subs = result.scalars().all()
            
            print(f"--- Subscription Refresh Status ---")
            print(f"Total subscriptions: {len(subs)}")
            now = datetime.utcnow()
            print(f"Current UTC Time: {now}")
            
            for sub in subs:
                should_update = sub.should_update_now()
                print(f"ID: {sub.id} | Title: {sub.title} | Freq: {sub.update_frequency} | Status: {sub.status}")
                print(f"  Last Fetched: {sub.last_fetched_at}")
                print(f"  Should Update Now: {should_update}")
                
                # Try to access next_update_at or computed_next_update_at
                try:
                    next_up = getattr(sub, 'next_update_at', None) or getattr(sub, 'computed_next_update_at', None)
                    print(f"  Next Scheduled: {next_up}")
                except Exception as e:
                    print(f"  Error calculating next: {e}")
                
            print(f"------------------------------------")
    except Exception as e:
        print(f"Error checking subscriptions: {e}")
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(check_subscriptions())
