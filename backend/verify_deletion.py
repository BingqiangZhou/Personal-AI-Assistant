import asyncio
import sys
import os

# Add backend directory to sys.path
sys.path.append(os.getcwd())

from app.core.database import async_session
from app.domains.ai.models import AIModelConfig, ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from sqlalchemy import delete, select

async def main():
    async with async_session() as session:
        repo = AIModelConfigRepository(session)
        
        # 1. Create a dummy system model directly in DB (bypassing service checks if any)
        print("Creating dummy system model...")
        dummy_model = AIModelConfig(
            name="dummy-system-model",
            display_name="Dummy System Model",
            model_type=ModelType.TEXT_GENERATION,
            api_url="https://example.com",
            api_key="123",
            model_id="dummy-gpt",
            is_system=True,
            is_active=True
        )
        session.add(dummy_model)
        await session.commit()
        await session.refresh(dummy_model)
        dummy_id = dummy_model.id
        print(f"Created model with ID: {dummy_id}, is_system: {dummy_model.is_system}")

        # 2. Verify it exists
        fetched = await repo.get_by_id(dummy_id)
        if not fetched:
            print("Error: Could not fetch created model.")
            return
        
        # 3. Try to delete it
        print("Attempting to delete model...")
        success = await repo.delete(dummy_id)
        
        if success:
            print("Delete operation returned True.")
        else:
            print("Delete operation returned False.")

        # 4. Verify it is physically gone
        # We use a raw select to bypass any repository logic if it were doing soft deletes (though getting by id usually returns all)
        stmt = select(AIModelConfig).where(AIModelConfig.id == dummy_id)
        result = await session.execute(stmt)
        final_check = result.scalar_one_or_none()
        
        if final_check is None:
            print("SUCCESS: Model was physically deleted.")
        else:
            print(f"FAILURE: Model still exists. is_active: {final_check.is_active}")
            # Clean up if failed
            await session.delete(final_check)
            await session.commit()

if __name__ == "__main__":
    asyncio.run(main())
