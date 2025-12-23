
import asyncio
import os
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

async def list_and_delete_models():
    # Force use localhost since we are running on host, using the credentials from docker-compose
    DATABASE_URL = "postgresql+asyncpg://admin:MySecurePass2024!@localhost:5432/personal_ai"
    print(f"Connecting to database: {DATABASE_URL}")
    
    engine = create_async_engine(DATABASE_URL)
    async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    models_to_delete = ["GPT-3.5 Turbo", "GPT-4o", "GPT-4o Mini"]
    
    try:
        async with async_session_factory() as session:
            # First, list all models to see what we have
            print("Current models in database:")
            result = await session.execute(text("SELECT id, name, display_name FROM ai_model_configs"))
            rows = result.all()
            if not rows:
                print("No models found in ai_model_configs table.")
            for row in rows:
                print(f"ID: {row.id}, Name: {row.name}, Display Name: {row.display_name}")
            
            # Now delete
            for model_name in models_to_delete:
                print(f"Attempting to delete model by display_name: '{model_name}'")
                del_result = await session.execute(
                    text("DELETE FROM ai_model_configs WHERE display_name = :name"),
                    {"name": model_name}
                )
                print(f"Rows affected for '{model_name}': {del_result.rowcount}")
                
                # Also try by name
                del_result_name = await session.execute(
                    text("DELETE FROM ai_model_configs WHERE name = :name"),
                    {"name": model_name}
                )
                if del_result_name.rowcount > 0:
                     print(f"Rows affected for '{model_name}' (by name): {del_result_name.rowcount}")
            
            await session.commit()
            print("Transaction committed successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        await engine.dispose()
    print("Done.")

if __name__ == "__main__":
    asyncio.run(list_and_delete_models())
