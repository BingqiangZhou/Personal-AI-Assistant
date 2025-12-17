"""User repository implementation."""

from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload

from app.domains.user.models import User, UserSession
from app.shared.schemas import UserCreate, UserUpdate


class UserRepository:
    """Repository for User model."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, user_data: UserCreate) -> User:
        """Create a new user."""
        from app.core.security import get_password_hash

        hashed_password = get_password_hash(user_data.password)
        db_user = User(
            email=user_data.email,
            username=user_data.username,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            is_active=user_data.is_active,
            is_superuser=user_data.is_superuser
        )

        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        return db_user

    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User).filter(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.db.execute(
            select(User).filter(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        result = await self.db.execute(
            select(User).filter(User.username == username)
        )
        return result.scalar_one_or_none()

    async def get_by_api_key(self, api_key: str) -> Optional[User]:
        """Get user by API key."""
        result = await self.db.execute(
            select(User).filter(User.api_key == api_key)
        )
        return result.scalar_one_or_none()

    async def update(self, user_id: int, user_data: UserUpdate) -> Optional[User]:
        """Update user."""
        user = await self.get_by_id(user_id)
        if not user:
            return None

        update_data = user_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)

        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def delete(self, user_id: int) -> bool:
        """Delete user."""
        user = await self.get_by_id(user_id)
        if not user:
            return False

        await self.db.delete(user)
        await self.db.commit()
        return True

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = True
    ) -> List[User]:
        """List users."""
        query = select(User)

        if active_only:
            query = query.filter(User.is_active == True)

        query = query.offset(skip).limit(limit).order_by(User.created_at.desc())

        result = await self.db.execute(query)
        return result.scalars().all()


class UserSessionRepository:
    """Repository for UserSession model."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(self, user_id: int, session_token: str, **kwargs) -> UserSession:
        """Create a new user session."""
        db_session = UserSession(
            user_id=user_id,
            session_token=session_token,
            **kwargs
        )

        self.db.add(db_session)
        await self.db.commit()
        await self.db.refresh(db_session)
        return db_session

    async def get_by_token(self, session_token: str) -> Optional[UserSession]:
        """Get session by token."""
        result = await self.db.execute(
            select(UserSession).filter(
                and_(
                    UserSession.session_token == session_token,
                    UserSession.is_active == True
                )
            )
        )
        return result.scalar_one_or_none()

    async def deactivate(self, session_token: str) -> bool:
        """Deactivate a session."""
        session = await self.get_by_token(session_token)
        if not session:
            return False

        session.is_active = False
        await self.db.commit()
        return True

    async def deactivate_all_for_user(self, user_id: int) -> int:
        """Deactivate all sessions for a user."""
        result = await self.db.execute(
            select(UserSession).filter(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True
                )
            )
        )
        sessions = result.scalars().all()

        for session in sessions:
            session.is_active = False

        await self.db.commit()
        return len(sessions)