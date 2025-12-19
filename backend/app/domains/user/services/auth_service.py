"""Authentication service for user management."""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.exc import IntegrityError
import secrets
import uuid

from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token
)
from app.core.config import settings
from app.core.exceptions import (
    BadRequestError,
    UnauthorizedError,
    ConflictError,
    NotFoundError
)
from app.domains.user.models import User, UserSession, PasswordReset
from app.core.email import email_service


class AuthenticationService:
    """Service for handling authentication operations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register_user(
        self,
        email: str,
        password: str,
        username: Optional[str] = None
    ) -> User:
        """
        Register a new user.

        Args:
            email: User's email address
            password: Plain text password
            username: Optional username

        Returns:
            Created user instance

        Raises:
            ConflictError: If user already exists
            BadRequestError: If password is too weak
        """
        # Validate password strength
        if len(password) < 8:
            raise BadRequestError("Password must be at least 8 characters long")

        # Generate username from email if not provided
        if not username:
            # Extract username from email (part before @)
            username = email.split('@')[0]
            # Ensure uniqueness by adding number if needed
            base_username = username
            counter = 1
            while await self._get_user_by_username(username):
                username = f"{base_username}{counter}"
                counter += 1

        # Check if user already exists
        existing_user = await self._get_user_by_email_or_username(email, username)
        if existing_user:
            if existing_user.email == email:
                raise ConflictError("Email already registered")
            elif existing_user.username == username:
                raise ConflictError("Username already taken")

        # Create new user
        hashed_password = get_password_hash(password)

        user = User(
            email=email,
            username=username,
            hashed_password=hashed_password,
            status="active",
            is_verified=False,
            is_superuser=False
        )

        try:
            self.db.add(user)
            await self.db.commit()
            await self.db.refresh(user)
            return user
        except IntegrityError as e:
            await self.db.rollback()
            raise ConflictError("User registration failed")

    async def authenticate_user(
        self,
        email_or_username: str,
        password: str
    ) -> Optional[User]:
        """
        Authenticate user with email/username and password.

        Args:
            email_or_username: User's email or username
            password: Plain text password

        Returns:
            User instance if authentication successful, None otherwise
        """
        # Get user by email or username
        user = await self._get_user_by_email_or_username(email_or_username, email_or_username)

        if not user:
            return None

        # Check password
        if not verify_password(password, user.hashed_password):
            return None

        # Check if user is active
        if user.status != "active":
            return None

        # Update last login
        user.last_login_at = datetime.utcnow()
        await self.db.commit()

        return user

    async def create_user_session(
        self,
        user: User,
        device_info: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create user session with tokens.

        Args:
            user: User instance
            device_info: Optional device information
            ip_address: Optional IP address
            user_agent: Optional user agent string

        Returns:
            Dictionary containing access and refresh tokens
        """
        # Create tokens
        access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )

        refresh_token = create_refresh_token(
            data={"sub": str(user.id), "email": user.email}
        )

        # Calculate expiry times
        access_expires_at = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        refresh_expires_at = datetime.utcnow() + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

        # Create session record
        session = UserSession(
            user_id=user.id,
            session_token=access_token,
            refresh_token=refresh_token,
            device_info=device_info or {},
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=access_expires_at,
            last_activity_at=datetime.utcnow(),
            is_active=True
        )

        try:
            self.db.add(session)
            await self.db.commit()
            await self.db.refresh(session)
        except IntegrityError:
            await self.db.rollback()
            raise BadRequestError("Failed to create user session")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "session_id": session.id
        }

    async def refresh_access_token(self, refresh_token: str) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.

        Args:
            refresh_token: Valid refresh token

        Returns:
            Dictionary with new access token

        Raises:
            UnauthorizedError: If refresh token is invalid
            NotFoundError: If session not found
        """
        # Verify refresh token
        try:
            payload = verify_token(refresh_token, token_type="refresh")
            user_id = int(payload.get("sub"))
        except Exception:
            raise UnauthorizedError("Invalid refresh token")

        # Find valid session
        session = await self._get_valid_session_by_refresh_token(refresh_token)
        if not session or session.user_id != user_id:
            raise NotFoundError("Invalid session")

        # Check if session is still active
        if not session.is_active or session.expires_at < datetime.utcnow():
            raise UnauthorizedError("Session expired")

        # Get user
        user = await self._get_user_by_id(user_id)
        if not user or user.status != "active":
            raise UnauthorizedError("User not found or inactive")

        # Create new access token
        new_access_token = create_access_token(
            data={"sub": str(user.id), "email": user.email}
        )

        # Update session
        session.session_token = new_access_token
        session.last_activity_at = datetime.utcnow()
        session.expires_at = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

        await self.db.commit()

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    async def logout_user(self, refresh_token: str) -> bool:
        """
        Logout user by invalidating session.

        Args:
            refresh_token: Refresh token to invalidate

        Returns:
            True if logout successful

        Raises:
            NotFoundError: If session not found
        """
        session = await self._get_valid_session_by_refresh_token(refresh_token)
        if not session:
            raise NotFoundError("Session not found")

        # Mark session as inactive
        session.is_active = False
        session.last_activity_at = datetime.utcnow()
        await self.db.commit()

        return True

    async def logout_all_sessions(self, user_id: int) -> bool:
        """
        Logout user from all devices.

        Args:
            user_id: User ID

        Returns:
            True if logout successful
        """
        result = await self.db.execute(
            select(UserSession).where(
                and_(
                    UserSession.user_id == user_id,
                    UserSession.is_active == True
                )
            )
        )
        sessions = result.scalars().all()

        for session in sessions:
            session.is_active = False
            session.last_activity_at = datetime.utcnow()

        await self.db.commit()
        return True

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        result = await self.db.execute(
            select(UserSession).where(
                or_(
                    UserSession.expires_at < datetime.utcnow(),
                    and_(
                        UserSession.last_activity_at < datetime.utcnow() - timedelta(days=30),
                        UserSession.is_active == False
                    )
                )
            )
        )
        sessions = result.scalars().all()

        count = 0
        for session in sessions:
            await self.db.delete(session)
            count += 1

        await self.db.commit()
        return count

    async def create_password_reset_token(self, email: str) -> Dict[str, Any]:
        """
        Create a password reset token for the given email.

        Args:
            email: User's email address

        Returns:
            Dictionary containing the reset token and expiry time

        Raises:
            NotFoundError: If user with given email doesn't exist
        """
        # Check if user exists
        user = await self._get_user_by_email(email)
        if not user:
            # Don't reveal if email exists or not for security
            return {
                "message": "If an account with this email exists, a password reset link has been sent.",
                "token": None  # Don't return actual token in production
            }

        # Invalidate any existing unused tokens for this email
        await self._invalidate_existing_tokens(email)

        # Generate secure token
        reset_token = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour

        # Create password reset record
        password_reset = PasswordReset(
            email=email,
            token=reset_token,
            expires_at=expires_at,
            is_used=False
        )

        try:
            self.db.add(password_reset)
            await self.db.commit()
            await self.db.refresh(password_reset)

            # Send password reset email
            await email_service.send_password_reset_email(
                email=email,
                token=reset_token,
                expires_at=expires_at
            )

            return {
                "message": "If an account with this email exists, a password reset link has been sent.",
                "token": reset_token,  # Only for development, remove in production
                "expires_at": expires_at.isoformat()
            }

        except IntegrityError:
            await self.db.rollback()
            raise BadRequestError("Failed to create password reset token")

    async def reset_password(self, token: str, new_password: str) -> Dict[str, Any]:
        """
        Reset user password using the given token.

        Args:
            token: Password reset token
            new_password: New password to set

        Returns:
            Success message

        Raises:
            BadRequestError: If token is invalid or expired
            NotFoundError: If token doesn't exist
        """
        # Validate password strength
        if len(new_password) < 8:
            raise BadRequestError("Password must be at least 8 characters long")

        # Get the password reset record
        password_reset = await self._get_valid_password_reset_token(token)

        if not password_reset:
            raise BadRequestError("Invalid or expired reset token")

        # Get user by email
        user = await self._get_user_by_email(password_reset.email)
        if not user:
            raise NotFoundError("User not found")

        # Update user password
        user.hashed_password = get_password_hash(new_password)
        user.updated_at = datetime.utcnow()

        # Mark token as used
        password_reset.is_used = True
        password_reset.updated_at = datetime.utcnow()

        # Invalidate all user sessions (force re-login)
        await self.logout_all_sessions(user.id)

        await self.db.commit()

        return {
            "message": "Password has been successfully reset. Please login with your new password."
        }

    async def _get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def _invalidate_existing_tokens(self, email: str) -> None:
        """Invalidate all existing unused tokens for the given email."""
        result = await self.db.execute(
            select(PasswordReset).where(
                and_(
                    PasswordReset.email == email,
                    PasswordReset.is_used == False,
                    PasswordReset.expires_at > datetime.utcnow()
                )
            )
        )
        tokens = result.scalars().all()

        for token in tokens:
            token.is_used = True
            token.updated_at = datetime.utcnow()

        await self.db.commit()

    async def _get_valid_password_reset_token(self, token: str) -> Optional[PasswordReset]:
        """Get valid password reset token."""
        result = await self.db.execute(
            select(PasswordReset).where(
                and_(
                    PasswordReset.token == token,
                    PasswordReset.is_used == False,
                    PasswordReset.expires_at > datetime.utcnow()
                )
            )
        )
        return result.scalar_one_or_none()

    async def _get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def _get_user_by_email_or_username(
        self,
        email: Optional[str] = None,
        username: Optional[str] = None
    ) -> Optional[User]:
        """Get user by email or username."""
        conditions = []
        if email:
            conditions.append(User.email == email)
        if username:
            conditions.append(User.username == username)

        if not conditions:
            return None

        result = await self.db.execute(
            select(User).where(or_(*conditions))
        )
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def _get_valid_session_by_refresh_token(
        self,
        refresh_token: str
    ) -> Optional[UserSession]:
        """Get valid session by refresh token."""
        result = await self.db.execute(
            select(UserSession).where(
                and_(
                    UserSession.refresh_token == refresh_token,
                    UserSession.is_active == True,
                    UserSession.expires_at > datetime.utcnow()
                )
            )
        )
        return result.scalar_one_or_none()