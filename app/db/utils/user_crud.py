"""
User-specific CRUD operations
"""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.models.user import User
from app.db.models.enums import UserRole
from app.db.schemas.user import UserCreate, UserUpdate
from app.db.utils.crud import CRUDBase
from app.core.security import hash_password


class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    """
    CRUD operations for User model
    """

    async def get_by_email(
        self,
        db: AsyncSession,
        email: str
    ) -> Optional[User]:
        """
        Get user by email
        """
        result = await db.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_username(
        self,
        db: AsyncSession,
        username: str
    ) -> Optional[User]:
        """
        Get user by username
        """
        result = await db.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def create(
        self,
        db: AsyncSession,
        obj_in: UserCreate
    ) -> User:
        """
        Create a new user with hashed password
        """
        db_obj = User(
            username=obj_in.username,
            email=obj_in.email,
            hashed_password=hash_password(obj_in.password),
            first_name=obj_in.first_name,
            last_name=obj_in.last_name,
            role=obj_in.role
        )
        db.add(db_obj)
        await db.flush()
        await db.refresh(db_obj)
        return db_obj

    async def authenticate(
        self,
        db: AsyncSession,
        username_or_email: str,
        password: str
    ) -> Optional[User]:
        """
        Authenticate a user by username or email
        """
        from app.core.security import verify_password

        # Try to find user by username first
        user = await self.get_by_username(db, username_or_email)

        # If not found, try by email
        if not user:
            user = await self.get_by_email(db, username_or_email)

        # If still not found, authentication failed
        if not user:
            return None

        # Verify password
        if not verify_password(password, user.hashed_password):
            return None

        return user

    async def is_active(self, user: User) -> bool:
        """
        Check if user is active
        """
        return user.is_active

    async def has_role(self, user: User, role: UserRole) -> bool:
        """
        Check if user has specific role
        """
        return user.role == role

    async def is_admin(self, user: User) -> bool:
        """
        Check if user is admin or superadmin
        """
        return user.role in [UserRole.ADMIN, UserRole.SUPERADMIN]

    async def is_superadmin(self, user: User) -> bool:
        """
        Check if user is superadmin
        """
        return user.role == UserRole.SUPERADMIN

    async def get_by_role(
        self,
        db: AsyncSession,
        role: UserRole,
        skip: int = 0,
        limit: int = 100
    ) -> list[User]:
        """
        Get users by role
        """
        result = await db.execute(
            select(User).where(User.role == role).offset(skip).limit(limit)
        )
        return list(result.scalars().all())


# Create a singleton instance
user_crud = CRUDUser(User)
