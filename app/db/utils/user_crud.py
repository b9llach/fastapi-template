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

    async def get_by_oauth(
        self,
        db: AsyncSession,
        oauth_provider: str,
        oauth_id: str
    ) -> Optional[User]:
        """
        Get user by OAuth provider and ID
        """
        result = await db.execute(
            select(User).where(
                User.oauth_provider == oauth_provider,
                User.oauth_id == oauth_id
            )
        )
        return result.scalar_one_or_none()

    async def create_oauth_user(
        self,
        db: AsyncSession,
        email: str,
        username: str,
        oauth_provider: str,
        oauth_id: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        avatar_url: Optional[str] = None,
        email_verified: bool = False
    ) -> User:
        """
        Create a new user from OAuth authentication
        """
        # Check if username already exists, make it unique if needed
        existing_user = await self.get_by_username(db, username)
        if existing_user:
            # Append random suffix to make username unique
            import random
            username = f"{username}{random.randint(1000, 9999)}"

        db_obj = User(
            username=username,
            email=email,
            hashed_password=None,  # OAuth users don't have passwords
            first_name=first_name,
            last_name=last_name,
            avatar_url=avatar_url,
            oauth_provider=oauth_provider,
            oauth_id=oauth_id,
            email_verified=email_verified,
            role=UserRole.USER
        )
        db.add(db_obj)
        await db.flush()
        await db.refresh(db_obj)
        return db_obj

    async def get_or_create_oauth_user(
        self,
        db: AsyncSession,
        email: str,
        username: str,
        oauth_provider: str,
        oauth_id: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        avatar_url: Optional[str] = None,
        email_verified: bool = False
    ) -> tuple[User, bool]:
        """
        Get existing OAuth user or create new one

        Returns:
            Tuple of (user, created) where created is True if user was just created
        """
        # First try to get by OAuth ID
        user = await self.get_by_oauth(db, oauth_provider, oauth_id)
        if user:
            return user, False

        # Check if user exists with this email
        user = await self.get_by_email(db, email)
        if user:
            # Link OAuth to existing account
            user.oauth_provider = oauth_provider
            user.oauth_id = oauth_id
            if not user.avatar_url and avatar_url:
                user.avatar_url = avatar_url
            if not user.email_verified:
                user.email_verified = email_verified
            db.add(user)
            await db.flush()
            await db.refresh(user)
            return user, False

        # Create new user
        user = await self.create_oauth_user(
            db=db,
            email=email,
            username=username,
            oauth_provider=oauth_provider,
            oauth_id=oauth_id,
            first_name=first_name,
            last_name=last_name,
            avatar_url=avatar_url,
            email_verified=email_verified
        )
        return user, True


# Create a singleton instance
user_crud = CRUDUser(User)
