"""
Authentication dependencies
"""
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.core.async_database import get_db
from app.core.security import decode_token, verify_api_key
from app.db.models.user import User
from app.db.models.enums import UserRole
from app.db.utils.user_crud import user_crud


security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token

    Args:
        credentials: Bearer token credentials
        db: Database session

    Returns:
        User object

    Raises:
        HTTPException: If token is invalid or user not found
    """
    token = credentials.credentials
    payload = decode_token(token)

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

    # Fetch user from database
    user = await user_crud.get(db, int(user_id))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current active user

    Args:
        current_user: Current user from get_current_user

    Returns:
        Active user object

    Raises:
        HTTPException: If user is inactive
    """
    if not await user_crud.is_active(current_user):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_admin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get current admin or superadmin user

    Args:
        current_user: Current active user

    Returns:
        Admin user object

    Raises:
        HTTPException: If user is not admin or superadmin
    """
    if not await user_crud.is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required."
        )
    return current_user


async def get_current_superadmin_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get current superadmin user

    Args:
        current_user: Current active user

    Returns:
        Superadmin user object

    Raises:
        HTTPException: If user is not superadmin
    """
    if not await user_crud.is_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Superadmin role required."
        )
    return current_user


def require_role(required_role: UserRole):
    """
    Dependency factory to require specific role

    Args:
        required_role: Required user role

    Returns:
        Dependency function

    Example:
        @app.get("/admin-only")
        async def admin_endpoint(user: User = Depends(require_role(UserRole.ADMIN))):
            ...
    """
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if not await user_crud.has_role(current_user, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. {required_role.value} role required."
            )
        return current_user
    return role_checker


def require_any_role(*roles: UserRole):
    """
    Dependency factory to require any of specified roles

    Args:
        *roles: Required user roles (any of them)

    Returns:
        Dependency function

    Example:
        @app.get("/staff-only")
        async def staff_endpoint(
            user: User = Depends(require_any_role(UserRole.ADMIN, UserRole.SUPERADMIN))
        ):
            ...
    """
    async def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        user_has_role = any([
            await user_crud.has_role(current_user, role)
            for role in roles
        ])
        if not user_has_role:
            role_names = ", ".join([role.value for role in roles])
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. One of these roles required: {role_names}"
            )
        return current_user
    return role_checker


async def verify_api_key_dependency(
    x_api_key: Optional[str] = Header(None)
):
    """
    Verify API key from header

    Args:
        x_api_key: API key from header

    Returns:
        True if valid

    Raises:
        HTTPException: If API key is invalid
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required"
        )

    if not verify_api_key(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    return True
