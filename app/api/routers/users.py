"""
User management endpoints
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_database import get_db
from app.api.dependencies.auth import (
    get_current_active_user,
    get_current_admin_user,
    get_current_superadmin_user
)
from app.api.dependencies.pagination import get_pagination
from app.db.models.user import User
from app.db.models.enums import UserRole
from app.db.schemas.user import UserUpdate, UserResponse
from app.services.user_service import user_service

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current authenticated user information
    """
    return current_user


@router.get("/", response_model=List[UserResponse])
async def list_users(
    pagination: dict = Depends(get_pagination),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)  # Requires admin role
):
    """
    List all users (paginated) - Admin only
    """
    users = await user_service.get_users(
        db,
        skip=pagination["skip"],
        limit=pagination["limit"]
    )
    return users


@router.get("/role/{role}", response_model=List[UserResponse])
async def list_users_by_role(
    role: UserRole,
    pagination: dict = Depends(get_pagination),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)  # Requires admin role
):
    """
    List users by role - Admin only
    """
    users = await user_service.get_users_by_role(
        db,
        role,
        skip=pagination["skip"],
        limit=pagination["limit"]
    )
    return users


@router.get("/get/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get user by ID
    """
    # Users can only view their own profile, admins can view anyone
    if current_user.id != user_id and not await user_service.user_crud.is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this user"
        )

    user = await user_service.get_user_by_id(db, user_id)
    return user


@router.put("/update/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_in: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update user by ID
    """
    # Users can only update their own profile, admins can update anyone
    if current_user.id != user_id and not await user_service.user_crud.is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this user"
        )

    # Prevent non-superadmin from updating roles
    if user_in.role is not None and not await user_service.user_crud.is_superadmin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superadmin can change user roles"
        )

    user = await user_service.update_user(db, user_id, user_in)
    return user


@router.put("/update/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: int,
    new_role: UserRole = Body(..., embed=True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superadmin_user)  # Superadmin only
):
    """
    Update user role - Superadmin only
    """
    user = await user_service.update_user_role(db, user_id, new_role, current_user)
    return user


@router.delete("/delete/{user_id}")
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)  # Admin only
):
    """
    Delete user by ID - Admin only
    """
    # Prevent deleting yourself
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    await user_service.delete_user(db, user_id)
    return {"message": "User deleted successfully"}
