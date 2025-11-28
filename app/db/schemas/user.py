"""
User Pydantic schemas
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

from app.db.models.enums import UserRole


class UserBase(BaseModel):
    """
    Base user schema with common attributes
    """
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    phone_number: Optional[str] = Field(None, max_length=20)
    avatar_url: Optional[str] = Field(None, max_length=500)
    bio: Optional[str] = None
    timezone: Optional[str] = Field("UTC", max_length=50)
    language: Optional[str] = Field("en", max_length=10)


class UserCreate(UserBase):
    """
    Schema for creating a new user
    """
    password: str = Field(..., min_length=8, max_length=100)
    role: Optional[UserRole] = UserRole.USER


class UserUpdate(BaseModel):
    """
    Schema for updating a user
    """
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    first_name: Optional[str] = Field(None, max_length=50)
    last_name: Optional[str] = Field(None, max_length=50)
    phone_number: Optional[str] = Field(None, max_length=20)
    avatar_url: Optional[str] = Field(None, max_length=500)
    bio: Optional[str] = None
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(None, max_length=10)
    password: Optional[str] = Field(None, min_length=8, max_length=100)
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None


class UserResponse(UserBase):
    """
    Schema for user response
    """
    id: int
    is_active: bool
    role: UserRole
    two_fa_enabled: bool
    email_verified: bool
    phone_verified: bool
    oauth_provider: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    stripe_connect_id: Optional[str] = None
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserSettings(BaseModel):
    """
    Schema for user settings update
    """
    two_fa_enabled: Optional[bool] = None
    email_notifications: Optional[bool] = None


class TwoFactorRequest(BaseModel):
    """
    Schema for 2FA verification request
    """
    user_id: int
    code: str = Field(..., min_length=6, max_length=6)


class UserLogin(BaseModel):
    """
    Schema for user login (supports username or email)
    """
    username_or_email: str = Field(..., description="Username or email address")
    password: str


class Token(BaseModel):
    """
    Schema for authentication token
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """
    Schema for token data
    """
    username: Optional[str] = None
