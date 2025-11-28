"""
Authentication endpoints including 2FA
"""
from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.async_database import get_db
from app.api.dependencies.auth import get_current_active_user
from app.db.models.user import User
from app.db.schemas.user import (
    UserCreate,
    UserLogin,
    UserResponse,
    Token,
    UserSettings,
    TwoFactorRequest
)
from app.services.user_service import user_service
from app.services.email_service import email_service
from app.db.utils.user_crud import user_crud
from app.core.config import settings

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user (public endpoint)
    """
    user = await user_service.create_user(db, user_in)
    return user


@router.post("/login")
async def login(
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Login endpoint - initiates 2FA if enabled for user
    Supports login with username or email
    """
    # Authenticate user credentials (supports username or email)
    user = await user_crud.authenticate(
        db,
        credentials.username_or_email,
        credentials.password
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password"
        )

    if not await user_crud.is_active(user):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    # Check if user has 2FA enabled
    if user.two_fa_enabled:
        # Generate and send 2FA code
        code = await email_service.generate_2fa_code(user.id)
        await email_service.send_2fa_email(
            to=user.email,
            username=user.username,
            code=code
        )

        return {
            "message": "2FA code sent to your email",
            "requires_2fa": True,
            "user_id": user.id
        }
    else:
        # No 2FA, return tokens directly and update last_login_at
        from datetime import datetime, timezone
        user.last_login_at = datetime.now(timezone.utc)
        db.add(user)
        await db.commit()

        tokens = await user_service.authenticate_user(
            db,
            credentials.username_or_email,
            credentials.password
        )
        return tokens


@router.post("/verify-2fa", response_model=Token)
async def verify_2fa(
    request: TwoFactorRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify 2FA code and complete login
    """
    # Verify the 2FA code
    is_valid = await email_service.verify_2fa_code(request.user_id, request.code)

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired 2FA code"
        )

    # Get user and generate tokens
    user = await user_service.get_user_by_id(db, request.user_id)

    # Update last login timestamp
    from datetime import datetime, timezone
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    await db.commit()

    from app.core.security import create_access_token, create_refresh_token

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value
        }
    )
    refresh_token = create_refresh_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value
        }
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/enable-2fa")
async def enable_2fa(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Enable 2FA for current user
    """
    if current_user.two_fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled"
        )

    # Check if email is verified
    if not current_user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please verify your email before enabling 2FA"
        )

    # Enable 2FA
    current_user.two_fa_enabled = True
    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)

    # Send confirmation email
    await email_service.send_email(
        to=[current_user.email],
        subject="2FA Enabled",
        body=f"Two-factor authentication has been enabled for your account.",
        html=f"<p>Two-factor authentication has been successfully enabled for your account.</p>"
    )

    return {
        "message": "2FA has been enabled successfully",
        "two_fa_enabled": True
    }


@router.post("/disable-2fa")
async def disable_2fa(
    password: str = Body(..., embed=True),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Disable 2FA for current user (requires password confirmation)
    """
    if not current_user.two_fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled"
        )

    # Verify password for security
    from app.core.security import verify_password
    if not verify_password(password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Disable 2FA
    current_user.two_fa_enabled = False
    db.add(current_user)
    await db.commit()
    await db.refresh(current_user)

    # Send notification email
    await email_service.send_email(
        to=[current_user.email],
        subject="2FA Disabled",
        body=f"Two-factor authentication has been disabled for your account. If this wasn't you, please secure your account immediately.",
        html=f"<p>Two-factor authentication has been disabled for your account.</p><p>If this wasn't you, please secure your account immediately.</p>"
    )

    return {
        "message": "2FA has been disabled successfully",
        "two_fa_enabled": False
    }


@router.post("/test-2fa")
async def test_2fa(
    current_user: User = Depends(get_current_active_user)
):
    """
    Send a test 2FA code to verify email configuration
    """
    # Generate test code
    code = await email_service.generate_2fa_code(current_user.id)

    # Send test email
    success = await email_service.send_2fa_email(
        to=current_user.email,
        username=current_user.username,
        code=code
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send test email. Check SMTP configuration."
        )

    return {
        "message": "Test 2FA code sent to your email",
        "email": current_user.email
    }


# Google OAuth endpoints
@router.get("/google/login")
async def google_login(request: Request):
    """
    Initiate Google OAuth login flow

    Redirects user to Google's OAuth consent screen
    """
    if not settings.GOOGLE_OAUTH_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not enabled. Set GOOGLE_OAUTH_ENABLED=True in environment."
        )

    from app.core.oauth import oauth

    redirect_uri = request.url_for('google_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/google/callback", response_model=Token)
async def google_callback(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Handle Google OAuth callback

    After user authorizes, Google redirects here with auth code.
    This endpoint exchanges the code for user info and creates/logs in the user.
    """
    if not settings.GOOGLE_OAUTH_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not enabled"
        )

    from app.core.oauth import oauth, validate_google_user_info
    from app.core.security import create_access_token, create_refresh_token
    from datetime import datetime, timezone

    try:
        # Exchange authorization code for access token
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to authorize with Google: {str(e)}"
        )

    # Get user info from Google
    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to get user info from Google"
        )

    # Validate and extract user data
    validated_data = validate_google_user_info(user_info)

    # Get or create user
    user, created = await user_crud.get_or_create_oauth_user(
        db=db,
        email=validated_data['email'],
        username=validated_data['username'],
        oauth_provider=validated_data['oauth_provider'],
        oauth_id=validated_data['oauth_id'],
        first_name=validated_data.get('first_name'),
        last_name=validated_data.get('last_name'),
        avatar_url=validated_data.get('avatar_url'),
        email_verified=validated_data.get('email_verified', False)
    )

    # Update last login
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    await db.commit()

    # Generate JWT tokens
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value
        }
    )
    refresh_token = create_refresh_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value
        }
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }
