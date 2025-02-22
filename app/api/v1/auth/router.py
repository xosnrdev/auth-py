"""Authentication router for user registration and login.

Following RFCs:
- RFC 6749: OAuth 2.0 Framework
- RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
- RFC 6750: Bearer Token Usage
- RFC 7009: OAuth 2.0 Token Revocation
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update

from app.api.v1.auth.dependencies import CurrentUser, DBSession
from app.core.config import settings
from app.core.security import (
    create_jwt_token,
    get_password_hash,
    verify_password,
)
from app.models import AuditLog, Token, User
from app.models.token import RevocationReason
from app.schemas import (
    TokenError,
    TokenResponse,
    TokenType,
    UserCreate,
    UserResponse,
)
from app.schemas.token import ErrorCode, TokenRevocationRequest

router = APIRouter(prefix="/auth", tags=["auth"])


def get_client_ip(request: Request) -> str:
    """Get client IP address from request.

    Args:
        request: FastAPI request object

    Returns:
        str: Client IP address
    """
    if request.client and request.client.host:
        return request.client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    db: DBSession,
) -> User:
    """Register a new user.

    Creates a new user account with the provided email and password.
    The password is hashed before storage.
    An audit log entry is created for the registration.

    Args:
        request: FastAPI request object
        user_in: User registration data
        db: Database session

    Returns:
        User: Created user object

    Raises:
        HTTPException:
            - 400: Email already registered

    OpenAPI:
        tags:
          - auth
        summary: Register new user
        description: |
            Create a new user account.
            The password will be securely hashed.
            An audit log entry will be created.
        requestBody:
            content:
                application/json:
                    schema:
                        $ref: '#/components/schemas/UserCreate'
        responses:
            201:
                description: User successfully created
                content:
                    application/json:
                        schema:
                            $ref: '#/components/schemas/UserResponse'
            400:
                description: Email already registered
    """
    # Check if email exists
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create user
    db_user = User(
        email=user_in.email,
        phone=user_in.phone,
        password_hash=get_password_hash(user_in.password),
        roles=user_in.roles,
    )
    db.add(db_user)

    # Log registration
    audit_log = AuditLog(
        user_id=db_user.id,
        action="register",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="User registration",
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(db_user)

    return db_user


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> TokenResponse:
    """OAuth2 compatible token login, get an access token for future requests.

    Implements OAuth 2.0 password grant flow (RFC 6749 Section 4.3).
    Returns a JWT access token (RFC 9068) and refresh token.
    Creates an audit log entry for the login attempt.

    Args:
        request: FastAPI request object
        form_data: OAuth2 password request form
        db: Database session

    Returns:
        TokenResponse: Access and refresh tokens with expiration times

    Raises:
        HTTPException:
            - 401: Invalid credentials
            - 403: Inactive user

    Security:
        - Access token is a JWT following RFC 9068
        - Refresh token is stored in database for revocation
        - Implements OAuth 2.0 password grant (RFC 6749)
        - Uses asymmetric signing (RS256)

    OpenAPI:
        tags:
          - auth
        summary: OAuth2 password grant token endpoint
        description: |
            Authenticate user and receive access and refresh tokens.
            The access token is a JWT that must be sent in the Authorization header.
            The refresh token can be used to obtain new access tokens.
        requestBody:
            content:
                application/x-www-form-urlencoded:
                    schema:
                        required:
                            - username
                            - password
                        properties:
                            username:
                                type: string
                                description: User's email address
                            password:
                                type: string
                                format: password
                                description: User's password
        responses:
            200:
                description: Successful authentication
                content:
                    application/json:
                        schema:
                            $ref: '#/components/schemas/TokenResponse'
            401:
                description: Invalid credentials
            403:
                description: Inactive user
    """
    # Get user by email
    stmt = select(User).where(User.email == form_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    # Create tokens
    access_token, access_exp = create_jwt_token(user.id, "access")
    refresh_token, refresh_exp = create_jwt_token(user.id, "refresh")

    # Store only the refresh token
    db_token = Token(
        jti=user.id,
        refresh_token=refresh_token,
        expires_at=refresh_exp,
    )
    db.add(db_token)

    # Log login
    audit_log = AuditLog(
        user_id=user.id,
        action="login",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="User login",
    )
    db.add(audit_log)

    await db.commit()

    return TokenResponse(
        access_token=access_token,
        token_type=TokenType.BEARER,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        refresh_token=refresh_token,
        expires_at=refresh_exp,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    user: CurrentUser,
    db: DBSession,
) -> None:
    """Logout current user by revoking all refresh tokens.

    Implements token revocation (RFC 7009).
    Creates an audit log entry for the logout.

    Args:
        request: FastAPI request object
        user: Current authenticated user
        db: Database session

    Security:
        - Requires valid access token
        - Revokes all refresh tokens
        - Audit logged

    OpenAPI:
        tags:
          - auth
        summary: Logout current user
        description: |
            Revoke all refresh tokens for the current user.
            The access token will remain valid until expiration.
            An audit log entry will be created.
        security:
            - BearerAuth: []
        responses:
            204:
                description: Successfully logged out
            401:
                description: Invalid or missing token
    """
    # Revoke all user's refresh tokens
    stmt = (
        update(Token)
        .where(Token.jti == user.id)
        .values(
            revoked=True,
            revoked_at=datetime.now(UTC),
            revocation_reason=RevocationReason.LOGOUT,
        )
    )
    await db.execute(stmt)

    # Log logout
    audit_log = AuditLog(
        user_id=user.id,
        action="logout",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="User logout",
    )
    db.add(audit_log)

    await db.commit()


@router.post("/revoke", status_code=status.HTTP_200_OK, responses={
    200: {"description": "Token successfully revoked"},
    400: {"model": TokenError, "description": "Invalid request"},
    404: {"description": "Token not found"},
})
async def revoke_token(
    request: Request,
    revocation: TokenRevocationRequest,
    user: CurrentUser,
    db: DBSession,
) -> None:
    """Revoke a specific token as per RFC 7009.

    Args:
        request: FastAPI request object
        revocation: Token revocation request
        user: Current authenticated user
        db: Database session

    Raises:
        HTTPException:
            - 400: Invalid request
            - 404: Token not found

    Security:
        - Requires valid access token
        - Only refresh tokens can be revoked
        - Audit logged

    OpenAPI:
        tags:
          - auth
        summary: Revoke a specific token
        description: |
            Revoke a specific refresh token.
            Access tokens cannot be revoked as they are stateless.
            An audit log entry will be created.
        security:
            - BearerAuth: []
        requestBody:
            content:
                application/json:
                    schema:
                        $ref: '#/components/schemas/TokenRevocationRequest'
        responses:
            200:
                description: Token successfully revoked
            400:
                description: Invalid request
                content:
                    application/json:
                        schema:
                            $ref: '#/components/schemas/TokenError'
            404:
                description: Token not found
    """
    # Only refresh tokens can be revoked
    if revocation.token_type_hint and revocation.token_type_hint != "refresh_token":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=TokenError(
                error=ErrorCode.INVALID_REQUEST,
                error_description="Only refresh tokens can be revoked",
            ).model_dump(),
        )

    # Find and revoke the token
    stmt = (
        update(Token)
        .where(
            Token.refresh_token == revocation.token,
            Token.jti == user.id,  # Ensure user can only revoke their own tokens
            Token.revoked.is_(False),
        )
        .values(
            revoked=True,
            revoked_at=datetime.now(UTC),
            revocation_reason=revocation.reason,
        )
    )
    result = await db.execute(stmt)

    if result.rowcount == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=TokenError(
                error=ErrorCode.INVALID_REQUEST,
                error_description="Token not found or already revoked",
            ).model_dump(),
        )

    # Log revocation
    audit_log = AuditLog(
        user_id=user.id,
        action="revoke_token",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Token revoked: {revocation.reason}",
    )
    db.add(audit_log)

    await db.commit()


@router.get("/me", response_model=UserResponse)
async def get_current_user(user: CurrentUser) -> User:
    """Get current authenticated user data.

    Args:
        user: Current authenticated user from bearer token

    Returns:
        User: Current user data

    Security:
        - Requires valid access token

    OpenAPI:
        tags:
          - auth
        summary: Get current user
        description: |
            Get the profile of the currently authenticated user.
            Requires a valid access token.
        security:
            - BearerAuth: []
        responses:
            200:
                description: Current user profile
                content:
                    application/json:
                        schema:
                            $ref: '#/components/schemas/UserResponse'
            401:
                description: Invalid or missing token
    """
    return user
