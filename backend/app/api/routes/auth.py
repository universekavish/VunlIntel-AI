"""Organization registration and login endpoints."""

from fastapi import APIRouter, HTTPException, status

from app.api.dependencies import CurrentUser, DatabaseSession
from app.core.security.tokens import create_access_token
from app.repositories.organizations import get_organization
from app.schemas.auth import AuthResponse, LoginRequest, RegisterRequest
from app.schemas.identity import OrganizationRead, UserRead
from app.services.auth import authenticate_user, register_organization

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: RegisterRequest, session: DatabaseSession) -> AuthResponse:
    """Create a tenant, its initial owner account, and a short-lived access token."""
    organization, user = register_organization(
        session,
        organization_name=payload.organization_name,
        display_name=payload.display_name,
        email=str(payload.email),
        password=payload.password,
    )
    token, expires_in = create_access_token(user)
    return AuthResponse(
        access_token=token,
        expires_in=expires_in,
        user=UserRead.model_validate(user),
        organization=OrganizationRead.model_validate(organization),
    )


@router.post("/login", response_model=AuthResponse)
def login(payload: LoginRequest, session: DatabaseSession) -> AuthResponse:
    """Authenticate an active organization user with a non-enumerating error."""
    user = authenticate_user(
        session,
        email=str(payload.email),
        password=payload.password,
    )

    organization = get_organization(session, user.organization_id)
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token, expires_in = create_access_token(user)
    return AuthResponse(
        access_token=token,
        expires_in=expires_in,
        user=UserRead.model_validate(user),
        organization=OrganizationRead.model_validate(organization),
    )


@router.get("/me", response_model=UserRead)
def get_me(user: CurrentUser) -> UserRead:
    """Return the authenticated user's safe public profile."""
    return UserRead.model_validate(user)
