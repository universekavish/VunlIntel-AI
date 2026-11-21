"""Organization-scoped role types used by API schemas and policy checks."""

from enum import StrEnum
from typing import Literal


class UserRole(StrEnum):
    """Supported tenant-scoped roles."""

    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


AssignableRole = Literal[UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER]
