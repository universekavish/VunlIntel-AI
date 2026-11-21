"""Application-level errors safe to translate to HTTP responses."""


class ResourceConflictError(Exception):
    """Raised when a requested resource conflicts with an existing record."""


class InvalidCredentialsError(Exception):
    """Raised when a user cannot be authenticated."""


class PermissionDeniedError(Exception):
    """Raised when a user cannot perform an organization action."""


class ResourceNotFoundError(Exception):
    """Raised when a resource is not visible in the current tenant."""
