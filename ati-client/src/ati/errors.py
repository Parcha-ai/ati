"""ATI error types."""


class AtiError(Exception):
    """Base error for all ATI operations."""


class TokenError(AtiError):
    """Error issuing, validating, or inspecting a JWT."""


class ScopeError(AtiError):
    """Error parsing or checking scopes."""


class ProvisionError(AtiError):
    """Error provisioning a sandbox environment."""
