"""Typed exceptions for RedFlag.

app.py maps each one to an HTTP status code, so routes never have to
pick status codes themselves.
"""

from __future__ import annotations


class RedFlagError(Exception):
    """Base class for all typed RedFlag exceptions."""

    code = "REDFLAG_ERROR"

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class ValidationError(RedFlagError):
    """Raised when user input fails validation (maps to 400)."""

    code = "VALIDATION_ERROR"


class ParsingError(RedFlagError):
    """Raised when a .eml file cannot be parsed (maps to 400)."""

    code = "PARSING_ERROR"


class ProviderError(RedFlagError):
    """Raised when a threat intelligence provider returns an error (maps to 502)."""

    code = "PROVIDER_ERROR"


class ProviderTimeout(RedFlagError):
    """Raised when a threat intelligence provider does not respond in time (maps to 504)."""

    code = "PROVIDER_TIMEOUT"
