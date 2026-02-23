from __future__ import annotations


class CanariError(Exception):
    """Base error with stable CLI exit code and human-facing message."""

    exit_code = 1


class UsageError(CanariError):
    exit_code = 2


class InputError(CanariError):
    exit_code = 3


class NotFoundError(CanariError):
    exit_code = 4


class ConfigError(CanariError):
    exit_code = 5
