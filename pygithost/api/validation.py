"""Strict mutation input validation; no coercion or silently ignored fields."""

import re

from .errors import APIError


def fields(document, allowed, required=()):
    if set(document) - set(allowed):
        raise APIError(422, "validation_error", "Unknown request fields.")
    if set(required) - set(document):
        raise APIError(422, "validation_error", "Required request fields are missing.")


def text(document, name, *, maximum=65536, empty=False):
    value = document.get(name)
    if (not isinstance(value, str) or len(value) > maximum or "\0" in value
            or not empty and not value.strip()):
        raise APIError(422, "validation_error", f"Invalid {name} field.")
    return value


def sha(document, name):
    value = document.get(name)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        raise APIError(422, "validation_error", f"{name} must be a full commit SHA.")
    return value.lower()


def name(value):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", value)
            or ".." in value or value.endswith(".git")):
        raise APIError(422, "validation_error", "Invalid repository name.")
    return value


def expected_revision(document):
    value = document.get("expected_revision")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise APIError(422, "validation_error", "expected_revision must be a resource revision from a current GET response.")
    return value
