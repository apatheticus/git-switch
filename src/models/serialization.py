"""Serialization utilities for Git-Switch.

This module provides custom JSON encoding for application models.
"""

from __future__ import annotations

import base64
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID


class GitSwitchEncoder(json.JSONEncoder):
    """Custom JSON encoder for Git-Switch models.

    Handles encoding of special types:
    - UUID: Converted to string representation.
    - datetime: Converted to ISO 8601 format.
    - Path: Converted to string representation.
    - bytes: Converted to base64-encoded ASCII string.
    - dataclass: Converted to dictionary via asdict().
    """

    def default(self, obj: Any) -> Any:
        """Encode non-standard types.

        Args:
            obj: Object to encode.

        Returns:
            JSON-serializable representation of the object.

        Raises:
            TypeError: If object type is not supported.
        """
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("ascii")
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        return super().default(obj)


def serialize(obj: Any, indent: int | None = None) -> str:
    """Serialize an object to JSON string.

    Args:
        obj: Object to serialize.
        indent: JSON indentation level (None for compact).

    Returns:
        JSON string representation.
    """
    return json.dumps(obj, cls=GitSwitchEncoder, indent=indent)


def deserialize_bytes(data: str) -> bytes:
    """Deserialize a base64-encoded string to bytes.

    Args:
        data: Base64-encoded ASCII string.

    Returns:
        Decoded bytes.
    """
    return base64.b64decode(data.encode("ascii"))


def deserialize_uuid(data: str) -> UUID:
    """Deserialize a string to UUID.

    Args:
        data: String representation of UUID.

    Returns:
        UUID object.
    """
    return UUID(data)


def deserialize_datetime(data: str) -> datetime:
    """Deserialize an ISO 8601 string to datetime.

    Args:
        data: ISO 8601 formatted datetime string.

    Returns:
        datetime object.
    """
    return datetime.fromisoformat(data)


def deserialize_path(data: str) -> Path:
    """Deserialize a string to Path.

    Args:
        data: String representation of path.

    Returns:
        Path object.
    """
    return Path(data)


__all__ = [
    "GitSwitchEncoder",
    "deserialize_bytes",
    "deserialize_datetime",
    "deserialize_path",
    "deserialize_uuid",
    "serialize",
]
