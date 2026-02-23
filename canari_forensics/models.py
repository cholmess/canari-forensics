from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class ConversationTurn:
    """A normalized unit of conversation text for forensic scanning."""

    conversation_id: str
    turn_index: int
    role: str
    content: str
    timestamp: datetime
    metadata: dict[str, Any]
    source_format: str
