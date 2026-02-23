from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable

from canari_forensics.models import ConversationTurn


SCHEMA = """
CREATE TABLE IF NOT EXISTS turns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id TEXT NOT NULL,
  turn_index INTEGER NOT NULL,
  role TEXT NOT NULL,
  content TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  source_format TEXT NOT NULL,
  span_id TEXT,
  span_name TEXT,
  event_name TEXT
);
"""


class SQLiteTurnStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def insert_turns(self, turns: Iterable[ConversationTurn]) -> int:
        rows = []
        for t in turns:
            rows.append(
                (
                    t.conversation_id,
                    t.turn_index,
                    t.role,
                    t.content,
                    t.timestamp.isoformat(),
                    t.source_format,
                    str(t.metadata.get("span_id", "")),
                    str(t.metadata.get("span_name", "")),
                    str(t.metadata.get("event_name", "")),
                )
            )
        if not rows:
            return 0

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO turns (
                  conversation_id, turn_index, role, content, timestamp,
                  source_format, span_id, span_name, event_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
        return len(rows)

    def count_turns(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM turns").fetchone()
            return int(row[0]) if row else 0
