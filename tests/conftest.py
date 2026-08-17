from __future__ import annotations

import json
from pathlib import Path

import pytest


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def session_storage(tmp_path: Path) -> Path:
    root = tmp_path / "sessions"
    session = root / "session_demo"
    write_json(
        session / "session.json",
        {"session_id": "demo", "session_type": "AGENT", "created_at": "2026-01-01T00:00:00Z"},
    )
    write_json(
        session / "agents" / "agent_researcher" / "agent.json",
        {
            "agent_id": "researcher",
            "state": {"api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz", "workspace": "/Users/alice/project"},
            "conversation_manager_state": {},
            "_internal_state": {},
        },
    )
    messages = session / "agents" / "agent_researcher" / "messages"
    write_json(
        messages / "message_0.json",
        {
            "message_id": 0,
            "message": {"role": "user", "content": [{"text": "email alice@example.com"}]},
            "redact_message": None,
        },
    )
    write_json(
        messages / "message_1.json",
        {
            "message_id": 1,
            "message": {"role": "assistant", "content": [{"toolUse": {"name": "search", "input": {}}}]},
            "redact_message": None,
        },
    )
    write_json(
        messages / "message_2.json",
        {
            "message_id": 2,
            "message": {"role": "user", "content": [{"text": "original unsafe text"}]},
            "redact_message": {"role": "user", "content": [{"text": "guardrail replacement"}]},
        },
    )
    return root
