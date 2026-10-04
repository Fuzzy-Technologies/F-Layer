"""Apply deterministic stage discovery and deny real socket networking in tests."""

from __future__ import annotations

import socket
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

import pytest

TEST_STAGES = frozenset({"unit", "contract", "functional", "integration", "e2e"})


def pytest_collection_modifyitems(config: pytest.Config, items: Sequence[pytest.Item]) -> None:
    """Assign the stage from the test directory and reject unclassified test paths."""

    tests_root = Path(config.rootpath) / "tests"

    for item in items:
        relative_path = item.path.relative_to(tests_root)
        stage_name = relative_path.parts[0]

        if stage_name not in TEST_STAGES:
            raise pytest.UsageError(f"Test must belong to a supported stage: {item.path}")

        item.add_marker(getattr(pytest.mark, stage_name))


def RejectNetwork(*arguments: object, **keyword_arguments: object) -> NoReturn:
    """Require provider tests to use injected fakes rather than live networking."""

    raise RuntimeError("Real socket networking is disabled in F-Layer tests; use a fake")


@pytest.fixture(autouse=True)
def deny_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block socket connections, datagrams, and DNS for the duration of each test."""

    monkeypatch.setattr(socket, "create_connection", RejectNetwork)
    monkeypatch.setattr(socket, "getaddrinfo", RejectNetwork)
    monkeypatch.setattr(socket.socket, "connect", RejectNetwork)
    monkeypatch.setattr(socket.socket, "connect_ex", RejectNetwork)
    monkeypatch.setattr(socket.socket, "sendto", RejectNetwork)
