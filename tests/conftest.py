"""Apply deterministic stage discovery and deny real socket networking in tests."""

from __future__ import annotations

import socket
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import NoReturn

import pytest

SOCKET_CONNECT = socket.socket.connect

TEST_STAGES = frozenset({"unit", "contract", "functional", "integration", "e2e"})


def pytest_collection_modifyitems(config: pytest.Config, items: Sequence[pytest.Item]) -> None:
    """Assign the stage from the test directory and reject unclassified test paths."""

    testsRoot = Path(config.rootpath) / "tests"

    for item in items:
        relativePath = item.path.relative_to(testsRoot)
        stageName = relativePath.parts[0]

        if stageName not in TEST_STAGES:
            raise pytest.UsageError(f"Test must belong to a supported stage: {item.path}")

        item.add_marker(getattr(pytest.mark, stageName))


def RejectNetwork(*arguments: object, **keywordArguments: object) -> NoReturn:
    """Require provider tests to use injected fakes rather than live networking."""

    raise RuntimeError("Real socket networking is disabled in F-Layer tests; use a fake")


@pytest.fixture(autouse=True, name='denyNetwork')
def DenyNetworkFixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block socket connections, datagrams, and DNS for the duration of each test."""

    monkeypatch.setattr(socket, "create_connection", RejectNetwork)
    monkeypatch.setattr(socket, "getaddrinfo", RejectNetwork)
    monkeypatch.setattr(socket.socket, "connect", RejectNetwork)
    monkeypatch.setattr(socket.socket, "connect_ex", RejectNetwork)
    monkeypatch.setattr(socket.socket, "sendto", RejectNetwork)


@pytest.fixture(name='loopbackConnection')
def LoopbackConnectionFixture() -> Callable[[int], socket.socket]:
    """Connect only to a repository-defined IPv4 loopback listener without DNS."""

    def ConnectLoopback(port: int) -> socket.socket:
        """Keep all non-loopback socket operations blocked by deny_network."""

        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(2)

        try:
            SOCKET_CONNECT(connection, ("127.0.0.1", port))

        except OSError:
            connection.close()
            raise

        return connection

    return ConnectLoopback
