# SPDX-License-Identifier: Apache-2.0
# Copyright The Ilorium Authors
"""Offline test setup. No test here touches the network."""

import socket
import sys
from pathlib import Path

import pytest

AGENT_DIR = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any attempt to open a socket fails the test."""

    def guard(*args, **kwargs):
        raise RuntimeError("network access attempted in an offline test")

    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)


@pytest.fixture
def fixtures():
    return FIXTURES
