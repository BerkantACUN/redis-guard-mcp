"""Integration tests for the MCP tool layer, against the same local
Redis + redisguard_readonly ACL user used by the other test modules."""

import os

import pytest
import redis

import redis_guard_mcp.server as server_module

TEST_URL = os.environ.get(
    "REDIS_GUARD_TEST_URL",
    "redis://redisguard_readonly:redisguard_readonly_dev_pw@127.0.0.1:6379/0",
)


def _connectable() -> bool:
    try:
        redis.from_url(TEST_URL, socket_connect_timeout=3).ping()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _connectable(),
    reason="no local Redis reachable — set REDIS_GUARD_TEST_URL or start the dev container",
)


@pytest.fixture(autouse=True)
def _configure_url(monkeypatch):
    monkeypatch.setenv("REDIS_GUARD_URL", TEST_URL)
    server_module._client = None
    yield
    server_module._client = None


class TestReadTools:
    def test_get_returns_the_seeded_value(self):
        result = server_module.redis_get("greeting")
        assert result["result"] == "hello redis-guard"

    def test_hscan_returns_the_seeded_hash_fields(self):
        result = server_module.redis_hscan("user:1")
        assert result["result"]["fields"] == {"name": "Ada", "role": "engineer"}

    def test_scan_keys_finds_the_seeded_key(self):
        result = server_module.redis_scan_keys("greet*")
        assert "greeting" in result["result"]["keys"]

    def test_dbsize_is_a_typed_result(self):
        result = server_module.redis_dbsize()
        assert result["result"] >= 5


class TestCheckPermissions:
    def test_readonly_user_shows_no_dangerous_commands_would_succeed(self):
        result = server_module.redis_check_permissions()
        assert result["result"]["would_succeed"] == []


class TestMissingConfig:
    def test_missing_url_is_a_typed_error(self, monkeypatch):
        monkeypatch.delenv("REDIS_GUARD_URL", raising=False)
        server_module._client = None
        result = server_module.redis_get("greeting")
        assert result["error"] == "MissingConfig"
