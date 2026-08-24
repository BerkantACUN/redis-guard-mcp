"""Tests for connection setup and the ACL permission check."""

import os

import pytest
import redis

from redis_guard_mcp.client import MissingConfigError, check_permissions, get_client

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


pytestmark_live = pytest.mark.skipif(
    not _connectable(),
    reason="no local Redis reachable — set REDIS_GUARD_TEST_URL or start the dev container",
)


class TestGetClient:
    def test_missing_url_is_a_clear_error(self, monkeypatch):
        monkeypatch.delenv("REDIS_GUARD_URL", raising=False)
        with pytest.raises(MissingConfigError):
            get_client()

    def test_configured_url_returns_a_working_client(self, monkeypatch):
        monkeypatch.setenv("REDIS_GUARD_URL", TEST_URL)
        if not _connectable():
            pytest.skip("no local Redis reachable")
        client = get_client()
        assert client.ping() is True


@pytestmark_live
class TestCheckPermissionsAgainstRealRedis:
    """These exercise ACL DRYRUN against the real, provisioned
    redisguard_readonly user — ground truth from Redis's own ACL
    engine, not a re-implementation of its semantics."""

    def test_the_project_provisioned_readonly_user_has_no_dangerous_access(self):
        client = redis.from_url(TEST_URL, decode_responses=True)
        result = check_permissions(client)
        assert result["would_succeed"] == []
        assert result["username"] == "redisguard_readonly"
        assert result["commands_checked"] > 0

    def test_the_exact_client_admin_overlap_bug_stays_fixed(self):
        # The concrete CRITICAL finding from security review: CLIENT
        # KILL/PAUSE/LIST are members of both @admin and @connection, so
        # a rule list ending in "-@admin ... +@connection" (the wrong
        # order) silently re-grants them. This asserts the *current*
        # rule order (in scripts/setup_dev_redis.sh) doesn't regress.
        client = redis.from_url(TEST_URL, decode_responses=True)
        username = client.acl_whoami()
        for probe in (("CLIENT", "LIST"), ("CLIENT", "PAUSE", "0"), ("CLIENT", "KILL", "ID", "1")):
            verdict = client.acl_dryrun(username, *probe)
            assert verdict != "OK", f"{probe} unexpectedly allowed for {username}"

    def test_ordinary_read_commands_are_unaffected(self):
        client = redis.from_url(TEST_URL, decode_responses=True)
        username = client.acl_whoami()
        assert client.acl_dryrun(username, "GET", "greeting") == "OK"
        assert client.acl_dryrun(username, "PING") == "OK"

    def test_a_user_with_full_access_is_correctly_flagged(self):
        # Requires the container's default user to still have full
        # access (true for a fresh `redis:7-alpine` with no
        # requirepass) — used here only to prove the detector actually
        # detects the unsafe case, not just the safe one.
        try:
            default_client = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
            default_client.ping()
        except Exception:
            pytest.skip("default admin user not reachable without auth in this environment")
        result = check_permissions(default_client)
        assert result["would_succeed"], (
            "expected the default full-access user to show at least one dangerous command as allowed"
        )
