"""
Tests for the read-only command layer, run against a real local Redis.

Also includes a structural test that's arguably the most important one
in this project: that the module exposing tools genuinely contains no
path to a dangerous command, not just that the currently-implemented
functions happen to be safe ones.
"""

import os

import pytest
import redis

import redis_guard_mcp.commands as commands_module
from redis_guard_mcp.commands import (
    TooManyKeysError,
    redis_dbsize,
    redis_exists,
    redis_get,
    redis_hget,
    redis_hscan,
    redis_lrange,
    redis_mget,
    redis_scan_keys,
    redis_sscan,
    redis_ttl,
    redis_type,
    redis_zrange,
)

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


@pytest.fixture()
def client():
    return redis.from_url(TEST_URL, decode_responses=True)


class TestReadingSeedData:
    """These read the fixture data seeded by scripts/setup_dev_redis.sh
    (greeting, user:1, queue, tags, scores) — if the seed changes,
    update these together with it."""

    def test_get_returns_the_seeded_string(self, client):
        assert redis_get(client, "greeting") == "hello redis-guard"

    def test_get_on_a_missing_key_returns_none_not_an_error(self, client):
        assert redis_get(client, "does-not-exist") is None

    def test_mget_returns_a_dict_keyed_by_the_requested_keys(self, client):
        result = redis_mget(client, ["greeting", "does-not-exist"])
        assert result["greeting"] == "hello redis-guard"
        assert result["does-not-exist"] is None

    def test_mget_rejects_too_many_keys(self, client):
        with pytest.raises(TooManyKeysError):
            redis_mget(client, [f"k{i}" for i in range(300)])

    def test_type_reports_the_real_redis_type(self, client):
        assert redis_type(client, "greeting") == "string"
        assert redis_type(client, "user:1") == "hash"
        assert redis_type(client, "queue") == "list"
        assert redis_type(client, "tags") == "set"
        assert redis_type(client, "scores") == "zset"

    def test_exists_counts_how_many_of_the_given_keys_are_present(self, client):
        assert redis_exists(client, ["greeting", "does-not-exist", "user:1"]) == 2

    def test_exists_rejects_too_many_keys(self, client):
        with pytest.raises(TooManyKeysError):
            redis_exists(client, [f"k{i}" for i in range(300)])

    def test_hscan_returns_all_fields_across_pages(self, client):
        seen = {}
        cursor = 0
        while True:
            page = redis_hscan(client, "user:1", cursor)
            seen.update(page["fields"])
            cursor = page["cursor"]
            if cursor == 0:
                break
        assert seen == {"name": "Ada", "role": "engineer"}

    def test_hget_returns_a_single_field(self, client):
        assert redis_hget(client, "user:1", "name") == "Ada"

    def test_lrange_returns_list_elements_in_order(self, client):
        result = redis_lrange(client, "queue")
        assert result["items"] == ["a", "b", "c"]
        assert result["truncated"] is False

    def test_lrange_with_explicit_stop(self, client):
        result = redis_lrange(client, "queue", start=0, stop=1)
        assert result["items"] == ["a", "b"]

    def test_sscan_returns_all_members_across_pages(self, client):
        seen = set()
        cursor = 0
        while True:
            page = redis_sscan(client, "tags", cursor)
            seen.update(page["members"])
            cursor = page["cursor"]
            if cursor == 0:
                break
        assert seen == {"red", "green", "blue"}

    def test_zrange_without_scores(self, client):
        result = redis_zrange(client, "scores")
        assert result["items"] == ["alice", "bob", "carol"]

    def test_zrange_with_scores(self, client):
        result = redis_zrange(client, "scores", with_scores=True)
        assert result["items"][0] == {"member": "alice", "score": 1.0}

    def test_dbsize_is_positive_with_seed_data_present(self, client):
        assert redis_dbsize(client) >= 5

    def test_ttl_of_a_key_with_no_expiry_is_minus_one(self, client):
        assert redis_ttl(client, "greeting") == -1

    def test_ttl_of_a_missing_key_is_minus_two(self, client):
        assert redis_ttl(client, "does-not-exist") == -2


class TestScanKeys:
    def test_finds_the_seeded_key(self, client):
        result = redis_scan_keys(client, pattern="greet*")
        assert "greeting" in result["keys"]
        assert "cursor" in result


class TestPaginationCaps:
    """The actual resource-exhaustion mitigation: no single call to any
    of these can make the server materialize/serialize an arbitrarily
    large collection, whatever the collection's real size."""

    def test_lrange_default_call_never_exceeds_the_cap(self, client):
        result = redis_lrange(client, "queue")
        assert len(result["items"]) <= commands_module.MAX_ITEMS_PER_CALL

    def test_lrange_truncated_flag_is_only_set_when_the_cap_was_actually_hit(self, client):
        # The seeded "queue" list has 3 elements — nowhere near the cap.
        result = redis_lrange(client, "queue")
        assert result["truncated"] is False


class TestTheAllowlistIsTheToolSurfaceItself:
    """The core architectural claim of this project: not that dangerous
    commands are checked and rejected, but that the code to send them
    doesn't exist here at all. This parses commands.py's actual syntax
    tree and inspects every method call made on something named
    "client" — deliberately not a substring search over the raw source,
    which would false-positive on the module's own docstrings
    explaining what ISN'T here (as an earlier version of this test
    briefly did)."""

    _DANGEROUS_METHOD_NAMES = {
        "eval", "evalsha", "fcall", "fcall_ro", "script",
        "config_set", "config_get", "config_resetstat", "config_rewrite",
        "module_load", "module_unload",
        "debug_segfault", "debug_object", "debug_sleep",
        "shutdown", "flushall", "flushdb",
        "slaveof", "replicaof",
        "acl_setuser", "acl_deluser", "acl_save", "acl_load",
        "client_kill", "client_pause",
        "keys",  # SCAN only, never bare KEYS
        "hgetall", "smembers",  # HSCAN/SSCAN only, never single-shot
        "info",  # Redis's own @dangerous category, see commands.py docstring
    }

    def test_no_dangerous_redis_py_call_appears_in_the_commands_module(self):
        import ast
        import inspect
        import textwrap

        source = textwrap.dedent(inspect.getsource(commands_module))
        tree = ast.parse(source)

        called_methods = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "client"
        }

        dangerous_found = called_methods & self._DANGEROUS_METHOD_NAMES
        assert not dangerous_found, f"commands.py calls client.{dangerous_found} — not allowed"

    def test_every_client_call_is_one_of_the_explicitly_reviewed_safe_methods(self):
        # The inverse check: an allowlist of what IS expected, so a
        # brand new (and not obviously dangerous-sounding) client
        # method being added later still gets noticed here rather than
        # silently passing just because it isn't on the deny-list above.
        import ast
        import inspect
        import textwrap

        expected = {
            "get", "mget", "type", "ttl", "exists", "scan",
            "hget", "hscan", "lrange", "sscan", "zrange", "dbsize",
        }

        source = textwrap.dedent(inspect.getsource(commands_module))
        tree = ast.parse(source)
        called_methods = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "client"
        }
        assert called_methods == expected, (
            f"commands.py's client.* calls changed: {called_methods}. "
            "If this is a deliberate new tool, review it against Redis's "
            "own ACL category for the command, then update this list."
        )
