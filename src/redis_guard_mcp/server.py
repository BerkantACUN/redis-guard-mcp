"""
MCP tool surface for redis-guard-mcp.

Every tool wraps exactly one function from commands.py, which itself
wraps exactly one redis-py method mapping to exactly one safe Redis
command. There is deliberately no `redis_run_command(cmd, *args)` tool —
that escape hatch is exactly what let a "readonly: true"-labeled tool in
another MCP server actually execute EVAL and FLUSHALL. It doesn't exist
here to mislabel.
"""

from __future__ import annotations

import os
import sys

try:
    from mcp.server import MCPServer as _MCPServerImpl
except ImportError:  # SDK < 2.0
    from mcp.server.fastmcp import FastMCP as _MCPServerImpl  # type: ignore[no-redef]

import threading

import redis

from . import commands
from .client import MissingConfigError, check_permissions, get_client

mcp = _MCPServerImpl("redis-guard-mcp")

_client: redis.Redis | None = None
_client_lock = threading.Lock()


def _get_client() -> redis.Redis:
    # The MCP SDK dispatches synchronous tool calls onto separate worker
    # threads, so this lazy singleton is a genuine race, not a
    # theoretical one: two calls arriving shortly after startup could
    # both see _client is None and both construct a redis.Redis (with
    # its own connection pool), and the loser's pool would leak until
    # garbage collection eventually disconnects it.
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = get_client()
    return _client


def _safe(fn, *args, **kwargs) -> dict:
    try:
        # Always wrap in a {"result": ...} envelope, even when the
        # underlying value is itself a dict (e.g. HGETALL) — an earlier
        # version passed dict-shaped results through unwrapped, so a
        # caller couldn't tell whether to read result["result"] or the
        # top level without knowing the Redis type in advance.
        result = fn(_get_client(), *args, **kwargs)
        return {"result": result}
    except MissingConfigError as e:
        return {"error": "MissingConfig", "message": str(e)}
    except redis.exceptions.NoPermissionError as e:
        return {"error": "NoPermission", "message": str(e)}
    except Exception as e:
        return {"error": type(e).__name__, "message": str(e)}


@mcp.tool()
def redis_get(key: str) -> dict:
    """Get a string value by key. Returns null if the key doesn't exist."""
    return _safe(commands.redis_get, key)


@mcp.tool()
def redis_mget(keys: list[str]) -> dict:
    """Get multiple string values at once, as {key: value}."""
    return _safe(commands.redis_mget, keys)


@mcp.tool()
def redis_type(key: str) -> dict:
    """Report a key's Redis type (string/hash/list/set/zset/...)."""
    return _safe(commands.redis_type, key)


@mcp.tool()
def redis_ttl(key: str) -> dict:
    """Seconds until a key expires. -1 = no expiry, -2 = key doesn't exist."""
    return _safe(commands.redis_ttl, key)


@mcp.tool()
def redis_exists(keys: list[str]) -> dict:
    """Count how many of the given keys currently exist."""
    return _safe(commands.redis_exists, keys)


@mcp.tool()
def redis_scan_keys(pattern: str = "*", cursor: int = 0) -> dict:
    """One SCAN page of keys matching a glob pattern. Never blocks the
    server the way KEYS can on a large keyspace — pass the returned
    cursor back in as `cursor` to continue; 0 means done."""
    return _safe(commands.redis_scan_keys, pattern, cursor)


@mcp.tool()
def redis_hget(key: str, field: str) -> dict:
    """Get one field from a hash."""
    return _safe(commands.redis_hget, key, field)


@mcp.tool()
def redis_hscan(key: str, cursor: int = 0) -> dict:
    """One HSCAN page of a hash's fields. Pass the returned cursor back
    in as `cursor` to continue; 0 means done. Paginated rather than a
    single HGETALL, which can block a shared Redis server for as long
    as a large hash takes to serialize."""
    return _safe(commands.redis_hscan, key, cursor)


@mcp.tool()
def redis_lrange(key: str, start: int = 0, stop: int | None = None) -> dict:
    """A range of list elements, capped at 1000 per call. stop omitted
    means "as many as fit within the cap starting at start" — if
    `truncated` comes back true, call again with start advanced by
    len(items) to continue."""
    return _safe(commands.redis_lrange, key, start, stop)


@mcp.tool()
def redis_sscan(key: str, cursor: int = 0) -> dict:
    """One SSCAN page of a set's members, sorted. Pass the returned
    cursor back in as `cursor` to continue; 0 means done. Paginated
    rather than a single SMEMBERS, for the same reason HGETALL is
    avoided above."""
    return _safe(commands.redis_sscan, key, cursor)


@mcp.tool()
def redis_zrange(key: str, start: int = 0, stop: int | None = None, with_scores: bool = False) -> dict:
    """A range of sorted-set members, capped at 1000 per call, same
    pagination convention as redis_lrange."""
    return _safe(commands.redis_zrange, key, start, stop, with_scores)


@mcp.tool()
def redis_dbsize() -> dict:
    """Total number of keys in the current database."""
    return _safe(commands.redis_dbsize)


@mcp.tool()
def redis_check_permissions() -> dict:
    """Ask Redis's own ACL engine, via ACL DRYRUN, whether each of a
    curated list of dangerous commands (EVAL, CONFIG SET, FLUSHALL,
    SHUTDOWN, CLIENT KILL/PAUSE, ...) would actually succeed for the
    connected user right now. `would_succeed` should always be empty —
    the tool surface itself can't send any of these either way, but an
    empty list here means the privilege layer is also configured
    correctly, not just relied upon by omission."""
    return _safe(lambda client: check_permissions(client))


def main() -> None:
    if not os.environ.get("REDIS_GUARD_URL"):
        print(
            "redis-guard-mcp: REDIS_GUARD_URL is not set — every tool call will fail "
            "until it is. See README.md.",
            file=sys.stderr,
        )
    mcp.run()


if __name__ == "__main__":
    main()
