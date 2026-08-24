"""
Read-only Redis operations. Every function here calls exactly one
redis-py method that maps to exactly one safe Redis command — there is
no function anywhere in this module that accepts a command name or a
raw command string. That is the actual security property this project
provides: not a check that rejects EVAL/CONFIG/FLUSHALL, but the literal
absence of any code path that could send them.

Every "give me a collection" tool here is cursor-based and/or capped —
never a single call that can make the server materialize and serialize
an entire, arbitrarily large collection in one shot. `redis_scan_keys`
uses `SCAN`, `redis_hscan` uses `HSCAN`, `redis_sscan` uses `SSCAN` —
never bare `KEYS`, `HGETALL`, or `SMEMBERS`, which are all single-shot
and can block a shared Redis server for as long as the collection takes
to serialize (this is exactly why `KEYS` was excluded — the same
argument applies to `HGETALL`/`SMEMBERS` on a large hash/set, just less
famously). `redis_lrange`/`redis_zrange` cap how many elements a single
call can return, for the same reason applied to lists and sorted sets.

Deliberately not exposed: `INFO`. It reads like a harmless
server-metadata command, but Redis itself categorizes it as `@dangerous`
(it's `nondeterministic_output` and touches cluster-sensitive state) —
this project trusts Redis's own category assignments rather than
overriding them with its own judgment call, so nothing here maps to a
command outside `@read` except the three narrow, purely self-
introspective exceptions `client.py` needs for its own permission check
(`ACL WHOAMI`/`ACL GETUSER`/`ACL DRYRUN`, which only ever answer "what
can the connected user do", never touching data or server state) and
`@connection` (for a working `PING`).
"""

from __future__ import annotations

import redis

# Applies to SCAN/HSCAN/SSCAN's COUNT hint and to LRANGE/ZRANGE's
# returned span — a single call is capped at this many items so no tool
# here can ask the server to materialize and serialize an arbitrarily
# large chunk of a collection in one shot on a shared Redis instance.
MAX_ITEMS_PER_CALL = 1000

# redis_mget/redis_exists take a caller-supplied key list directly
# (there's no cursor concept for "get these specific keys") — capped
# with a clear error instead, since silently dropping some of the keys
# the caller asked about would be more surprising than refusing.
MAX_KEYS_PER_CALL = 200


class TooManyKeysError(ValueError):
    pass


def redis_get(client: redis.Redis, key: str) -> str | None:
    return client.get(key)


def redis_mget(client: redis.Redis, keys: list[str]) -> dict[str, str | None]:
    if len(keys) > MAX_KEYS_PER_CALL:
        raise TooManyKeysError(
            f"{len(keys)} keys requested, max {MAX_KEYS_PER_CALL} per call"
        )
    values = client.mget(keys)
    return dict(zip(keys, values))


def redis_type(client: redis.Redis, key: str) -> str:
    return client.type(key)


def redis_ttl(client: redis.Redis, key: str) -> int:
    """Seconds until expiry. -1 means no expiry set, -2 means the key
    doesn't exist (redis-py/Redis's own TTL semantics, passed through
    as-is rather than reinterpreted)."""
    return client.ttl(key)


def redis_exists(client: redis.Redis, keys: list[str]) -> int:
    if len(keys) > MAX_KEYS_PER_CALL:
        raise TooManyKeysError(
            f"{len(keys)} keys requested, max {MAX_KEYS_PER_CALL} per call"
        )
    return client.exists(*keys)


def redis_scan_keys(client: redis.Redis, pattern: str = "*", cursor: int = 0) -> dict:
    """One SCAN page of keys matching a glob pattern. Pass the returned
    cursor back in as `cursor` to continue; 0 means iteration is done."""
    next_cursor, keys = client.scan(cursor=cursor, match=pattern, count=MAX_ITEMS_PER_CALL)
    return {"cursor": next_cursor, "keys": keys}


def redis_hget(client: redis.Redis, key: str, field: str) -> str | None:
    return client.hget(key, field)


def redis_hscan(client: redis.Redis, key: str, cursor: int = 0) -> dict:
    """One HSCAN page of a hash's fields. Pass the returned cursor back
    in as `cursor` to continue; 0 means iteration is done. Never a
    single-shot HGETALL, which can block a shared Redis server for as
    long as a large hash takes to serialize."""
    next_cursor, fields = client.hscan(key, cursor=cursor, count=MAX_ITEMS_PER_CALL)
    return {"cursor": next_cursor, "fields": fields}


def redis_lrange(client: redis.Redis, key: str, start: int = 0, stop: int | None = None) -> dict:
    """A range of list elements, capped at MAX_ITEMS_PER_CALL per call.
    stop=None means "as many as fit within the cap starting at start" —
    call again with start advanced by the number of items returned to
    page through a longer list."""
    effective_stop = start + MAX_ITEMS_PER_CALL - 1 if stop is None else min(stop, start + MAX_ITEMS_PER_CALL - 1)
    items = client.lrange(key, start, effective_stop)
    return {"items": items, "truncated": len(items) == MAX_ITEMS_PER_CALL}


def redis_sscan(client: redis.Redis, key: str, cursor: int = 0) -> dict:
    """One SSCAN page of a set's members. Pass the returned cursor back
    in as `cursor` to continue; 0 means iteration is done. Never a
    single-shot SMEMBERS, for the same reason HGETALL is avoided above."""
    next_cursor, members = client.sscan(key, cursor=cursor, count=MAX_ITEMS_PER_CALL)
    return {"cursor": next_cursor, "members": sorted(members)}


def redis_zrange(
    client: redis.Redis, key: str, start: int = 0, stop: int | None = None, with_scores: bool = False
) -> dict:
    """A range of sorted-set members, capped at MAX_ITEMS_PER_CALL per
    call, same pagination convention as redis_lrange."""
    effective_stop = start + MAX_ITEMS_PER_CALL - 1 if stop is None else min(stop, start + MAX_ITEMS_PER_CALL - 1)
    result = client.zrange(key, start, effective_stop, withscores=with_scores)
    items = [{"member": member, "score": score} for member, score in result] if with_scores else result
    return {"items": items, "truncated": len(items) == MAX_ITEMS_PER_CALL}


def redis_dbsize(client: redis.Redis) -> int:
    return client.dbsize()
