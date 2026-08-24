"""
Connection and privilege-check layer.

The primary defense in this project is architectural: no tool takes an
arbitrary command string, so there is no code path through which a
dangerous command could be sent regardless of what the connected user is
allowed to do (see commands.py). This module adds the second, independent
layer — real Redis ACL enforcement — and a way to verify it's actually in
place, the same role pg_check_privileges plays in pg-guard-mcp.

check_permissions() uses `ACL DRYRUN` — asking Redis directly "would this
exact command succeed for this user" — rather than re-deriving the answer
from the category rule list ourselves. An earlier version did the latter
and got it wrong twice, both confirmed by a security review that actually
ran the commands against a live server:

1. Rule ORDER matters (Redis ACL rules apply left to right, last match
   wins), and CLIENT KILL/PAUSE/LIST/UNBLOCK belong to *both* @admin and
   @connection — so a category list ending in "... -@admin +@connection"
   silently re-grants those four commands, and a naive "does +@admin
   appear anywhere" check can't see that at all.
2. ACL selectors (Redis 7+, per-key-pattern or per-command overrides) and
   individually-granted commands outside the category system (e.g. a
   bare "+flushall") were either not read or read-but-never-evaluated.

DRYRUN sidesteps all of that: it's Redis's own ACL engine answering the
question, not a re-implementation of Redis's own semantics living in this
file.
"""

from __future__ import annotations

import os

import redis

# Individual commands worth checking directly via ACL DRYRUN — not an
# exhaustive list of every dangerous command in Redis, but every command
# named in this project's own threat model (see README.md's "Why this
# exists"), plus the two @admin/@connection-overlap commands the ACL
# rule-order bug above was actually caught with.
_DANGEROUS_COMMAND_PROBES: list[tuple[str, ...]] = [
    ("EVAL", "return 1", "0"),
    ("EVALSHA", "0000000000000000000000000000000000000000", "0"),
    ("FCALL", "nonexistent", "0"),
    ("CONFIG", "GET", "dir"),
    ("CONFIG", "SET", "dir", "/tmp"),
    ("MODULE", "LIST"),
    ("FLUSHALL",),
    ("FLUSHDB",),
    ("SHUTDOWN", "NOSAVE"),
    ("DEBUG", "OBJECT", "nonexistent-key"),
    ("SLAVEOF", "NO", "ONE"),
    ("REPLICAOF", "NO", "ONE"),
    ("ACL", "SETUSER", "probe-only-never-created"),
    ("ACL", "DELUSER", "probe-only-never-created"),
    ("SAVE",),
    ("BGSAVE",),
    ("CLIENT", "KILL", "ID", "999999999"),
    ("CLIENT", "PAUSE", "0"),
    ("CLIENT", "LIST"),
    ("KEYS", "*"),
]


class MissingConfigError(RuntimeError):
    pass


def get_client() -> redis.Redis:
    url = os.environ.get("REDIS_GUARD_URL")
    if not url:
        raise MissingConfigError(
            "REDIS_GUARD_URL is not set — redis-guard-mcp refuses to guess "
            "a connection. Set it to a redis:// URL, ideally for a "
            "restricted read-only ACL user. See README.md."
        )
    return redis.from_url(url, decode_responses=True)


def check_permissions(client: redis.Redis) -> dict:
    """Report, per dangerous command, whether it would actually succeed
    for the connected user right now — verified with `ACL DRYRUN`
    against the live server, not re-derived from the ACL rule list.
    `would_succeed` should always be an empty list — the tool surface
    itself can't send any of these either way, but an empty list here
    means the privilege layer is also configured correctly, not just
    relied upon by omission."""
    username = client.acl_whoami()

    would_succeed = []
    for probe in _DANGEROUS_COMMAND_PROBES:
        verdict = client.acl_dryrun(username, *probe)
        if verdict == "OK":
            would_succeed.append(" ".join(probe))

    return {
        "username": username,
        "would_succeed": would_succeed,
        "commands_checked": len(_DANGEROUS_COMMAND_PROBES),
    }
