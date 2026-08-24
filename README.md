# redis-guard-mcp

A Redis MCP server whose "read-only" isn't a label — it's the entire tool
surface. Every tool maps to exactly one safe, read-only Redis command
through `redis-py`'s typed API. There is no "run this command string" tool
to mislabel.

## Why this exists

Redis is one of the most deployed pieces of infrastructure in professional
backends (cache, session store, queue, rate limiter, pub/sub), and its
command surface includes some of the most dangerous single commands in any
widely-used data store:

- **`EVAL`/`EVALSHA`/`FCALL`** — arbitrary Lua execution inside the Redis
  process.
- **`CONFIG SET dir` + `CONFIG SET dbfilename` + `SAVE`** — the standard,
  widely-documented technique for writing an arbitrary file (e.g. a web
  shell into a web root, or a cron job) to disk through Redis alone.
- **`MODULE LOAD`** — loads an arbitrary shared library into the Redis
  process. Direct RCE if an attacker can get a `.so`/`.dll` onto disk.
- **`FLUSHALL`/`FLUSHDB`** — deletes every key in the database, immediately,
  no confirmation.
- **`SHUTDOWN`, `DEBUG`, `SLAVEOF`/`REPLICAOF`, `ACL`, `CLIENT KILL`** —
  server-crashing, replication-hijacking, permission-rewriting, and
  session-terminating admin surface.

A published audit of MCP servers found one where a command-execution tool
was labeled `readonly: true` in its metadata but still accepted and ran
`EVAL` and `FLUSHALL` — the metadata was decorative, not enforced. Checked
directly against the **official** `redis/mcp-redis` server: its own
documentation states the only mitigation for any of the above is
configuring Redis ACLs yourself — the server ships with no built-in
blocking of `EVAL`, `FLUSHALL`, `CONFIG`, `MODULE`, or `DEBUG`, and no
read-only mode of its own. Safety is entirely the operator's responsibility,
by default, out of the box.

## How redis-guard-mcp is different

1. **The allowlist isn't a filter — it's the tool surface.** Nothing in
   this server takes an arbitrary command string. Every tool is a specific
   Python function that calls one specific `redis-py` method (`r.get(key)`,
   `r.hget(key, field)`, ...). There is no code path through which `EVAL`,
   `CONFIG`, `MODULE`, `FLUSHALL`, or any other command not explicitly
   implemented as its own tool could ever be sent — not because it's
   checked and rejected, but because the client code to send it simply
   doesn't exist here.
2. **Real privilege enforcement too, not just app-level restriction.** The
   recommended (and startup-checked) setup connects with a Redis ACL user
   created with `+@read -@write -@admin -@dangerous`. Even a bug in this
   server's own code couldn't run a write or admin command against a
   correctly-configured connection, because Redis itself would refuse it
   at the protocol level. **Rule order matters** — `CLIENT KILL`/`PAUSE`/
   `LIST`/`UNBLOCK` belong to *both* `@admin` and `@connection`, so
   `... -@admin +@connection` (the wrong order) silently re-grants those
   four commands. This is not a hypothetical: an early version of this
   project's own setup script had exactly that ordering, and a security
   review *ran `CLIENT PAUSE` against the shipped "correctly-configured"
   user and it worked* — a server-wide DoS primitive, from a user this
   project's own documentation claimed couldn't do it. Fixed by putting
   `+@connection` first; see `scripts/setup_dev_redis.sh` for the correct
   order and a comment explaining why it can't be swapped back.
3. **Cursor-based, never single-shot, for every collection.** `KEYS` is in
   Redis's own built-in `@dangerous` category because a single call can
   block the entire server serializing a large keyspace — the same is
   true of `HGETALL` on a large hash and `SMEMBERS` on a large set, just
   less famously. Every "give me a collection" tool here is either
   cursor-based (`redis_scan_keys`/`redis_hscan`/`redis_sscan`) or capped
   at 1000 items per call with an explicit `truncated` flag
   (`redis_lrange`/`redis_zrange`) — never a call that can make the
   server materialize an arbitrarily large collection in one shot.
4. **A privilege check that asks Redis, not a re-implementation of Redis's
   own semantics.** `redis_check_permissions()` uses `ACL DRYRUN` — Redis's
   own "would this command actually succeed for this user" answer — against
   a curated list of dangerous commands, rather than trying to re-derive
   the answer from parsing the ACL rule list (which is exactly how the
   rule-order bug above happened: a category-list read in isolation can't
   see that `@admin` and `@connection` overlap). `would_succeed` should
   always come back empty.

## Tools

| Tool | Does |
|---|---|
| `redis_get(key)` | Get a string value |
| `redis_mget(keys)` | Get multiple string values as `{key: value}` (max 200 keys) |
| `redis_type(key)` | Report a key's Redis type |
| `redis_ttl(key)` | Seconds until expiry (-1 none, -2 missing) |
| `redis_exists(keys)` | Count how many of the given keys exist (max 200 keys) |
| `redis_scan_keys(pattern="*", cursor=0)` | One SCAN page of matching keys |
| `redis_hget(key, field)` | One hash field |
| `redis_hscan(key, cursor=0)` | One HSCAN page of a hash's fields |
| `redis_lrange(key, start=0, stop=None)` | List elements, capped at 1000 per call |
| `redis_sscan(key, cursor=0)` | One SSCAN page of a set's members, sorted |
| `redis_zrange(key, start=0, stop=None, with_scores=False)` | Sorted set members, capped at 1000 per call |
| `redis_dbsize()` | Total key count |
| `redis_check_permissions()` | Ground-truth `ACL DRYRUN` check against a curated dangerous-command list — `would_succeed` should always be empty |

## Setup

```bash
pip install redis-guard-mcp
export REDIS_GUARD_URL="redis://readonly_user:password@localhost:6379/0"
redis-guard-mcp
```

`REDIS_GUARD_URL` is required — there is no default. Point your MCP client at the `redis-guard-mcp` command with it set in its env config. See `scripts/setup_dev_redis.sh` for a working, correctly-*ordered* example of provisioning the restricted ACL user (`+@connection +@read -@write -@admin -@dangerous`, plus the three narrow `ACL WHOAMI`/`ACL GETUSER`/`ACL DRYRUN` exceptions `redis_check_permissions` itself needs — see `client.py` for why those are safe to grant despite being individually outside `@read`).

## Testing

```bash
pip install -e ".[dev]"
scripts/setup_dev_redis.sh   # starts a Redis container + provisions the ACL user + seeds data
pytest tests/ -v
```

34 tests, almost all against the real local container (a couple of pure config-validation tests need no Redis and skip-check independently); skips automatically if the container isn't reachable. Includes a regression test for the exact `CLIENT PAUSE` rule-order bug above, and an AST-based structural test asserting the precise set of `redis-py` methods `commands.py` calls, so a new tool being added later gets noticed here rather than silently passing review.

## Status

v0.1.0. Went through adversarial security review before its first commit, which found and this now fixes: the ACL rule-order bug above (confirmed by actually running `CLIENT PAUSE` against the shipped setup), two blind spots in the original category-based permission check (now replaced with `ACL DRYRUN`), unbounded collection reads on a shared Redis instance (now capped/paginated), a non-idempotent dev seed script, and a lazy-singleton thread-safety race in the MCP tool layer.

## License

MIT
