#!/usr/bin/env bash
# Starts a local Redis container and provisions the restricted
# redisguard_readonly ACL user this project's own tests run against,
# plus a handful of seed keys the tests read back.
set -euo pipefail

CONTAINER_NAME="${REDIS_GUARD_DEV_CONTAINER:-redis-guard-dev}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  docker run -d --name "$CONTAINER_NAME" -p 6379:6379 redis:7-alpine
  # give the server a moment to accept connections
  for _ in $(seq 1 20); do
    docker exec "$CONTAINER_NAME" redis-cli PING >/dev/null 2>&1 && break
    sleep 0.5
  done
fi

# Rule ORDER matters: Redis ACL rules apply left to right, last match
# wins per command. CLIENT KILL/PAUSE/LIST/UNBLOCK are members of BOTH
# @admin and @connection — so +@connection must come BEFORE -@admin
# -@dangerous, or it silently re-grants those four admin-category
# commands (a real, empirically-confirmed bug in an earlier version of
# this script: the readonly user could run CLIENT PAUSE, a server-wide
# DoS primitive, despite -@admin being present).
docker exec "$CONTAINER_NAME" redis-cli ACL SETUSER redisguard_readonly reset on \
  '>redisguard_readonly_dev_pw' '~*' \
  '+@connection' '+@read' '-@write' '-@admin' '-@dangerous' \
  '+acl|whoami' '+acl|getuser' '+acl|dryrun'

# DEL first — this script must be safe to re-run. HSET/SADD/ZADD are
# naturally idempotent (keyed by field/member), but RPUSH is not: running
# it twice without clearing "queue" first silently duplicates every
# element (a real bug an earlier version of this script had).
docker exec "$CONTAINER_NAME" redis-cli DEL greeting user:1 queue tags scores >/dev/null
docker exec "$CONTAINER_NAME" redis-cli SET greeting "hello redis-guard"
docker exec "$CONTAINER_NAME" redis-cli HSET user:1 name "Ada" role "engineer"
docker exec "$CONTAINER_NAME" redis-cli RPUSH queue a b c
docker exec "$CONTAINER_NAME" redis-cli SADD tags red green blue
docker exec "$CONTAINER_NAME" redis-cli ZADD scores 1 alice 2 bob 3 carol

echo "redis-guard-dev container and redisguard_readonly ACL user are ready."
echo "REDIS_GUARD_TEST_URL=redis://redisguard_readonly:redisguard_readonly_dev_pw@127.0.0.1:6379/0"
