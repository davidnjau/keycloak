#!/usr/bin/env bash
# wait-for-it.sh (no nc needed, works with bash)

set -e

host_port="$1"
shift
cmd="$@"

host=$(echo $host_port | cut -d: -f1)
port=$(echo $host_port | cut -d: -f2)

echo "Waiting for $host:$port..."

while ! (echo > /dev/tcp/$host/$port) >/dev/null 2>&1; do
  sleep 2
done

>&2 echo "$host:$port is up - executing command"
exec $cmd
