#!/bin/sh
set -e

BASE=/tmp/web-server-demo
REPLY=$BASE/reply.txt
SERVER_LOG=$BASE/server.log
CLIENT_LOG=$BASE/client.log

mkdir -p "$BASE"

./server > /dev/null 2> "$SERVER_LOG" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT

sleep 0.5

run_command() {
    echo "db> $1"
    printf '%s\n' "$1" | ./client 127.0.0.1 8032 > "$REPLY" 2> "$CLIENT_LOG"
    cat "$REPLY"
    echo
}

echo "web-server key-value store"
echo "========================="
echo
echo "Each command below opens a new encrypted client connection; the store is shared."
echo

run_command "set name John"
run_command "get name"
run_command "set name John Brown"
run_command "get name"
run_command "set city London"
run_command "print"
run_command "delete name"
run_command "get name"
run_command "print"
run_command "get missing"

echo "demo complete"
