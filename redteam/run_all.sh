#!/bin/bash
#   Run every red-team attack against a running server
#
#   Author: Giselle Wu, Dartmouth CS60, Fall 2026
#            Assisted by Claude (Anthropic): wrote the attack scripts
#
#   run: bash redteam/run_all.sh <server_port>
#   start the server first, in a directory with helloworld.html, english_words.txt and a .env

if [ -z "$1" ]; then
    echo "Usage: bash redteam/run_all.sh <server_port>"
    exit 1
fi
cd "$(dirname "$0")"
ulimit -n 8192 2>/dev/null #the flood attacker needs lots of sockets

status=0
for script in framing.py limits.py paths.py floods.py; do
    echo "=== $script ==="
    python3 "$script" "$1" || status=1
    echo
done
exit $status
