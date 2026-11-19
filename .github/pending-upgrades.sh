#!/usr/bin/env bash
# Prints the number of pending Alpine package upgrades in an image (a fresh
# "apk update" inside it). A failing "apk update" or "docker run" fails the
# script rather than look like "nothing pending".
#   pending-upgrades.sh <image>
set -euo pipefail

upgrade=$(docker run --rm --platform linux/amd64 --user 0 --entrypoint sh "$1" \
  -c 'apk update >/dev/null && apk upgrade --simulate')
grep -cE '^\([0-9]+/[0-9]+\) ' <<< "$upgrade" || true
