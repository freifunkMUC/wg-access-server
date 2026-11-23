#!/usr/bin/env bash
# Decides whether the daily rebuild publishes; prints push=true or push=false.
#   should-rebuild.sh <published image:tag> <base digest>
# Also prints pending_only=<n> if the pending upgrades are the only reason; the
# workflow then publishes only if the fresh build has fewer (see its Compare step).
# Publishes if the image is not there yet, if the published image has pending
# Alpine package upgrades (a fresh "apk update" inside it), or if it was built
# from another base image than the Dockerfile pins now. FORCE=true publishes
# regardless. Anything unexpected fails rather than looking like "nothing
# pending".
set -euo pipefail

image=$1 base_digest=$2

if [ "${FORCE:-false}" = true ]; then
  echo "Forced" >&2
  echo "push=true"
  exit 0
fi

if ! out=$(docker pull --quiet --platform linux/amd64 "$image" 2>&1); then
  if grep -qiE 'not found|manifest unknown' <<< "$out"; then
    echo "Nothing published yet" >&2
    echo "push=true"
    exit 0
  fi
  echo "Cannot pull $image: $out" >&2
  exit 1
fi

pending=$("$(dirname "$0")/pending-upgrades.sh" "$image")
built_from=$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.base.digest" }}' "$image")

echo "Pending upgrades: $pending" >&2
echo "Base digest: published ${built_from:-none}, Dockerfile $base_digest" >&2
if [ "$pending" -gt 0 ] || [ "$built_from" != "$base_digest" ]; then
  echo "push=true"
  # Only the pending upgrades call for it: the fresh build must have fewer.
  if [ "$built_from" = "$base_digest" ]; then echo "pending_only=$pending"; fi
else
  echo "up to date" >&2
  echo "push=false"
fi
