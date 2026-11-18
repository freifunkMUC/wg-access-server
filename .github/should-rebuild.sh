#!/usr/bin/env bash
# Decides whether the daily rebuild publishes; prints push=true or push=false.
#   should-rebuild.sh <published image:tag> <base digest>
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

# A failing "apk update" or "docker run" must not look like "nothing pending".
upgrade=$(docker run --rm --platform linux/amd64 --user 0 --entrypoint sh "$image" \
  -c 'apk update >/dev/null && apk upgrade --simulate')
pending=$(grep -cE '^\([0-9]+/[0-9]+\) ' <<< "$upgrade" || true)
built_from=$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.base.digest" }}' "$image")

echo "Pending upgrades: $pending" >&2
echo "Base digest: published ${built_from:-none}, Dockerfile $base_digest" >&2
if [ "$pending" -gt 0 ] || [ "$built_from" != "$base_digest" ]; then
  echo "push=true"
else
  echo "up to date" >&2
  echo "push=false"
fi
