#!/usr/bin/env bash
# Prints the base images of a Dockerfile as key=value lines:
#   base_name=<image of the final stage, without digest>
#   base_digest=<its digest, empty if it is not pinned>
#   build_digests=<digests of the other stages, sorted, comma separated>
# The build and the daily rebuild put them into the image labels.
#   base-image.sh [--pin] [Dockerfile]
# --pin first adds the current digest to every FROM that has none (the daily
# rebuild of an older release, whose Dockerfile was not pinned yet). Only
# plain registry references are handled: a FROM that names an earlier stage or
# takes an ARG is not resolved, and the build then fails instead of going on.
set -euo pipefail

pin=false
if [ "${1:-}" = --pin ]; then pin=true; shift; fi
dockerfile=${1:-Dockerfile}

if [ "$pin" = true ]; then
  tmp=$(mktemp)
  re='^[Ff][Rr][Oo][Mm][[:space:]]+(--[^[:space:]]+[[:space:]]+)*([^[:space:]@]+)([[:space:]]|$)'
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ $line =~ $re ]]; then
      ref=${BASH_REMATCH[2]}
      digest=$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}')
      line=${line/"$ref"/"$ref@$digest"}
    fi
    printf '%s\n' "$line" >> "$tmp"
  done < "$dockerfile"
  cat "$tmp" > "$dockerfile"
  rm -f "$tmp"
fi

refs=$(awk 'toupper($1) == "FROM" { for (i = 2; i <= NF; i++) if ($i !~ /^--/) { print $i; break } }' "$dockerfile")
[ -n "$refs" ] || { echo "No FROM in $dockerfile" >&2; exit 1; }

final=$(tail -n1 <<< "$refs")
echo "base_name=${final%@*}"
case "$final" in *@sha256:*) echo "base_digest=${final##*@}" ;; *) echo "base_digest=" ;; esac
echo "build_digests=$(head -n -1 <<< "$refs" | grep -o 'sha256:[0-9a-f]*' | sort -u | paste -sd, - || true)"
