#!/bin/sh
# Publishes the documentation with mike, one version per minor release:
#
#   deploy.sh dev           the state of master, as "dev (unreleased)"
#   deploy.sh release TAG   a release: vX.Y.Z goes to vX.Y. The newest release
#                           becomes "latest", which is what visitors see first.
#   deploy.sh migrate       once: builds every minor release from its newest
#                           tag, and replaces the unversioned pages the docs had
#                           before with redirects to "latest"
#
# Writes to the local gh-pages branch; set DOCS_PUSH=1 to push it as well.
set -eu

cd "$(dirname "$0")/../.."
push=""
if [ "${DOCS_PUSH:-}" = "1" ]; then
	push="--push"
fi

# The newest release tag, vX.Y.Z; pre-releases are left out.
newest_release() {
	git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1
}

minor() {
	echo "$1" | sed -E 's/^(v[0-9]+\.[0-9]+)\..*/\1/'
}

# deploy_tag TAG [ALIAS]: builds the docs as they were at TAG. Older tags know
# nothing of mike, so a config next to theirs adds the version selector.
deploy_tag() {
	tag=$1
	shift
	version=$(minor "$tag")
	worktree=$(mktemp -d)
	git worktree add --quiet --detach "$worktree" "$tag"
	cat >"$worktree/mkdocs.mike.yml" <<EOF
INHERIT: mkdocs.yml
extra:
  version:
    provider: mike
EOF
	(
		cd "$worktree"
		mike deploy $push --config-file mkdocs.mike.yml --alias-type=redirect \
			--update-aliases --title "$version" "$version" "$@"
	)
	git worktree remove --force "$worktree"
}

# release TAG: the newest release becomes "latest"; a fix for an older minor
# release only updates that one.
release() {
	tag=$1
	# a release candidate would take the place of the release it precedes
	if ! echo "$tag" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
		echo "Not a release: $tag - no docs published."
		return
	fi
	if [ "$tag" = "$(newest_release)" ]; then
		deploy_tag "$tag" latest
		mike set-default $push latest
	else
		deploy_tag "$tag"
	fi
}

# The pages from before versioning sit at the top of gh-pages; see
# redirect_unversioned.py.
redirect_unversioned() {
	pages=$(mktemp -d)
	git worktree add --quiet "$pages" gh-pages
	python3 scripts/docs/redirect_unversioned.py "$pages"
	git -C "$pages" add --all
	if ! git -C "$pages" diff --cached --quiet; then
		git -C "$pages" commit --quiet -m "Redirect the unversioned docs to the latest release"
	fi
	git worktree remove --force "$pages"
	if [ -n "$push" ]; then
		git push origin gh-pages
	fi
}

dev() {
	# GitHub Pages does not follow symbolic links, so aliases are redirects
	mike deploy $push --alias-type=redirect --update-aliases --title "dev (unreleased)" dev
}

case "${1:-}" in
dev)
	dev
	;;
release)
	release "${2:?the release tag, e.g. v1.3.0}"
	;;
migrate)
	newest=$(newest_release)
	for version in $(git tag -l 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sed -E 's/^(v[0-9]+\.[0-9]+)\..*/\1/' | sort -uV); do
		# releases before 1.0 are the original project's
		case "$version" in v0.*) continue ;; esac
		tag=$(git tag -l "$version.*" | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)
		if [ "$tag" = "$newest" ]; then
			deploy_tag "$tag" latest
		else
			deploy_tag "$tag"
		fi
	done
	mike set-default $push latest
	# before the redirects: pages no release has yet redirect to dev
	dev
	redirect_unversioned
	;;
*)
	echo "usage: $0 dev | release TAG | migrate" >&2
	exit 2
	;;
esac
