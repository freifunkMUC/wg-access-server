"""Replaces the pages of the docs from before versioning with redirects.

They sit at the top of the gh-pages branch, next to the versions mike
publishes. Left alone, every link to them - from the README, from search
engines, from anywhere - would show that old state forever. Each one becomes a
redirect to the same page in "latest", or in "dev" for a page no release has
yet. The anchor of the link is kept.

Usage: redirect_unversioned.py GH_PAGES_CHECKOUT
"""

import json
import os
import shutil
import sys
from html import escape

# mike's own files at the top of the branch
MIKE_FILES = {"versions.json", "index.html", ".nojekyll", ".git"}

REDIRECT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting</title>
<link rel="canonical" href="{target}">
<meta http-equiv="refresh" content="0; url={target}">
<script>location.replace("{target}" + location.hash);</script>
</head>
<body><a href="{target}">This page has moved.</a></body>
</html>
"""

NOT_FOUND = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Page not found</title>
</head>
<body>
<h1>Page not found</h1>
<p>See the <a href="/wg-access-server/latest/">documentation of the latest release</a>.</p>
</body>
</html>
"""


def main(root):
    with open(os.path.join(root, "versions.json")) as f:
        versions = json.load(f)
    keep = set(MIKE_FILES)
    for version in versions:
        keep.add(version["version"])
        keep.update(version["aliases"])

    # every page of the old site: a directory with an index.html
    pages = []
    for entry in sorted(os.listdir(root)):
        if entry in keep:
            continue
        path = os.path.join(root, entry)
        if os.path.isdir(path):
            for dirpath, _, files in os.walk(path):
                if "index.html" in files:
                    pages.append(os.path.relpath(dirpath, root))
            shutil.rmtree(path)
        else:
            os.remove(path)

    for page in pages:
        target = "latest/"
        for version in ("latest", "dev"):
            if os.path.exists(os.path.join(root, version, page, "index.html")):
                target = f"{version}/{page}/"
                break
        # relative, so that it works wherever the site is served from
        relative = "../" * (page.count("/") + 1) + target
        os.makedirs(os.path.join(root, page), exist_ok=True)
        with open(os.path.join(root, page, "index.html"), "w") as f:
            f.write(REDIRECT.format(target=escape(relative, quote=True)))
        print(f"{page}/ -> {target}")

    with open(os.path.join(root, "404.html"), "w") as f:
        f.write(NOT_FOUND)


if __name__ == "__main__":
    main(sys.argv[1])
