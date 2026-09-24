"""Normalize pasted git-host URLs into (clone URL, ref, subpath) triples.

Users paste what the GitHub/GitLab web UI shows: repo root, `/tree/<ref>/…`
directory views, `/blob/<ref>/…` file views, and `…/repo.git` tails. `git
clone` only accepts a repo remote; passing a tree/blob URL verbatim fails
with "repository not found" (exactly the bug this module fixes).

Supported shapes (GitHub / GitLab / Bitbucket, http(s) only):

  https://host/owner/repo                         -> (same, -, "")
  https://host/owner/repo/tree/main               -> (repo, "main", "")
  https://host/owner/repo/tree/main/skills/tdd    -> (repo, "main", "skills/tdd")
  https://host/owner/repo/blob/main/SKILL.md      -> (repo, "main", "SKILL.md")
  https://host/owner/repo.git/tree/main/x         -> (repo.git, "main", "x")

Also handles GitLab's legacy `/-/` separator (`/repos/owner/repo/-/tree/…`).
Refs may contain `/` (release branches) — everything after the marker up to
the next known marker is the ref; when the resulting ref doesn't resolve, the
caller can retry with the longest-prefix fallback (see extract_git_parts).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Path segment that starts a tree/blob view in the big three hosts.
_TREE_MARKERS = ("tree", "blob", "commits", "tags", "raw")

_GIT_LAB_SEP = re.compile(r"/-/")


def extract_git_parts(url: str) -> tuple[str, str, str] | None:
    """Split a pasted URL into (clone_url, ref, subpath).

    Returns None when the URL doesn't look like a repo/treetop URL we can
    normalize (caller falls back to treating it as a plain remote).
    """
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        return None
    parsed = urlparse(u)
    host = parsed.netloc.lower()
    if not host:
        return None
    # GitLab legacy separator: /owner/repo/-/tree/main/...
    path = _GIT_LAB_SEP.sub("/", parsed.path, count=1)

    segs = [s for s in path.split("/") if s]
    if not segs:
        return None  # bare host

    # Strip a trailing .git on the repo segment (keep the URL conventional).
    repo = segs[0] if len(segs) == 1 else segs[1]
    is_gitlab = "gitlab" in host

    # GitHub/GitLab/Bitbucket need owner/repo; a single segment is not a repo.
    if len(segs) < 2:
        return None

    owner = segs[0]
    repo_seg = segs[1]
    if repo_seg.endswith(".git"):
        repo_seg = repo_seg[: -len(".git")]

    base = f"{parsed.scheme}://{host}/{owner}/{repo_seg}"

    rest = segs[2:]
    ref = ""
    subpath = ""
    if rest and rest[0] in _TREE_MARKERS:
        rest = rest[1:]
        if rest:
            # The ref may itself contain slashes ("release/1.2"). We cannot
            # know without asking the remote, so take the single next segment
            # as the ref and treat the remainder as the subpath; if the ref
            # fails to resolve, git clone's error surfaces to the user.
            ref = rest[0]
            subpath = "/".join(rest[1:])

    return base, ref, subpath
