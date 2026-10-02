"""Normalize only recognized git-host web views into clone/ref/path triples.

GitHub supports owner/repo tree and blob views; GitLab's /-/ separator
preserves nested group namespaces; Bitbucket uses owner/repo/src/ref/path.
Unknown hosts and unsupported shapes return None so extraction passes the
exact stripped remote to git, rather than guessing a different repository.
The first segment after the view marker is the ref; extraction retains its
existing bounded retry for refs containing a slash.
"""
from __future__ import annotations

from urllib.parse import urlparse


def extract_git_parts(url: str) -> tuple[str, str, str] | None:
    """Split a pasted URL into (clone_url, ref, subpath).

    Returns None when the URL doesn't look like a repo/treetop URL we can
    normalize (caller falls back to treating it as a plain remote).
    """
    u = url.strip()
    if not u.startswith(("http://", "https://")):
        return None
    parsed = urlparse(u)
    host = (parsed.hostname or "").lower()
    if host not in {"github.com", "www.github.com", "gitlab.com", "www.gitlab.com", "bitbucket.org", "www.bitbucket.org"}:
        return None
    segs = parsed.path.strip("/").split("/")
    if len(segs) < 2 or any(not s for s in segs):
        return None

    if host in {"gitlab.com", "www.gitlab.com"}:
        if "-" not in segs:
            return None  # preserve the entire nested clone path unchanged
        boundary = segs.index("-")
        if boundary < 2:
            return None
        repo_parts, rest = segs[:boundary], segs[boundary + 1:]
        markers = ("tree", "blob")
    else:
        repo_parts, rest = segs[:2], segs[2:]
        markers = ("src",) if host in {"bitbucket.org", "www.bitbucket.org"} else ("tree", "blob")

    if any(s in (".", "..") for s in repo_parts):
        return None
    repo_parts[-1] = repo_parts[-1].removesuffix(".git")
    if not repo_parts[-1]:
        return None
    base = f"{parsed.scheme}://{parsed.netloc}/{'/'.join(repo_parts)}"
    if not rest:
        return base, "", ""
    if rest[0] not in markers or len(rest) < 2 or rest[1] in (".", ".."):
        return None
    if rest[0] == "blob" and len(rest) < 3:
        return None  # a file view without a file cannot select the root
    # Keep selected-path components for extraction's containment check. An
    # escaping path must not fall back to auditing a plain-remote root.
    return base, rest[1], "/".join(rest[2:])
