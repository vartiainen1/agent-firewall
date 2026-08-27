"""Deterministic normalization and controlled resource matching.

Responsibility (IMPLEMENTATION 7): represent input canonically. This module
does NOT decide authorization -- it only canonicalizes agents, actions and
resources so the evaluator can match them deterministically.

Security properties preserved here:
  * path traversal ("./src/../secret", "..", absolute paths that escape the
    workspace) can never change which normalized resource a request maps to
    relative to a likewise-normalized policy pattern;
  * normalization failures fail closed (SPEC 15, SECURITY 22);
  * resource patterns use a *controlled* glob language -- no regex, no raw
    fnmatch-on-whole-path (SPEC 14, SECURITY 27).
"""

from typing import List, Optional, Sequence, Tuple

from .model import InvalidRequestError

# Action prefix that marks a resource as a filesystem path.
_FILESYSTEM_PREFIX = "filesystem."


def validate_request(request) -> "Request":
    """Validate a request; raise InvalidRequestError when malformed."""
    agent = getattr(request, "agent", None)
    action = getattr(request, "action", None)
    resource = getattr(request, "resource", None)
    if not isinstance(agent, str) or not agent.strip():
        raise InvalidRequestError("agent must be a non-empty string")
    if not isinstance(action, str) or not action.strip():
        raise InvalidRequestError("action must be a non-empty string")
    if resource is not None and not isinstance(resource, str):
        raise InvalidRequestError("resource must be a string when present")
    return request


def _is_filesystem(action: str) -> bool:
    return action.startswith(_FILESYSTEM_PREFIX)


def _is_absolute(path: str) -> bool:
    """Return True for an absolute filesystem path (platform independent).

    Phase 1 resources are workspace-relative. Recognised as invalid absolute
    forms (checked on the raw string so behaviour does not depend on the
    host OS -- these are the raw leading sequences, before any separator
    normalization):
      * POSIX root:  starts with a forward slash (for example /etc/passwd);
      * Windows drive prefix: starts with a letter then a colon
        (for example C:..., either drive-root via C:/... or bare C:...);
      * UNC share:  starts with two backslash characters (or two forward
        slashes when expressed as //server/share/...).
    A bare drive path is rejected too: it is drive-scoped and carries no
    workspace-relative meaning.
    """
    if path.startswith("/"):
        return True
    if len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        return True
    if path.startswith("\\"):
        return True
    return False


def normalize_path(path: str) -> str:
    """Lexically normalize a filesystem path to a canonical POSIX form.

    Rules (deterministic, case-sensitive):
      * both '\\' and '/' are treated as separators;
      * Phase 1 resources are workspace-relative; an ABSOLUTE path (POSIX
        '/', Windows drive 'C:', or UNC '\\') is INVALID and raises
        InvalidRequestError instead of being reinterpreted as relative;
      * '.' segments are dropped;
      * '..' removes the previous segment, but only while the path stays at
        or above the workspace base;
      * a '..' that would rise ABOVE the workspace base is a root-escape
        attempt and raises InvalidRequestError (fail closed) -- it is never
        turned into a different apparently-valid resource (SECURITY 14);
      * the result has no leading './'.

    Because policy patterns are normalized with the exact same function,
    absolute and root-escaping patterns fail closed at load, and a traversal
    trick such as './src/../.env' maps to '.env' on both the request side
    and the pattern side, so it can never reach a resource the policy author
    did not grant while legitimate relative normalization still works
    (DESIGN 19, TEST_PLAN 10).
    """
    if not isinstance(path, str):
        raise InvalidRequestError("filesystem resource must be a string")
    if _is_absolute(path):
        raise InvalidRequestError(
            "absolute paths are invalid; resources must be workspace-relative")
    parts = path.replace("\\", "/").split("/")
    stack: List[str] = []
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                raise InvalidRequestError(
                    "path attempts to escape the workspace root")
            stack.pop()
            continue
        stack.append(part)
    return "/".join(stack)


def _segment_match(segment: str, pattern: str) -> bool:
    """Match ONE path segment against a pattern supporting only '*' and '?'.

    '*' matches any sequence of characters (including none) within the
    segment; '?' matches exactly one character. Both are case-sensitive and
    neither crosses a '/' because matching happens one segment at a time.

    No regex and no character classes are part of the Phase 1 contract; '[',
    ']', '.' etc. are treated literally except for the two wildcards.
    """
    si = 0
    pi = 0
    n = len(segment)
    m = len(pattern)
    star = -1
    match = 0
    while si < n:
        if pi < m and pattern[pi] == "*":
            star = pi
            match = si
            pi += 1
        elif pi < m and (pattern[pi] == segment[si] or pattern[pi] == "?"):
            pi += 1
            si += 1
        elif star != -1:
            pi = star + 1
            match += 1
            si = match
        else:
            return False
    while pi < m and pattern[pi] == "*":
        pi += 1
    return pi == m


def _segments_match(segments: Sequence[str], pattern: Sequence[str]) -> bool:
    """Match normalized target segments against normalized pattern segments.

    A pattern segment equal to '**' spans zero or more target segments;
    every other pattern segment is matched with _segment_match. All matching
    operates on already-normalized segments, so '.'/'..' traversal cannot be
    smuggled through resource names at this layer.
    """

    def rec(si: int, pi: int) -> bool:
        if pi >= len(pattern):
            return si >= len(segments)
        p = pattern[pi]
        if p == "**":
            if rec(si, pi + 1):
                return True
            if si < len(segments):
                return rec(si + 1, pi)
            return False
        if si >= len(segments):
            return False
        if _segment_match(segments[si], p):
            return rec(si + 1, pi + 1)
        return False

    return rec(0, 0)


def split_segments(value: str) -> Tuple[str, ...]:
    """Split an already-normalized POSIX resource into its segments."""
    if value == "":
        return ()
    return tuple(value.split("/"))


def normalize_request_resource(action: str, resource: Optional[str]) -> Optional[Tuple[str, ...]]:
    """Return the normalized matching segments of a request's resource.

    Filesystem resources are lexically normalized then split into path
    segments. Non-filesystem resources are treated as a single opaque
    segment so that wildcards never accidentally span separators in host
    names or process names (DESIGN 18/21/22).
    """
    if resource is None:
        return None
    if _is_filesystem(action):
        return split_segments(normalize_path(resource))
    return (resource,)


def normalize_pattern_segments(action: str, resource: Optional[str]) -> Optional[Tuple[str, ...]]:
    """Normalize a policy rule's resource pattern into matching segments."""
    if resource is None:
        return None
    if _is_filesystem(action):
        return split_segments(normalize_path(resource))
    return (resource,)


def resource_matches(segments: Optional[Tuple[str, ...]],
                     pattern: Optional[Tuple[str, ...]]) -> bool:
    """Return whether normalized request segments match a normalized pattern.

    A ``None`` pattern means the rule applies to the action generally and
    therefore matches any resource (SPEC 10). A non-None request resource
    that is ``None`` (request carried no resource) never matches a
    resource-scoped pattern.
    """
    if pattern is None:
        return True
    if segments is None:
        return False
    return _segments_match(segments, pattern)