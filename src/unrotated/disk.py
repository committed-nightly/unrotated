"""Whether a log pattern matches anything, and when we cannot tell.

logrotate itself answers this, but only after it has become the user named
by `su`, which it cannot do when unrotated is run by an ordinary user. So
this module asks the filesystem the same question with the same syscalls.

The distinction that matters here is between "no file matches" and "I was
not allowed to look". A pattern under a directory this user cannot search
globs to nothing, and calling that an empty pattern would be a tidy, wrong
answer about a log that is rotating perfectly well.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass

#: Characters that make a path a glob to logrotate, which uses glob(3).
META = "*?["


@dataclass(frozen=True)
class Match:
    pattern: str
    #: Paths that exist now. Empty when nothing matched *or* when unknown.
    paths: tuple[str, ...]
    #: Set when the filesystem would not tell us, with the reason why.
    unknown: str = ""

    @property
    def is_glob(self) -> bool:
        return any(char in self.pattern for char in META)

    @property
    def matches_nothing(self) -> bool:
        return not self.paths and not self.unknown


def static_prefix(pattern: str) -> str:
    """The deepest directory of a pattern that contains no glob character.

    A glob can sit in a directory component -- `/var/log/ngin?/a.log` -- and
    the readability check has to climb above it. Stopping at the first
    dirname would try to scan a directory that cannot exist under any name,
    and report a pattern that matches fine as matching nothing.
    """
    head = os.path.dirname(pattern)
    while head and any(char in head for char in META):
        head = os.path.dirname(head)
    return head


def resolve(pattern: str) -> Match:
    """Expand one log pattern against the filesystem."""
    target = pattern

    if not any(char in target for char in META):
        try:
            os.stat(target)
        except FileNotFoundError:
            return Match(pattern=pattern, paths=())
        except PermissionError:
            return Match(
                pattern=pattern,
                paths=(),
                unknown="this user may not stat it; re-run as root to be sure",
            )
        except OSError as error:
            return Match(pattern=pattern, paths=(), unknown=f"stat failed: {error}")
        return Match(pattern=pattern, paths=(target,))

    directory = static_prefix(target)
    if directory:
        try:
            with os.scandir(directory) as entries:
                next(iter(entries), None)
        except FileNotFoundError:
            return Match(pattern=pattern, paths=())
        except PermissionError:
            return Match(
                pattern=pattern,
                paths=(),
                unknown=f"{directory} is not readable by this user; "
                "re-run as root to be sure",
            )
        except OSError as error:
            return Match(pattern=pattern, paths=(), unknown=f"cannot read {directory}: {error}")

    return Match(pattern=pattern, paths=tuple(sorted(glob.glob(target))))
