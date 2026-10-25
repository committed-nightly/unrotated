"""Joining logrotate's plan to the config text, and saying what is dead."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass, field

from . import disk
from .parse import Block, ParseError, overridden
from .plan import LogrotateError, Plan, plan_for
from .tree import Tree, load, mirror
from .verify import Checker, Verdict


class ConfigPathError(OSError):
    """The path given is not something unrotated can read as a config.

    An OSError because that is what it is, and because the command line
    already turns one into exit 2 with the message on stderr.
    """


class AlignmentError(Exception):
    """logrotate's plan and the config we read do not describe the same set.

    Raised instead of carrying on with whichever blocks happened to line up.
    Every finding here is anchored to a file and a line, and an anchor that
    has drifted by one block is worse than no finding at all.
    """


@dataclass(frozen=True)
class Finding:
    kind: str
    file: str
    #: 0 when the finding is about a whole file rather than a line in one.
    line: int
    detail: str
    subject: str = ""
    #: Where logrotate went instead, as `file:line`.
    instead: str = ""
    #: "confirmed", "invisible", or "" when this kind is not deletion-checked.
    checked: str = ""

    def sort_key(self) -> tuple:
        return (self.file, self.line, self.kind, self.subject)


@dataclass
class Result:
    config: str
    version: str = ""
    files_read: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    #: "checked", "skipped" (--no-verify), or "unavailable" with a note.
    verification: str = "skipped"
    verification_note: str = ""
    confirmed: int = 0
    invisible: int = 0
    rejected: list[str] = field(default_factory=list)
    logrotate_runs: int = 1
    #: Blocks logrotate stopped short of because it could not become the
    #: user named by `su`. Nothing is known about their logs.
    blocked_blocks: list[str] = field(default_factory=list)
    #: (pattern, reason) for patterns the filesystem would not answer for.
    unknown_patterns: list[tuple[str, str]] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=Finding.sort_key)


def _align(tree: Tree, plan: Plan) -> list[tuple[Block, object]]:
    """Pair config blocks with plan blocks, in the order logrotate read them."""
    blocks = tree.blocks_in_read_order()
    if len(blocks) != len(plan.blocks):
        raise AlignmentError(
            f"logrotate planned {len(plan.blocks)} blocks and unrotated read "
            f"{len(blocks)} from the same files. unrotated will not guess which "
            "is which; nothing is reported."
        )
    for block, planned in zip(blocks, plan.blocks):
        ours = " ".join(block.pattern_text.split())
        theirs = planned.patterns_normalised
        if ours != theirs:
            raise AlignmentError(
                f"{block.file}:{block.line}: unrotated read this block's logs as "
                f"{ours!r} and logrotate reported {theirs!r}. Nothing is reported."
            )
    return list(zip(blocks, plan.blocks))


def _claimant(pairs: list, path: str, before: tuple[str, int]) -> str:
    """The earlier block that took a log path, for a duplicate entry.

    Read out of the logs logrotate said it was considering, rather than by
    expanding the earlier blocks' patterns again and hoping the two
    expansions agree.
    """
    for block, planned in pairs:
        if (block.file, block.line) == before:
            break
        if path in planned.considered:
            return f"{block.file}:{block.line}"
    return ""


_NOT_REGULAR = (
    (stat.S_ISFIFO, "a named pipe"),
    (stat.S_ISSOCK, "a socket"),
    (stat.S_ISBLK, "a block device"),
    (stat.S_ISCHR, "a character device"),
)


def _refuse_unreadable(config: str) -> None:
    """Reject a config path this program cannot read, before anything runs.

    `analyse` asks logrotate for its plan before it opens the config
    itself, so without this check the cost of a bad argument is logrotate's
    to decide rather than ours. For a directory that is a wasted subprocess
    and a bare `Is a directory` at the end of it; for a named pipe it is
    the full 120s timeout, because logrotate's own open() blocks waiting
    for a writer that is never coming.
    """
    mode = os.stat(config).st_mode  # absent or unsearchable: the OS says so, now
    if stat.S_ISDIR(mode):
        raise ConfigPathError(
            f"{config} is a directory, and unrotated reads one config file plus the "
            "files it includes. Point it at the config that includes this directory, "
            "usually /etc/logrotate.conf."
        )
    if not stat.S_ISREG(mode):
        kind = next((name for test, name in _NOT_REGULAR if test(mode)), "not a regular file")
        raise ConfigPathError(
            f"{config} is {kind}, not a regular file. unrotated reads its config more "
            "than once, so it will not start one it cannot read twice."
        )
    with open(config, "rb"):  # unreadable: likewise, and before the subprocess
        pass


def analyse(config: str, binary: str = "logrotate", verify: bool = True) -> Result:
    """Run logrotate over `config` and report the lines with no effect."""
    _refuse_unreadable(config)
    with tempfile.TemporaryDirectory(prefix="unrotated-") as workdir:
        plan = plan_for(config, os.path.join(workdir, "state0"), binary=binary)
        result = Result(config=config, version=plan.version, files_read=list(plan.files_read))
        tree = load(config, plan)
        pairs = _align(tree, plan)

        for path, line, message in plan.config_errors:
            result.errors.append(f"logrotate rejected {path}:{line}: {message}")

        # Consulted only for the blocks logrotate's own answer does not
        # settle: the ones it was stopped short of, and the ones it found no
        # log for without saying why. Everywhere else its answer is the
        # better one and a second expansion here would only disagree with it.
        matches: dict[str, disk.Match] = {}
        for block, planned in pairs:
            if not (planned.privilege_blocked or planned.no_logs):
                continue
            for pattern in block.patterns:
                if pattern not in matches:
                    matches[pattern] = disk.resolve(pattern)

        _config_findings(result, plan)
        _include_findings(result, tree)
        _pattern_findings(result, plan, pairs, matches)
        _duplicate_findings(result, plan, pairs)

        if verify:
            _verify(result, tree, plan, pairs, workdir, binary)
        else:
            for block, _ in pairs:
                for loser, winner in overridden(block):
                    result.findings.append(_override_finding(block, loser, winner, ""))

    return result


def _config_findings(result: Result, plan: Plan) -> None:
    for ignored in plan.ignored_configs:
        path = os.path.join(ignored.directory, ignored.name) if ignored.directory else ignored.name
        result.findings.append(
            Finding(
                kind="config-never-read",
                file=path,
                line=0,
                subject=ignored.name,
                detail=(
                    f"logrotate found this file in {ignored.directory or 'the include'} "
                    f"and did not read it, because {ignored.reason}. Every directive in "
                    "it is dead, and outside -d or -v logrotate says so to nobody"
                ),
            )
        )


def _include_findings(result: Result, tree: Tree) -> None:
    for node in tree.nodes():
        for include in node.includes:
            if include.kind == "unreachable":
                result.findings.append(
                    Finding(
                        kind="include-missing",
                        file=node.config.path,
                        line=include.line,
                        subject=include.argument,
                        detail=(
                            f"`include {include.argument}` reads nothing: logrotate "
                            "cannot stat it. This one is not silent -- logrotate "
                            "reports it and exits 1 -- but from a cron job that "
                            "nobody reads, the effect is the same"
                        ),
                    )
                )


def _pattern_findings(result: Result, plan: Plan, pairs: list, matches: dict) -> None:
    """Patterns that rotate nothing.

    logrotate answers this itself, per log, and its answer is used wherever
    it gave one: it expands a glob differently from a plain glob(3) call on
    the same string -- a relative pattern in an `include`d file does not
    expand at all -- so expanding the pattern here and comparing would be
    comparing against the wrong thing.

    What it will not do is say *why* a block ended up with no logs. "No logs
    found. Rotation not needed." is printed both when an earlier block took
    them and when the glob could not be expanded at all, and on this machine
    the second is what /etc/logrotate.d/chrony hits: `/var/log/chrony` is
    mode 750 and owned by `_chrony`, so an ordinary user's glob comes back
    empty for a directory that is rotating fine. So a reason is only given
    when there is evidence for one, and a block nobody could look into is
    reported as undetermined rather than as dead.
    """
    claimed_at = {(duplicate.file, duplicate.line) for duplicate in plan.duplicates}

    for block, planned in pairs:
        if planned.privilege_blocked:
            result.blocked_blocks.append(f"{block.file}:{block.line}")
            _fallback_findings(
                result,
                block,
                matches,
                "logrotate could not check this block, and the filesystem has nothing for",
            )
            continue

        dead = [pattern for pattern in block.patterns if pattern in planned.missing]
        for pattern in dead:
            _add_dead_pattern(result, block, pattern, "logrotate found nothing to rotate for")

        if not planned.no_logs or len(dead) == len(block.patterns):
            continue

        if (block.file, block.line) in claimed_at:
            # logrotate named a log of this block as a duplicate, so its logs
            # demonstrably went somewhere else.
            live = [pattern for pattern in block.patterns if pattern not in dead]
            result.findings.append(
                Finding(
                    kind="rotates-nothing",
                    file=block.file,
                    line=block.line,
                    subject=" ".join(live),
                    detail=(
                        "logrotate reports 'No logs found. Rotation not needed.' for "
                        "this block: every log it names was already claimed by an "
                        "earlier block, and a log belongs to exactly one of them"
                    ),
                )
            )
            continue

        # No duplicate, no missing log named, and no logs either. logrotate's
        # glob came back empty and it did not say why, so go and look.
        _fallback_findings(
            result,
            block,
            matches,
            "logrotate found no log at all for this block, and the filesystem "
            "has nothing for",
        )


def _add_dead_pattern(result: Result, block: Block, pattern: str, lead: str) -> None:
    is_glob = any(char in pattern for char in disk.META)
    missingok = any(directive.name == "missingok" for directive in block.directives)
    what = "matches no file" if is_glob else "does not exist"
    # Measured: without `missingok` logrotate reports this and exits 1. With
    # it, logrotate exits 0 and prints nothing at all -- and `missingok` is
    # set by almost every packaged drop-in, which is why these survive.
    tail = (
        ", and `missingok` means logrotate exits 0 over it without a word"
        if missingok
        else ". logrotate does report this one, and exits 1"
    )
    result.findings.append(
        Finding(
            kind="pattern-matches-nothing" if is_glob else "log-missing",
            file=block.file,
            line=block.line,
            subject=pattern,
            detail=f"{lead} `{pattern}`: it {what} on this machine{tail}",
        )
    )


def _fallback_findings(result: Result, block: Block, matches: dict, lead: str) -> None:
    """Ask the filesystem about a block logrotate did not settle.

    A pattern this user is not allowed to expand is recorded as undetermined.
    It is the one answer that is always available and always wrong.
    """
    for pattern in block.patterns:
        match = matches.get(pattern)
        if match is None:
            continue
        if match.unknown:
            result.unknown_patterns.append((pattern, match.unknown))
            continue
        if match.matches_nothing:
            _add_dead_pattern(result, block, pattern, lead)


def _duplicate_findings(result: Result, plan: Plan, pairs: list) -> None:
    for duplicate in plan.duplicates:
        claimant = _claimant(pairs, duplicate.path, (duplicate.file, duplicate.line))
        result.findings.append(
            Finding(
                kind="duplicate-log-entry",
                file=duplicate.file,
                line=duplicate.line,
                subject=duplicate.path,
                instead=claimant,
                detail=(
                    f"logrotate already had {duplicate.path} from an earlier block, so "
                    "this one does not rotate it. logrotate reports this and exits 1, "
                    "which from a nightly cron job is a mail nobody reads"
                ),
            )
        )


def _override_finding(block: Block, loser, winner, checked: str) -> Finding:
    if loser.name in {"hourly", "daily", "weekly", "monthly", "yearly"} and winner.name == "size":
        detail = (
            f"`{loser.text}` never decides a rotation: `{winner.text}` in the same "
            "block replaces the interval outright rather than adding to it. "
            "`maxsize` is the one that keeps the interval"
        )
    else:
        detail = (
            f"`{loser.text}` has no effect: `{winner.text}` later in the same block "
            "sets the same thing, and logrotate keeps the last one"
        )
    return Finding(
        kind="overridden-directive",
        file=block.file,
        line=loser.line,
        subject=loser.text,
        instead=f"{block.file}:{winner.line}",
        detail=detail,
        checked=checked,
    )


def _verify(result: Result, tree: Tree, plan: Plan, pairs: list, workdir: str, binary: str) -> None:
    candidates = [(block, loser, winner) for block, _ in pairs for loser, winner in overridden(block)]

    mirror_dir = os.path.join(workdir, "mirror")
    os.makedirs(mirror_dir, exist_ok=True)
    try:
        root_path, paths = mirror(tree, mirror_dir)
        checker = Checker(root_path, paths, workdir, binary=binary)
    except (LogrotateError, OSError, ParseError) as error:
        result.verification = "unavailable"
        result.verification_note = f"could not copy the config to check it: {error}"
        for block, loser, winner in candidates:
            result.findings.append(_override_finding(block, loser, winner, ""))
        return

    if checker.baseline != plan.signature():
        result.verification = "unavailable"
        result.verification_note = (
            "a copy of this config does not produce the same plan as the original, "
            "so a deletion check on the copy would not be about your config"
        )
        result.logrotate_runs += checker.runs
        for block, loser, winner in candidates:
            result.findings.append(_override_finding(block, loser, winner, ""))
        return

    result.verification = "checked"
    for block, loser, winner in candidates:
        check = checker.check(block, loser, winner)
        if check.verdict is Verdict.REJECTED:
            result.rejected.append(
                f"{block.file}:{loser.line}: `{loser.text}` looked dead and is not: "
                f"blanking it changes logrotate's plan"
            )
            continue
        if check.verdict is Verdict.CONFIRMED:
            result.confirmed += 1
        else:
            result.invisible += 1
        result.findings.append(
            _override_finding(block, loser, winner, check.verdict.value)
        )
    result.logrotate_runs += checker.runs
