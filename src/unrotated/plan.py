"""Running logrotate and reading back what it decided.

`logrotate -d` prints the plan it would carry out: which config files it
read, which it ignored and why, and for every block the schedule and options
it resolved. That output is the only authority in this program.

It is also a debug format with no stability promise, so every shape it is
read with is anchored and a line that does not fit raises. Reporting a clean
config because the output stopped parsing is the one failure this module is
written to avoid.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

#: The strings logrotate prints for a resolved rotation criterion, measured
#: against logrotate 3.21.0 (see probe/schedules.sh). Note that `weekly 3`
#: prints plain "weekly": the weekday is not in the plan, which is why the
#: deletion check in `verify.py` needs a control.
#: logrotate 3.21 prints exactly these six and nothing else; the list is the
#: format strings out of the binary, not a guess at them.
SCHEDULE = r"hourly|weekly|monthly|yearly|after \d+ days|\d+ bytes"

#: And exactly one of these two for how many old logs it keeps.
_TAIL = r"\((?P<rotations>\d+) rotations\)|\((?P<kept>no old logs will be kept)\)"

_HEADER = re.compile(
    rf"rotating pattern: (?P<pattern>.*)[ \t]{{1,2}}(?P<schedule>{SCHEDULE})"
    rf" (?:{_TAIL})\Z",
    re.DOTALL,
)
_DUPLICATE = re.compile(
    r"error: (?P<file>.*):(?P<line>\d+) duplicate log entry for (?P<path>.*)\Z"
)
_IGNORED_TABOO = re.compile(
    r"Ignoring (?P<name>.*), because of (?P<pattern>\S+) pattern match\Z"
)
_IGNORED_OTHER = re.compile(r"Ignoring (?P<name>.*) because it's not a regular file\.\Z")
_CANNOT_STAT = re.compile(r"error: cannot stat (?P<path>.*): (?P<reason>.*)\Z")
_STAT_FAILED = re.compile(r"error: stat of (?P<path>.*) failed: (?P<reason>.*)\Z")
_MISSING_LOG = re.compile(r"log (?P<path>.*) does not exist -- skipping\Z")
_EUID = re.compile(r"error: error switching euid")
_CONFIG_ERROR = re.compile(r"error: (?P<file>[^:]+):(?P<line>\d+) (?P<message>.*)\Z")

#: How many lines a block header may span before we give up on it. A real one
#: spans as many lines as the block has pattern lines.
_HEADER_LINE_LIMIT = 200


class LogrotateError(Exception):
    """logrotate could not be run, or said something we will not guess at."""


@dataclass
class PlanBlock:
    """One block as logrotate resolved it."""

    pattern_text: str
    schedule: str
    #: None when logrotate says "no old logs will be kept".
    rotations: int | None
    options: str = ""
    #: Every log logrotate said it was considering for this block. When a
    #: glob matched nothing, logrotate considers the pattern itself.
    considered: list[str] = field(default_factory=list)
    #: Logs logrotate looked at and found absent, by the path it printed.
    missing: list[str] = field(default_factory=list)
    #: logrotate found no log to rotate for this block at all.
    no_logs: bool = False
    #: logrotate could not become the user named by `su`, so it stopped
    #: before looking at this block's logs. Nothing about them is known.
    privilege_blocked: bool = False

    @property
    def patterns_normalised(self) -> str:
        return " ".join(self.pattern_text.split())

    def signature(self) -> tuple:
        """What this block decides, with nothing time- or path-dependent.

        Compared before and after a line is deleted. State timestamps and
        config file names are left out so the only thing that can move it is
        a change in what logrotate would do.
        """
        return (
            self.patterns_normalised,
            self.schedule,
            self.rotations,
            self.options,
            tuple(sorted(self.considered)),
            tuple(sorted(self.missing)),
            self.no_logs,
            self.privilege_blocked,
        )


@dataclass
class Duplicate:
    file: str
    line: int
    path: str


@dataclass
class IgnoredConfig:
    directory: str
    name: str
    reason: str


@dataclass
class Plan:
    """Everything logrotate told us about one invocation."""

    #: Config files read, in the order read, resolved to paths.
    files_read: list[str] = field(default_factory=list)
    #: Directories reached by an `include`.
    included_dirs: list[str] = field(default_factory=list)
    ignored_configs: list[IgnoredConfig] = field(default_factory=list)
    #: (path, reason) for an `include` logrotate could not stat.
    unreachable_includes: list[tuple[str, str]] = field(default_factory=list)
    duplicates: list[Duplicate] = field(default_factory=list)
    blocks: list[PlanBlock] = field(default_factory=list)
    #: Parse errors logrotate reported in the config, as file:line, message.
    config_errors: list[tuple[str, int, str]] = field(default_factory=list)
    version: str = ""
    #: The raw output, so a surprise can be read rather than inferred.
    output: str = ""

    def signature(self) -> tuple:
        return tuple(block.signature() for block in self.blocks)


def version(binary: str = "logrotate") -> str:
    path = shutil.which(binary)
    if path is None:
        raise LogrotateError(
            f"{binary} is not on PATH; unrotated has nothing to ask and will not guess"
        )
    try:
        completed = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
    except OSError as error:  # pragma: no cover - needs an unexecutable binary
        raise LogrotateError(f"could not run {path}: {error}") from error
    first = (completed.stdout or completed.stderr).strip().splitlines()
    return first[0] if first else "unknown"


def run(config: str, state: str, binary: str = "logrotate") -> str:
    """Run `logrotate -d` and return its combined output.

    `-d` makes no changes. A throwaway state file is passed so the answer
    does not depend on when this machine last rotated anything, and so we
    never touch the real one.
    """
    path = shutil.which(binary)
    if path is None:
        raise LogrotateError(
            f"{binary} is not on PATH; unrotated has nothing to ask and will not guess"
        )
    argv = [path, "-d", "-s", state, config]
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=120, check=False
        )
    except subprocess.TimeoutExpired as error:
        raise LogrotateError(f"{binary} did not finish within 120s") from error
    except OSError as error:  # pragma: no cover - needs an unexecutable binary
        raise LogrotateError(f"could not run {path}: {error}") from error
    output = completed.stdout + completed.stderr
    if not output.strip():
        raise LogrotateError(f"{binary} -d printed nothing for {config}")
    return output


def parse_output(output: str, config: str) -> Plan:
    """Turn `logrotate -d` output into a Plan, or raise."""
    plan = Plan(output=output)
    lines = output.splitlines()
    include_dir = ""
    index = 0
    saw_handling = False

    while index < len(lines):
        line = lines[index].rstrip()
        stripped = line.strip()
        index += 1

        if stripped.startswith("rotating pattern: "):
            block, index = _read_header(lines, index - 1)
            plan.blocks.append(block)
            index = _read_block_detail(lines, index, block)
            continue

        if stripped.startswith("including "):
            include_dir = stripped[len("including ") :].strip()
            plan.included_dirs.append(include_dir)
            continue

        if stripped.startswith("reading config file "):
            name = stripped[len("reading config file ") :].strip()
            plan.files_read.append(_resolve(name, include_dir, config))
            continue

        if stripped.startswith("Handling ") and stripped.endswith(" logs"):
            saw_handling = True
            continue

        match = _IGNORED_TABOO.fullmatch(stripped)
        if match:
            plan.ignored_configs.append(
                IgnoredConfig(
                    directory=include_dir,
                    name=match["name"],
                    reason=f"its name matches the taboo pattern {match['pattern']}",
                )
            )
            continue

        match = _IGNORED_OTHER.fullmatch(stripped)
        if match:
            plan.ignored_configs.append(
                IgnoredConfig(
                    directory=include_dir,
                    name=match["name"],
                    reason="it is not a regular file",
                )
            )
            continue

        match = _CANNOT_STAT.fullmatch(stripped)
        if match:
            plan.unreachable_includes.append((match["path"], match["reason"]))
            continue

        match = _DUPLICATE.fullmatch(stripped)
        if match:
            plan.duplicates.append(
                Duplicate(
                    file=_resolve(match["file"], include_dir, config),
                    line=int(match["line"]),
                    path=match["path"],
                )
            )
            continue

        match = _CONFIG_ERROR.fullmatch(stripped)
        if match and not stripped.startswith("error: found error in file"):
            plan.config_errors.append(
                (
                    _resolve(match["file"], include_dir, config),
                    int(match["line"]),
                    match["message"],
                )
            )
            continue

    if not saw_handling:
        raise LogrotateError(
            "logrotate -d output has no 'Handling N logs' line, so it is not the "
            "plan this version of unrotated knows how to read:\n"
            + "\n".join(lines[:20])
        )
    return plan


def _resolve(name: str, include_dir: str, config: str) -> str:
    """Give a config file name as printed back as a usable path.

    Files found through an `include` are printed by basename only.
    """
    import os

    if name == os.path.basename(config) and not include_dir:
        return config
    if "/" in name:
        return name
    if include_dir:
        candidate = os.path.join(include_dir, name)
        if os.path.exists(candidate):
            return candidate
    return name


def _read_header(lines: list[str], index: int) -> tuple[PlanBlock, int]:
    """Read a `rotating pattern:` header, which may span several lines.

    logrotate echoes the pattern text out of the config verbatim, newlines
    and all, then appends the schedule. So the end of the header is the only
    thing that can be anchored on.
    """
    accumulated = lines[index].strip()
    cursor = index + 1
    for _ in range(_HEADER_LINE_LIMIT):
        match = _HEADER.fullmatch(accumulated)
        if match:
            block = PlanBlock(
                pattern_text=match["pattern"],
                schedule=match["schedule"],
                rotations=int(match["rotations"]) if match["rotations"] else None,
            )
            return block, cursor
        if cursor >= len(lines):
            break
        accumulated += "\n" + lines[cursor].rstrip()
        cursor += 1
    raise LogrotateError(
        "could not read the end of a `rotating pattern:` header. unrotated knows "
        f"these rotation criteria: {SCHEDULE.replace('|', ', ')}. The header was:\n"
        + accumulated[:600]
    )


def _read_block_detail(lines: list[str], index: int, block: PlanBlock) -> int:
    """Read the lines after a header that belong to that block."""
    first = True
    while index < len(lines):
        stripped = lines[index].strip()
        if stripped.startswith("rotating pattern: "):
            return index
        index += 1

        # The line straight after a header is logrotate's summary of the
        # block's options. Everything after it is per-log detail.
        if (
            first
            and stripped
            and stripped != "No logs found. Rotation not needed."
            and not stripped.startswith(("considering log", "error:", "Creating new state"))
        ):
            block.options = stripped
            first = False
            continue
        first = False

        if stripped == "No logs found. Rotation not needed.":
            block.no_logs = True
            continue
        if stripped.startswith("considering log "):
            block.considered.append(stripped[len("considering log ") :])
            continue
        if _EUID.match(stripped):
            block.privilege_blocked = True
            continue
        match = _MISSING_LOG.fullmatch(stripped)
        if match:
            block.missing.append(match["path"])
            continue
        match = _STAT_FAILED.fullmatch(stripped)
        if match:
            block.missing.append(match["path"])
            continue
    return index


def plan_for(config: str, state: str, binary: str = "logrotate") -> Plan:
    plan = parse_output(run(config, state, binary=binary), config)
    plan.version = version(binary)
    return plan
