"""Reading logrotate config far enough to say where a line is.

This module decides nothing. It locates text: which file, which line, which
block, which directive name. Every verdict about what a line *does* comes
from logrotate itself (see `plan.py`), because a second implementation of
logrotate's precedence rules would only be a second thing that can be wrong.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Directives that open a shell script running until `endscript`. Their
#: contents are shell, not logrotate directives, and must not be read as any.
SCRIPT_STARTERS = frozenset(
    {"prerotate", "postrotate", "firstaction", "lastaction", "preremove"}
)

#: Directives that select *when* a log rotates. logrotate keeps one answer,
#: so two of these in one block means the earlier one decides nothing.
#:
#: Plain `size` belongs here and `maxsize`/`minsize` do not, which is the
#: whole reason the set is written down. `size 100M` replaces the interval
#: outright -- logrotate's own plan stops mentioning `daily` at all -- while
#: `maxsize 100M` adds a second trigger and leaves the interval in place.
INTERVALS = frozenset({"hourly", "daily", "weekly", "monthly", "yearly", "size"})

#: Directives that come in pairs, mapped to the decision they both set. The
#: negation is not always `no` plus the name (`notifempty`, `maillast`), so
#: the table is spelled out rather than derived.
PAIRS = {
    "compress": "compress",
    "nocompress": "compress",
    "copy": "copy",
    "nocopy": "copy",
    "copytruncate": "copytruncate",
    "nocopytruncate": "copytruncate",
    "create": "create",
    "nocreate": "create",
    "createolddir": "createolddir",
    "nocreateolddir": "createolddir",
    "dateext": "dateext",
    "nodateext": "dateext",
    "delaycompress": "delaycompress",
    "nodelaycompress": "delaycompress",
    "ifempty": "ifempty",
    "notifempty": "ifempty",
    "mail": "mail",
    "nomail": "mail",
    "mailfirst": "mailwhen",
    "maillast": "mailwhen",
    "missingok": "missingok",
    "nomissingok": "missingok",
    "olddir": "olddir",
    "noolddir": "olddir",
    "sharedscripts": "sharedscripts",
    "nosharedscripts": "sharedscripts",
    "shred": "shred",
    "noshred": "shred",
    "su": "su",
    "nosu": "su",
}

#: Directives that accumulate rather than replace, so a second one is not a
#: sign the first was ignored. `tabooext +.foo` extends the list it is given.
ACCUMULATES = frozenset({"tabooext", "include"} | SCRIPT_STARTERS)


def group_of(name: str) -> str:
    """The decision a directive sets, for finding the ones that lost."""
    if name in INTERVALS:
        return "interval"
    return PAIRS.get(name, name)


@dataclass(frozen=True)
class Directive:
    name: str
    args: str
    #: 1-based, in the file it was written in.
    line: int

    @property
    def text(self) -> str:
        return f"{self.name} {self.args}".strip()


@dataclass
class Block:
    """One `patterns { ... }` definition."""

    file: str
    #: Line the first pattern is on.
    line: int
    patterns: list[str]
    #: The pattern text exactly as written, newlines and quotes included.
    #: logrotate echoes this back verbatim, so it is how a block in the
    #: config is matched to a block in logrotate's plan.
    pattern_text: str
    directives: list[Directive] = field(default_factory=list)


@dataclass
class ConfigFile:
    path: str
    blocks: list[Block] = field(default_factory=list)
    #: Directives outside any block, which become defaults for later blocks.
    globals: list[Directive] = field(default_factory=list)
    #: (line, argument) for each `include`.
    includes: list[tuple[int, str]] = field(default_factory=list)
    #: Lines as read, for the deletion check in `verify.py`.
    lines: list[str] = field(default_factory=list)


class ParseError(Exception):
    """The config is shaped in a way this reader does not handle.

    Raised rather than guessed around. A reader that silently skips what it
    does not understand reports a clean config for one it never read.
    """


def split_patterns(text: str) -> list[str]:
    """Split a block's pattern text the way logrotate's own lexer does.

    Whitespace separates, double quotes group, backslash escapes the next
    character. Single quotes are not special to logrotate and are not here.
    """
    out: list[str] = []
    current = ""
    started = False
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            current += text[index + 1]
            started = True
            index += 2
            continue
        if char == '"':
            quoted = not quoted
            started = True
        elif not quoted and char.isspace():
            if started:
                out.append(current)
            current = ""
            started = False
        else:
            current += char
            started = True
        index += 1
    if quoted:
        raise ParseError("unterminated quote in a log pattern")
    if started:
        out.append(current)
    return out


def _strip_comment(line: str) -> str:
    """Drop a whole-line comment.

    Only a `#` in the leading whitespace starts one. logrotate will take a
    `#` elsewhere too in some positions, but a path may contain one, and
    guessing wrong here would move a directive's line number.
    """
    return "" if line.lstrip().startswith("#") else line


def parse_file(path: str, text: str) -> ConfigFile:
    """Read one config file. Includes are followed by the caller."""
    config = ConfigFile(path=path, lines=text.splitlines())
    lines = config.lines

    index = 0
    header: list[str] = []
    header_line = 0

    while index < len(lines):
        raw = lines[index]
        line_number = index + 1
        content = _strip_comment(raw)
        stripped = content.strip()
        index += 1

        if not stripped:
            continue

        if not header:
            first = stripped.split(None, 1)
            name = first[0].lower()
            args = first[1].strip() if len(first) > 1 else ""
            if name == "include":
                config.includes.append((line_number, args))
                continue
            if name == "}":
                raise ParseError(f"{path}:{line_number}: `}}` with no block open")

        # A block header: pattern text, possibly over several lines, up to `{`.
        if "{" in stripped:
            before, _, after = content.partition("{")
            if after.strip():
                raise ParseError(
                    f"{path}:{line_number}: text after `{{`; logrotate wants "
                    "directives on their own lines"
                )
            header.append(before.rstrip())
            if not header_line:
                header_line = line_number
            pattern_text = "\n".join(part for part in header if part.strip())
            block = Block(
                file=path,
                line=header_line,
                patterns=split_patterns(pattern_text),
                pattern_text=pattern_text,
            )
            index = _parse_body(config, block, lines, index)
            config.blocks.append(block)
            header = []
            header_line = 0
            continue

        if header or _looks_like_pattern(stripped):
            header.append(content.rstrip())
            if not header_line:
                header_line = line_number
            continue

        first = stripped.split(None, 1)
        name = first[0].lower()
        args = first[1].strip() if len(first) > 1 else ""
        if name in SCRIPT_STARTERS:
            index = _skip_script(config.path, lines, index)
            config.globals.append(Directive(name=name, args=args, line=line_number))
            continue
        config.globals.append(Directive(name=name, args=args, line=line_number))

    if header:
        raise ParseError(f"{path}:{header_line}: log pattern with no `{{` after it")
    return config


def _looks_like_pattern(stripped: str) -> bool:
    """Is this line the start of a block header rather than a directive?

    logrotate decides by trying the first word as a directive name and
    treating anything else as a path. Paths in practice are absolute or
    quoted, which is what this tests -- a relative pattern outside a block
    would be misread, and `parse_file` raising later is how that surfaces.
    """
    return stripped.startswith(("/", '"', "'")) or stripped.startswith("~")


def _skip_script(path: str, lines: list[str], index: int) -> int:
    while index < len(lines):
        if lines[index].strip().lower() == "endscript":
            return index + 1
        index += 1
    raise ParseError(f"{path}: a script section is missing its `endscript`")


def _parse_body(config: ConfigFile, block: Block, lines: list[str], index: int) -> int:
    while index < len(lines):
        raw = lines[index]
        line_number = index + 1
        content = _strip_comment(raw)
        stripped = content.strip()
        index += 1

        if not stripped:
            continue
        if stripped == "}":
            return index
        if stripped.startswith("}"):
            raise ParseError(f"{config.path}:{line_number}: text after `}}`")

        first = stripped.split(None, 1)
        name = first[0].lower()
        args = first[1].strip() if len(first) > 1 else ""
        block.directives.append(Directive(name=name, args=args, line=line_number))
        if name in SCRIPT_STARTERS:
            index = _skip_script(config.path, lines, index)

    raise ParseError(f"{config.path}:{block.line}: block is never closed with `}}`")


def overridden(block: Block) -> list[tuple[Directive, Directive]]:
    """Directives in this block that a later one in the same block replaces.

    Returns (loser, winner) pairs. These are candidates only: logrotate is
    asked to confirm each one in `verify.py` before it is reported.
    """
    last: dict[str, Directive] = {}
    for directive in block.directives:
        if directive.name in ACCUMULATES:
            continue
        last[group_of(directive.name)] = directive

    pairs: list[tuple[Directive, Directive]] = []
    for directive in block.directives:
        if directive.name in ACCUMULATES:
            continue
        winner = last[group_of(directive.name)]
        if winner is not directive:
            pairs.append((directive, winner))
    return pairs
