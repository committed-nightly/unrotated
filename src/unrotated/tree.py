"""Loading the whole config set, and mirroring it somewhere writable.

Which files make up a logrotate config is not a question this program
answers: `include` can name a directory, and which of that directory's files
logrotate reads depends on taboo patterns, on the `tabooext` directive, and
on what counts as a regular file. So the file list comes out of logrotate's
own plan, and this module only arranges what the plan already named.

The mirror exists so the deletion check in `verify.py` can blank a line
without writing to the config it was pointed at -- which, by default, is
/etc/logrotate.conf.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .parse import ConfigFile, parse_file
from .plan import Plan


@dataclass
class Include:
    #: Line of the `include` directive in its own file.
    line: int
    argument: str
    #: "dir", "file", or "unreachable". Kept because mirroring a single-file
    #: include as a directory include would not be the same config: taboo
    #: patterns only apply to the files logrotate finds in a directory.
    kind: str
    children: list["Node"] = field(default_factory=list)


@dataclass
class Node:
    config: ConfigFile
    includes: list[Include] = field(default_factory=list)


@dataclass
class Tree:
    root: Node

    def nodes(self) -> list[Node]:
        out: list[Node] = []

        def walk(node: Node) -> None:
            out.append(node)
            for include in node.includes:
                for child in include.children:
                    walk(child)

        walk(self.root)
        return out

    def files(self) -> list[ConfigFile]:
        return [node.config for node in self.nodes()]

    def blocks_in_read_order(self) -> list:
        return [block for config in self.files() for block in config.blocks]


def _read(path: str) -> ConfigFile:
    with open(path, encoding="utf-8", errors="surrogateescape") as handle:
        return parse_file(path, handle.read())


def load(config: str, plan: Plan) -> Tree:
    """Parse every file logrotate said it read, keeping the include structure."""
    # Paths are kept as logrotate printed them -- usually relative, when it
    # was given a relative config -- so that a finding's file:line is
    # something the reader can paste into an editor. Absolute forms are used
    # only to decide whether two paths are the same file.
    originals = {os.path.abspath(path): path for path in plan.files_read}
    read = list(originals)
    unreachable = {os.path.abspath(path) for path, _ in plan.unreachable_includes}
    directories = {os.path.abspath(path) for path in plan.included_dirs}
    seen: set[str] = set()

    def build(path: str) -> Node:
        absolute = os.path.abspath(path)
        seen.add(absolute)
        node = Node(config=_read(path))
        for line, argument in node.config.includes:
            target = os.path.abspath(
                os.path.join(os.path.dirname(absolute), os.path.expanduser(argument))
            )
            if target in unreachable or not os.path.exists(target):
                node.includes.append(Include(line=line, argument=argument, kind="unreachable"))
                continue
            if target in directories or os.path.isdir(target):
                members = [
                    originals[candidate]
                    for candidate in read
                    if os.path.dirname(candidate) == target and candidate not in seen
                ]
                kind = "dir"
            elif target in read and target not in seen:
                members = [originals[target]]
                kind = "file"
            else:
                # logrotate never reported reading it, or we have been here
                # already. Not ours to explain: the plan's `ignored_configs`
                # carries the reason it was skipped.
                node.includes.append(
                    Include(line=line, argument=argument, kind="dir" if os.path.isdir(target) else "file")
                )
                continue
            node.includes.append(
                Include(
                    line=line,
                    argument=argument,
                    kind=kind,
                    children=[build(member) for member in members],
                )
            )
        return node

    return Tree(root=build(config))


def mirror(tree: Tree, destination: str) -> tuple[str, dict[str, str]]:
    """Write a copy of the config set under `destination`.

    Returns the path of the mirrored top-level file, and a map from each
    original config path to its copy. Include arguments are rewritten to
    point inside the mirror; an unreachable include is rewritten to a path
    that is also absent, so logrotate still reports it missing.
    """
    paths: dict[str, str] = {}
    count = 0

    def place(node: Node, target: str) -> None:
        nonlocal count
        paths[os.path.abspath(node.config.path)] = target
        rewrites: dict[int, str] = {}

        for include in node.includes:
            count += 1
            slot = os.path.join(destination, f"inc{count}")
            if include.kind == "unreachable":
                # Absent in the mirror too, so logrotate reports it missing
                # there as well and the two plans stay comparable.
                rewrites[include.line] = f"include {slot}"
                continue
            if include.kind == "dir":
                os.makedirs(slot, exist_ok=True)
                rewrites[include.line] = f"include {slot}"
                for child in include.children:
                    place(child, os.path.join(slot, os.path.basename(child.config.path)))
                continue
            # A single file: mirrored as a file include, not a directory one.
            if include.children:
                only = os.path.join(slot, os.path.basename(include.children[0].config.path))
                rewrites[include.line] = f"include {only}"
                place(include.children[0], only)
            else:
                rewrites[include.line] = f"include {slot}"

        lines = list(node.config.lines)
        for line, replacement in rewrites.items():
            lines[line - 1] = replacement
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8", errors="surrogateescape") as handle:
            handle.write("\n".join(lines) + "\n")

    root = os.path.join(destination, "root", os.path.basename(tree.root.config.path))
    place(tree.root, root)
    return root, paths
