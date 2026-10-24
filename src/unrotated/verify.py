"""Confirming a dead directive by deleting it and asking logrotate again.

Reading a config and saying "the second `rotate` wins" is a claim about
logrotate's precedence rules. Blanking the first `rotate` line and getting
a byte-identical plan back is a measurement of them.

The check needs a control, because logrotate's plan does not mention every
directive it honours. `compress` does not appear in it at all, so deleting a
live `compress` also leaves the plan unchanged -- and a checker without the
control would read that silence as proof and report every `compress` it was
handed. So each candidate is tested twice: blank the loser, and blank the
winner. Only a candidate whose winner *does* move the plan has been tested
at all.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum

from .parse import Block, Directive
from .plan import LogrotateError, parse_output, run


class Verdict(str, Enum):
    #: Blanking the loser left the plan alone; blanking the winner changed
    #: it. The directive has no effect and logrotate agrees.
    CONFIRMED = "confirmed"
    #: Neither line moves the plan, so the plan cannot see this directive.
    #: The finding stands on the config text alone.
    INVISIBLE = "invisible"
    #: Blanking the loser changed the plan. We were wrong about it.
    REJECTED = "rejected"


@dataclass
class Check:
    block: Block
    loser: Directive
    winner: Directive
    verdict: Verdict


class Checker:
    """Runs logrotate over a mirrored config with one line blanked out."""

    def __init__(self, root: str, paths: dict[str, str], workdir: str, binary: str = "logrotate"):
        self.root = root
        self.paths = paths
        self.workdir = workdir
        self.binary = binary
        self.runs = 0
        self._originals = {
            mirrored: self._read(mirrored) for mirrored in paths.values() if os.path.exists(mirrored)
        }
        self.baseline = self._signature()

    @staticmethod
    def _read(path: str) -> list[str]:
        with open(path, encoding="utf-8", errors="surrogateescape") as handle:
            return handle.read().splitlines()

    def _write(self, path: str, lines: list[str]) -> None:
        with open(path, "w", encoding="utf-8", errors="surrogateescape") as handle:
            handle.write("\n".join(lines) + "\n")

    def _signature(self) -> tuple:
        state = os.path.join(self.workdir, f"state{self.runs}")
        self.runs += 1
        output = run(self.root, state, binary=self.binary)
        return parse_output(output, self.root).signature()

    def _without(self, config_path: str, line: int) -> tuple:
        """The plan with one line blanked.

        Blanked rather than removed so every other line keeps its number,
        which keeps a mirror readable when a run has to be debugged by hand.
        """
        mirrored = self.paths[os.path.abspath(config_path)]
        original = self._originals[mirrored]
        edited = list(original)
        edited[line - 1] = ""
        self._write(mirrored, edited)
        try:
            return self._signature()
        finally:
            self._write(mirrored, original)

    def check(self, block: Block, loser: Directive, winner: Directive) -> Check:
        without_loser = self._without(block.file, loser.line)
        if without_loser != self.baseline:
            verdict = Verdict.REJECTED
        elif self._without(block.file, winner.line) == self.baseline:
            verdict = Verdict.INVISIBLE
        else:
            verdict = Verdict.CONFIRMED
        return Check(block=block, loser=loser, winner=winner, verdict=verdict)


def mirror_matches(checker_baseline: tuple, real: tuple) -> bool:
    """Does the mirrored config produce the same plan as the real one?

    If it does not, the mirror is not the config the user asked about and
    nothing measured in it may be reported as a measurement of theirs.
    """
    return checker_baseline == real


__all__ = ["Check", "Checker", "LogrotateError", "Verdict", "mirror_matches"]
