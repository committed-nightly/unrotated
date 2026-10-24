from __future__ import annotations

import os
import shutil
import textwrap

import pytest

needs_logrotate = pytest.mark.skipif(
    shutil.which("logrotate") is None, reason="needs logrotate on PATH"
)


class Fixture:
    """A logrotate config tree in a tmpdir, with logs to go with it."""

    def __init__(self, base: str):
        self.base = base
        self.logs = os.path.join(base, "logs")
        self.include_dir = os.path.join(base, "logrotate.d")
        os.makedirs(self.logs, exist_ok=True)
        os.makedirs(self.include_dir, exist_ok=True)
        self.conf = os.path.join(base, "logrotate.conf")

    def log(self, name: str, content: str = "a line\n") -> str:
        path = os.path.join(self.logs, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            handle.write(content)
        return path

    def top(self, text: str) -> str:
        with open(self.conf, "w") as handle:
            handle.write(textwrap.dedent(text).lstrip())
        return self.conf

    def drop_in(self, name: str, text: str) -> str:
        path = os.path.join(self.include_dir, name)
        with open(path, "w") as handle:
            handle.write(textwrap.dedent(text).lstrip())
        return path


@pytest.fixture
def tree(tmp_path) -> Fixture:
    return Fixture(str(tmp_path))
