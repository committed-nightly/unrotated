"""What unrotated does when it cannot answer.

The failure this program is written to avoid is reporting a clean config
because something stopped parsing. Each of these is a way that could happen,
and in every one of them the answer is a refusal rather than an empty list.
"""

from __future__ import annotations

import os

import pytest

from unrotated import disk
from unrotated.analyse import AlignmentError, ConfigPathError, _align, analyse
from unrotated.parse import Block, ConfigFile
from unrotated.plan import LogrotateError, Plan, PlanBlock
from unrotated.tree import Node, Tree


def tree_of(*patterns: str) -> Tree:
    config = ConfigFile(path="c")
    for index, pattern in enumerate(patterns, start=1):
        config.blocks.append(
            Block(file="c", line=index, patterns=[pattern], pattern_text=pattern)
        )
    return Tree(root=Node(config=config))


def plan_of(*patterns: str) -> Plan:
    return Plan(
        blocks=[
            PlanBlock(pattern_text=pattern, schedule="weekly", rotations=4)
            for pattern in patterns
        ]
    )


class TestAlignment:
    def test_matching_blocks_pair_up_in_order(self):
        pairs = _align(tree_of("/a.log", "/b.log"), plan_of("/a.log", "/b.log"))
        assert [block.line for block, _ in pairs] == [1, 2]

    def test_a_block_we_read_that_logrotate_did_not_plan_raises(self):
        with pytest.raises(AlignmentError, match="will not guess"):
            _align(tree_of("/a.log", "/b.log"), plan_of("/a.log"))

    def test_a_block_logrotate_planned_that_we_did_not_read_raises(self):
        with pytest.raises(AlignmentError, match="will not guess"):
            _align(tree_of("/a.log"), plan_of("/a.log", "/b.log"))

    def test_blocks_that_pair_up_but_disagree_raise(self):
        # The dangerous case: the counts match, so a checker that only
        # counted would carry on and anchor every finding one block out.
        with pytest.raises(AlignmentError, match="Nothing is reported"):
            _align(tree_of("/a.log", "/b.log"), plan_of("/a.log", "/c.log"))

    def test_whitespace_in_a_multi_line_header_is_not_a_disagreement(self):
        tree = tree_of("x")
        tree.root.config.blocks[0].pattern_text = '/a.log /b.log\n"/c d.log"'
        tree.root.config.blocks[0].patterns = ["/a.log", "/b.log", "/c d.log"]
        plan = plan_of('/a.log /b.log\n"/c d.log"')
        assert len(_align(tree, plan)) == 1


class TestConfigPath:
    """The argument is checked before logrotate is asked anything.

    Every case here names a logrotate that is not installed, so if the
    check ever moves back after `plan_for` these fail with a
    `LogrotateError` about PATH instead of the error being asserted. That
    is the regression worth catching: the old order paid for a bad
    argument at logrotate's pace, which for a named pipe was 120 seconds
    of waiting on an open() that could never return.
    """

    ABSENT = "logrotate-that-is-not-installed"

    def test_a_directory_says_which_file_to_point_at_instead(self, tmp_path):
        with pytest.raises(ConfigPathError, match="is a directory") as caught:
            analyse(str(tmp_path), binary=self.ABSENT)
        # The mistake this is written for is `unrotated /etc/logrotate.d`,
        # so the answer has to name the config that includes it.
        assert "/etc/logrotate.conf" in str(caught.value)

    def test_a_named_pipe_is_refused_instead_of_opened(self, tmp_path):
        fifo = tmp_path / "logrotate.conf"
        os.mkfifo(fifo)
        with pytest.raises(ConfigPathError, match="named pipe"):
            analyse(str(fifo), binary=self.ABSENT)

    def test_a_config_that_is_not_there_is_refused_first(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            analyse(str(tmp_path / "gone.conf"), binary=self.ABSENT)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_a_config_that_cannot_be_read_is_refused_first(self, tmp_path):
        config = tmp_path / "logrotate.conf"
        config.write_text("/a.log {\n    weekly\n}\n")
        config.chmod(0o000)
        try:
            with pytest.raises(PermissionError):
                analyse(str(config), binary=self.ABSENT)
        finally:
            config.chmod(0o644)

    def test_a_readable_regular_file_gets_as_far_as_logrotate(self, tmp_path):
        # The control: without it the four above would pass on a check
        # that rejected everything.
        config = tmp_path / "logrotate.conf"
        config.write_text("/a.log {\n    weekly\n}\n")
        with pytest.raises(LogrotateError, match="not on PATH"):
            analyse(str(config), binary=self.ABSENT)


class TestDisk:
    def test_a_file_that_is_there(self, tmp_path):
        path = tmp_path / "a.log"
        path.write_text("x")
        match = disk.resolve(str(path))
        assert match.paths == (str(path),)
        assert not match.matches_nothing
        assert match.unknown == ""

    def test_a_file_that_is_not(self, tmp_path):
        match = disk.resolve(str(tmp_path / "gone.log"))
        assert match.matches_nothing
        assert match.unknown == ""

    def test_a_glob_with_matches(self, tmp_path):
        (tmp_path / "a.log").write_text("x")
        (tmp_path / "b.log").write_text("x")
        match = disk.resolve(str(tmp_path / "*.log"))
        assert len(match.paths) == 2
        assert match.is_glob

    def test_a_glob_with_no_matches_in_a_readable_directory(self, tmp_path):
        (tmp_path / "a.txt").write_text("x")
        match = disk.resolve(str(tmp_path / "*.log"))
        assert match.matches_nothing
        assert match.unknown == ""

    def test_a_glob_under_a_missing_directory_matches_nothing(self, tmp_path):
        match = disk.resolve(str(tmp_path / "nope" / "*.log"))
        assert match.matches_nothing

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_a_glob_under_an_unreadable_directory_is_unknown_not_empty(self, tmp_path):
        private = tmp_path / "private"
        private.mkdir()
        (private / "a.log").write_text("x")
        private.chmod(0o000)
        try:
            match = disk.resolve(str(private / "*.log"))
            assert match.unknown
            assert not match.matches_nothing  # the distinction that matters
        finally:
            private.chmod(0o755)

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_a_file_under_an_unsearchable_directory_is_unknown(self, tmp_path):
        private = tmp_path / "private"
        private.mkdir()
        (private / "a.log").write_text("x")
        private.chmod(0o000)
        try:
            match = disk.resolve(str(private / "a.log"))
            assert match.unknown
            assert not match.matches_nothing
        finally:
            private.chmod(0o755)

    @pytest.mark.parametrize(
        ("pattern", "expected"),
        [
            ("/var/log/*.log", "/var/log"),
            ("/var/log/nginx/access.log", "/var/log/nginx"),
            ("/var/log/*/*.log", "/var/log"),
            ("/var/log/ngin?/a.log", "/var/log"),
        ],
    )
    def test_static_prefix(self, pattern, expected):
        assert disk.static_prefix(pattern) == expected
