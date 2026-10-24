from __future__ import annotations

import pytest

from unrotated.parse import (
    ParseError,
    group_of,
    overridden,
    parse_file,
    split_patterns,
)


def parse(text: str):
    return parse_file("c", text)


class TestSplitPatterns:
    def test_whitespace_separates(self):
        assert split_patterns("/a.log /b.log") == ["/a.log", "/b.log"]

    def test_quotes_group_a_path_with_a_space(self):
        assert split_patterns('"/var/log/with space.log"') == ["/var/log/with space.log"]

    def test_backslash_escapes(self):
        assert split_patterns(r"/var/log/with\ space.log") == ["/var/log/with space.log"]

    def test_newlines_separate_like_any_whitespace(self):
        assert split_patterns('/a.log /b.log\n"/c d.log"') == ["/a.log", "/b.log", "/c d.log"]

    def test_an_empty_quoted_pattern_survives(self):
        # Pathological, but it must not silently vanish into a shorter list
        # than logrotate's own, which is what breaks block alignment.
        assert split_patterns('/a.log ""') == ["/a.log", ""]

    def test_unterminated_quote_raises(self):
        with pytest.raises(ParseError):
            split_patterns('"/a.log')


class TestBlocks:
    def test_patterns_and_directives(self):
        config = parse("/a.log {\n    weekly\n    rotate 4\n}\n")
        assert len(config.blocks) == 1
        block = config.blocks[0]
        assert block.patterns == ["/a.log"]
        assert block.line == 1
        assert [(d.name, d.args, d.line) for d in block.directives] == [
            ("weekly", "", 2),
            ("rotate", "4", 3),
        ]

    def test_a_header_spanning_several_lines_keeps_the_first_line(self):
        config = parse('/a.log /b.log\n"/c d.log"\n{\n    weekly\n}\n')
        block = config.blocks[0]
        assert block.line == 1
        assert block.patterns == ["/a.log", "/b.log", "/c d.log"]
        assert block.pattern_text == '/a.log /b.log\n"/c d.log"'

    def test_globals_outside_a_block(self):
        config = parse("daily\nrotate 4\n/a.log {\n    weekly\n}\n")
        assert [d.name for d in config.globals] == ["daily", "rotate"]
        assert [d.name for d in config.blocks[0].directives] == ["weekly"]

    def test_includes_are_recorded_with_their_line(self):
        config = parse("daily\ninclude /etc/logrotate.d\n")
        assert config.includes == [(2, "/etc/logrotate.d")]

    def test_comments_do_not_move_line_numbers(self):
        config = parse("# a comment\n/a.log {\n    # another\n    weekly\n}\n")
        assert config.blocks[0].line == 2
        assert config.blocks[0].directives[0].line == 4

    def test_a_script_body_is_not_read_as_directives(self):
        # `weekly` and `rotate 2` inside the script are shell words. Reading
        # them as directives would invent an override that is not there.
        config = parse(
            "/a.log {\n"
            "    monthly\n"
            "    postrotate\n"
            "        echo weekly rotate 2\n"
            "        systemctl reload nginx\n"
            "    endscript\n"
            "    rotate 7\n"
            "}\n"
        )
        names = [d.name for d in config.blocks[0].directives]
        assert names == ["monthly", "postrotate", "rotate"]
        assert overridden(config.blocks[0]) == []

    def test_a_script_with_no_endscript_raises(self):
        with pytest.raises(ParseError):
            parse("/a.log {\n    postrotate\n        echo hi\n}\n")

    def test_an_unclosed_block_raises(self):
        with pytest.raises(ParseError):
            parse("/a.log {\n    weekly\n")

    def test_a_pattern_with_no_brace_raises(self):
        with pytest.raises(ParseError):
            parse("/a.log\n")

    def test_directives_after_a_brace_raise(self):
        # logrotate rejects `/a.log { weekly }` too, with "bad weekly
        # directive". Accepting it here would give every directive in the
        # block the same line number.
        with pytest.raises(ParseError):
            parse("/a.log { weekly }\n")

    def test_a_stray_closing_brace_raises(self):
        with pytest.raises(ParseError):
            parse("}\n")


class TestGrouping:
    @pytest.mark.parametrize(
        "name", ["hourly", "daily", "weekly", "monthly", "yearly", "size"]
    )
    def test_every_interval_shares_one_group(self, name):
        assert group_of(name) == "interval"

    @pytest.mark.parametrize("name", ["maxsize", "minsize"])
    def test_maxsize_and_minsize_are_not_intervals(self, name):
        # Measured, not assumed: `size 100M` replaces a `daily` and
        # `maxsize 100M` does not. See tests/test_against_logrotate.py.
        assert group_of(name) != "interval"

    @pytest.mark.parametrize(
        ("one", "other"),
        [
            ("compress", "nocompress"),
            ("ifempty", "notifempty"),
            ("mail", "nomail"),
            ("mailfirst", "maillast"),
            ("create", "nocreate"),
            ("su", "nosu"),
        ],
    )
    def test_a_directive_and_its_negation_share_a_group(self, one, other):
        assert group_of(one) == group_of(other)

    def test_an_unknown_directive_is_its_own_group(self):
        assert group_of("dateformat") == "dateformat"
        assert group_of("dateformat") != group_of("dateext")


class TestOverridden:
    def test_the_later_of_two_wins(self):
        config = parse("/a.log {\n    rotate 2\n    rotate 9\n}\n")
        pairs = overridden(config.blocks[0])
        assert [(loser.line, winner.line) for loser, winner in pairs] == [(2, 3)]

    def test_size_takes_the_interval_from_a_schedule(self):
        config = parse("/a.log {\n    daily\n    size 100M\n}\n")
        pairs = overridden(config.blocks[0])
        assert [(loser.name, winner.name) for loser, winner in pairs] == [("daily", "size")]

    def test_maxsize_leaves_the_interval_alone(self):
        config = parse("/a.log {\n    daily\n    maxsize 100M\n}\n")
        assert overridden(config.blocks[0]) == []

    def test_three_assignments_report_the_first_two(self):
        config = parse("/a.log {\n    rotate 1\n    rotate 2\n    rotate 3\n}\n")
        pairs = overridden(config.blocks[0])
        assert [(loser.line, winner.line) for loser, winner in pairs] == [(2, 4), (3, 4)]

    def test_tabooext_accumulates_so_two_is_not_an_override(self):
        config = parse("/a.log {\n    tabooext +.foo\n    tabooext +.bar\n}\n")
        assert overridden(config.blocks[0]) == []

    def test_two_different_scripts_are_not_an_override(self):
        config = parse(
            "/a.log {\n"
            "    prerotate\n        echo a\n    endscript\n"
            "    postrotate\n        echo b\n    endscript\n"
            "}\n"
        )
        assert overridden(config.blocks[0]) == []

    def test_separate_blocks_do_not_override_each_other(self):
        config = parse("/a.log {\n    rotate 2\n}\n/b.log {\n    rotate 9\n}\n")
        assert overridden(config.blocks[0]) == []
        assert overridden(config.blocks[1]) == []
