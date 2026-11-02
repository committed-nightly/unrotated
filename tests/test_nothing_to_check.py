"""Verdicts over a config with no rules in it.

The failure guarded here is the one in logbook#59: a check that examined
none of its subject printing the sentence reserved for having examined it.
`unrotated` ended a run over an empty file, over a config of nothing but
globals, and over a file logrotate rejected outright, all three on "Every
rule unrotated can check rotates something" and exit 0.

Each test below asserts the absence of that sentence as well as the
presence of the new one. Asserting only the new wording would pass a build
that printed both.
"""

from __future__ import annotations

import json
import os

import pytest

from unrotated.analyse import Result
from unrotated.cli import main

from .conftest import needs_logrotate

pytestmark = [needs_logrotate, pytest.mark.logrotate]

CLEAN = "Every rule unrotated can check rotates something."


class TestNoRules:
    """Nothing to check, but the input was understood. Exit 0, new sentence."""

    def test_an_empty_config_does_not_report_a_clean_one(self, tree, capsys):
        tree.top("")
        assert main([tree.conf]) == 0
        out = capsys.readouterr().out
        assert "No rules here" in out
        assert "Nothing to check." in out
        assert CLEAN not in out

    def test_a_config_of_only_globals_does_not_report_a_clean_one(self, tree, capsys):
        # The realistic one: an /etc/logrotate.conf whose drop-in directory
        # is empty still sets `weekly` and `rotate 4` at the top.
        tree.top("weekly\nrotate 4\n")
        assert main([tree.conf]) == 0
        out = capsys.readouterr().out
        assert "no rotation block" in out
        assert CLEAN not in out

    def test_an_empty_include_directory_does_not_report_a_clean_one(self, tree, capsys):
        tree.top(f"weekly\ninclude {tree.include_dir}\n")
        assert main([tree.conf]) == 0
        out = capsys.readouterr().out
        assert "No rules here" in out
        assert CLEAN not in out

    def test_the_control_one_real_rule_gets_the_clean_sentence(self, tree, capsys):
        # Without this the three above would pass on a build that had
        # deleted the clean verdict altogether.
        tree.log("a.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n    rotate 4\n}}\n")
        assert main([tree.conf]) == 0
        out = capsys.readouterr().out
        assert CLEAN in out
        assert "No rules here" not in out


class TestRejectedOutright:
    """logrotate understood none of it. No answer, so exit 2."""

    NOT_CONFIG = "hello world\nthis is not logrotate config\n"

    def test_a_file_that_is_not_a_config_is_two_and_claims_nothing(self, tree, capsys):
        tree.top(self.NOT_CONFIG)
        assert main([tree.conf]) == 2
        captured = capsys.readouterr()
        # The whole point: no verdict on stdout at all, clean or otherwise.
        assert captured.out == ""
        assert "not a logrotate config" in captured.err

    def test_the_rejected_lines_are_still_named_on_stderr(self, tree, capsys):
        # The refusal is a summary of these, not a replacement for them.
        tree.top(self.NOT_CONFIG)
        main([tree.conf])
        err = capsys.readouterr().err
        assert "logrotate rejected" in err
        assert "unknown option 'hello'" in err

    def test_json_mode_also_prints_nothing_on_stdout(self, tree, capsys):
        tree.top(self.NOT_CONFIG)
        assert main([tree.conf, "--json"]) == 2
        assert capsys.readouterr().out == ""

    def test_one_rejected_line_among_good_ones_is_not_a_refusal(self, tree, capsys):
        # The distinction the exit code turns on. A config with a typo in it
        # is still a config, and logrotate read the rest of it.
        tree.log("a.log")
        tree.top(f"hello world\n{tree.logs}/a.log {{\n    weekly\n    rotate 4\n}}\n")
        assert main([tree.conf]) == 0
        captured = capsys.readouterr()
        assert CLEAN in captured.out
        assert "not a logrotate config" not in captured.err

    def test_a_rejected_line_is_declared_in_the_verdict(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"hello world\n{tree.logs}/a.log {{\n    weekly\n}}\n")
        main([tree.conf])
        assert "1 line logrotate rejected" in capsys.readouterr().out

    def test_a_global_logrotate_did_understand_is_not_a_refusal(self, tree, capsys):
        # No rules either, so this lands on "No rules here" rather than on
        # exit 2: `weekly` survived, so the file is a logrotate config.
        tree.top("weekly\nhello world\n")
        assert main([tree.conf]) == 0
        assert "No rules here" in capsys.readouterr().out


class TestDenominator:
    """Every run says what it was measured over."""

    def test_the_clean_verdict_carries_the_rule_count(self, tree, capsys):
        tree.log("a.log")
        tree.log("b.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n}}\n{tree.logs}/b.log {{\n    weekly\n}}\n")
        assert main([tree.conf]) == 0
        assert "Read 2 rules in 1 config file." in capsys.readouterr().out

    def test_a_findings_verdict_carries_it_too(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n    monthly\n}}\n")
        assert main([tree.conf]) == 1
        assert "Read 1 rule in 1 config file." in capsys.readouterr().out

    def test_findings_with_no_rules_still_exit_one(self, tree, capsys):
        # A config with no blocks can still have something wrong with it, so
        # "No rules here: nothing to check" must not swallow a finding.
        tree.top(f"include {tree.base}/not-there\n")
        assert main([tree.conf]) == 1
        out = capsys.readouterr().out
        assert "include-missing" in out
        assert "Read 0 rules in 1 config file." in out
        assert "Nothing to check." not in out

    def test_json_carries_the_counts(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"weekly\n{tree.logs}/a.log {{\n    rotate 4\n}}\n")
        assert main([tree.conf, "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["rules"] == 1
        assert payload["rejected_lines"] == 0
        # `weekly`, the pattern line, and `rotate 4`.
        assert payload["directive_lines"] == 3


class TestLineArithmetic:
    """`understood_lines` is a subtraction, so it is worth pinning down."""

    def test_rejections_outside_the_lines_we_counted_cannot_go_negative(self):
        # logrotate can complain about a line inside a `postrotate` body,
        # which the parser skips and never counted. Taking its count whole
        # would make this negative and turn a readable config into a refusal.
        result = Result(config="c", directive_lines=0, rejected_lines=0)
        assert result.understood_lines == 0
        assert not result.unreadable_as_config

    def test_a_config_with_nothing_in_it_is_not_a_refusal(self):
        assert not Result(config="c").unreadable_as_config

    def test_every_line_rejected_is_a_refusal(self):
        result = Result(config="c", directive_lines=2, rejected_lines=2)
        assert result.unreadable_as_config

    def test_one_line_surviving_is_not(self):
        result = Result(config="c", directive_lines=2, rejected_lines=1)
        assert not result.unreadable_as_config

    @needs_logrotate
    def test_a_rejected_line_in_a_script_body_is_not_counted(self, tree, capsys):
        # The real version of the case above, through logrotate. `hello` is
        # inside postrotate, so logrotate passes it to the shell rather than
        # rejecting it, and either way the config is readable.
        tree.log("a.log")
        tree.top(
            f"{tree.logs}/a.log {{\n    weekly\n    postrotate\n        hello world\n"
            "    endscript\n}\n"
        )
        assert main([tree.conf]) == 0
        assert CLEAN in capsys.readouterr().out


class TestOsErrorText:
    """A path that is not there gets a sentence, not a Python repr."""

    def test_a_missing_config_is_named_without_an_errno(self, tree, capsys):
        missing = os.path.join(tree.base, "absent.conf")
        assert main([missing]) == 2
        err = capsys.readouterr().err
        assert err.strip() == f"unrotated: {missing}: no such file or directory"
        assert "Errno" not in err

    @pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
    def test_an_unreadable_config_says_why(self, tree, capsys):
        tree.top("weekly\n")
        os.chmod(tree.conf, 0o000)
        try:
            assert main([tree.conf]) == 2
            err = capsys.readouterr().err
            assert err.strip() == f"unrotated: {tree.conf}: permission denied"
        finally:
            # 0o600, not 0o644: this only has to be readable again so the
            # tmpdir can be cleaned up, and a world-readable mode here is
            # what CodeQL flags (py/overly-permissive-file).
            os.chmod(tree.conf, 0o600)

    def test_a_directory_keeps_its_own_message(self, tree, capsys):
        # ConfigPathError is an OSError too, and its message is written
        # rather than derived, so it must not go through the same formatting.
        assert main([tree.include_dir]) == 2
        err = capsys.readouterr().err
        assert "is a directory" in err
        assert "/etc/logrotate.conf" in err
