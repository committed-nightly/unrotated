from __future__ import annotations

import json
import os

import pytest

from unrotated.cli import main

from .conftest import needs_logrotate

pytestmark = [needs_logrotate, pytest.mark.logrotate]


class TestExitCodes:
    def test_nothing_to_report_is_zero(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n    rotate 4\n}}\n")
        assert main([tree.conf]) == 0
        assert "Every rule unrotated can check rotates something." in capsys.readouterr().out

    def test_findings_are_one(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n    monthly\n    rotate 4\n}}\n")
        assert main([tree.conf]) == 1
        assert "overridden-directive" in capsys.readouterr().out

    def test_no_answer_is_two(self, tree, capsys):
        tree.top("/a.log {\n    weekly\n")  # never closed
        assert main([tree.conf]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "unrotated:" in captured.err

    def test_a_missing_logrotate_is_two_and_says_so(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n}}\n")
        assert main([tree.conf, "--logrotate", "logrotate-that-is-not-installed"]) == 2
        captured = capsys.readouterr()
        # The point: no findings list, and no claim of a clean config.
        assert captured.out == ""
        assert "not on PATH" in captured.err
        assert "will not guess" in captured.err

    def test_a_config_that_is_not_there_is_two(self, tree, capsys):
        assert main([os.path.join(tree.base, "absent.conf")]) == 2
        assert capsys.readouterr().out == ""

    def test_a_directory_is_two_and_names_the_file_to_use(self, tree, capsys):
        # `unrotated /etc/logrotate.d` is the shape of this: the drop-in
        # directory is what people think of as "the config".
        assert main([tree.include_dir]) == 2
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "is a directory" in captured.err
        assert "/etc/logrotate.conf" in captured.err


class TestOutputModes:
    def _example(self, tree):
        tree.log("a.log")
        tree.top(
            f"{tree.logs}/a.log {{\n    weekly\n    monthly\n    rotate 4\n}}\n"
            f"{tree.logs}/gone.log {{\n    weekly\n}}\n"
        )

    def test_quiet_is_one_line_per_finding(self, tree, capsys):
        self._example(tree)
        assert main([tree.conf, "-q"]) == 1
        lines = [line for line in capsys.readouterr().out.splitlines() if line]
        assert len(lines) == 2
        assert all(line.startswith(tree.conf) for line in lines)
        assert all(line.count(":") >= 2 for line in lines)

    def test_json_is_valid_and_carries_the_check_result(self, tree, capsys):
        self._example(tree)
        assert main([tree.conf, "--json"]) == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["verification"] == "checked"
        assert payload["confirmed"] == 1
        assert payload["rejected"] == []
        assert "logrotate" in payload["logrotate_version"].lower()
        assert {finding["kind"] for finding in payload["findings"]} == {
            "overridden-directive",
            "log-missing",
        }
        overridden = [f for f in payload["findings"] if f["kind"] == "overridden-directive"]
        assert overridden[0]["checked"] == "confirmed"
        assert overridden[0]["subject"] == "weekly"

    def test_json_on_a_clean_config_still_lists_what_was_read(self, tree, capsys):
        tree.log("a.log")
        tree.top(f"{tree.logs}/a.log {{\n    weekly\n    rotate 4\n}}\n")
        assert main([tree.conf, "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["findings"] == []
        assert payload["files_read"] == [tree.conf]
