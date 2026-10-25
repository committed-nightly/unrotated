"""The claims unrotated makes, checked against the logrotate on this box.

Everything here was measured before it was coded. Where a comment says
logrotate does something surprising, the test is the evidence, and if a
future logrotate stops doing it the test is what notices.
"""

from __future__ import annotations

import os

import pytest

from unrotated.analyse import analyse
from unrotated.plan import plan_for

from .conftest import needs_logrotate

pytestmark = [needs_logrotate, pytest.mark.logrotate]

as_root = pytest.mark.skipif(
    os.geteuid() == 0, reason="this is about what an unprivileged run can see"
)


def kinds(result) -> list[tuple[str, str]]:
    return [(finding.kind, finding.subject) for finding in result.sorted_findings()]


def _logrotate(tree) -> tuple[int, str]:
    """Run real logrotate over the fixture and return (exit code, output)."""
    import subprocess

    state = os.path.join(tree.base, "exitstate")
    if os.path.exists(state):
        os.remove(state)
    completed = subprocess.run(
        ["logrotate", "-d", "-s", state, tree.conf],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


class TestWhatLogrotateItselfWillTellYou:
    """Why this tool exists, measured instead of asserted.

    Each case is a thing unrotated reports. The question here is whether
    logrotate would have told you on its own. Seven of these eleven are
    completely silent: exit 0 and not one line of error.

    `missingok` is the hinge. Without it a missing log is an error and a
    non-zero exit; with it logrotate says nothing whatsoever -- and almost
    every packaged drop-in sets it, which is how a rule for a log that has
    not existed for two years survives in /etc/logrotate.d indefinitely.
    """

    SILENT = [
        ("interval overridden", "{logs}/a.log {{\n weekly\n monthly\n rotate 4\n}}\n"),
        ("rotate overridden", "{logs}/a.log {{\n weekly\n rotate 2\n rotate 9\n}}\n"),
        ("interval killed by size", "{logs}/a.log {{\n daily\n size 100M\n}}\n"),
        ("compress overridden", "{logs}/a.log {{\n weekly\n compress\n nocompress\n}}\n"),
        ("dead glob, missingok", "{logs}/ghost*.log {{\n missingok\n weekly\n}}\n"),
        ("missing log, missingok", "{logs}/gone.log {{\n missingok\n weekly\n}}\n"),
    ]
    REPORTED = [
        ("dead glob, no missingok", "{logs}/ghost*.log {{\n weekly\n}}\n"),
        ("missing log, no missingok", "{logs}/gone.log {{\n weekly\n}}\n"),
        (
            "duplicate log entry",
            "{logs}/a.log {{\n weekly\n}}\n{logs}/a.log {{\n monthly\n}}\n",
        ),
    ]

    @pytest.mark.parametrize(("name", "template"), SILENT, ids=[n for n, _ in SILENT])
    def test_logrotate_says_nothing(self, tree, name, template):
        tree.log("a.log")
        tree.top(template.format(logs=tree.logs))
        code, output = _logrotate(tree)
        assert code == 0, f"{name}: expected a silent exit 0, got {code}\n{output}"
        assert [line for line in output.splitlines() if line.startswith("error:")] == []
        # And unrotated does not stay silent about it.
        assert analyse(tree.conf).findings != []

    @pytest.mark.parametrize(
        ("name", "template"), REPORTED, ids=[n for n, _ in REPORTED]
    )
    def test_logrotate_does_report_these(self, tree, name, template):
        tree.log("a.log")
        tree.top(template.format(logs=tree.logs))
        code, output = _logrotate(tree)
        assert code == 1, f"{name}: expected exit 1, got {code}\n{output}"
        assert any(line.startswith("error:") for line in output.splitlines())

    def test_a_config_file_it_never_reads_is_the_silent_one(self, tree):
        tree.log("a.log")
        tree.top(f"daily\nrotate 4\ninclude {tree.include_dir}\n")
        tree.drop_in("nginx.dpkg-dist", f"{tree.logs}/a.log {{\n    weekly\n}}\n")
        code, output = _logrotate(tree)
        assert code == 0
        assert "Ignoring nginx.dpkg-dist" in output  # only because of -d
        assert kinds(analyse(tree.conf, verify=False)) == [
            ("config-never-read", "nginx.dpkg-dist")
        ]

    def test_a_missing_include_is_reported(self, tree):
        tree.top(f"include {tree.base}/nope.d\n")
        code, output = _logrotate(tree)
        assert code == 1
        assert "cannot stat" in output


class TestSizeVersusMaxsize:
    """`size` replaces the interval. `maxsize` adds to it.

    This is the distinction the whole `interval` group in parse.py rests on,
    and the reason it is not just "anything that mentions bytes".
    """

    def test_size_takes_over_from_daily(self, tree):
        tree.log("a.log")
        tree.top(
            f"""
            {tree.logs}/a.log {{
                daily
                size 100M
                rotate 4
            }}
            """
        )
        plan = plan_for(tree.conf, os.path.join(tree.base, "state"))
        assert plan.blocks[0].schedule == "104857600 bytes"

        result = analyse(tree.conf)
        assert [
            (finding.kind, finding.subject, finding.checked)
            for finding in result.sorted_findings()
        ] == [("overridden-directive", "daily", "confirmed")]

    def test_maxsize_leaves_daily_in_place(self, tree):
        tree.log("a.log")
        tree.top(
            f"""
            {tree.logs}/a.log {{
                daily
                maxsize 100M
                rotate 4
            }}
            """
        )
        plan = plan_for(tree.conf, os.path.join(tree.base, "state"))
        assert plan.blocks[0].schedule == "after 1 days"
        assert "rotated earlier" in plan.blocks[0].options

        assert analyse(tree.conf).findings == []


class TestDeletionCheck:
    def test_an_overridden_interval_is_confirmed(self, tree):
        tree.log("a.log")
        tree.top(
            f"""
            {tree.logs}/a.log {{
                weekly
                monthly
                rotate 4
            }}
            """
        )
        result = analyse(tree.conf)
        assert result.verification == "checked"
        assert result.confirmed == 1
        assert kinds(result) == [("overridden-directive", "weekly")]
        assert result.sorted_findings()[0].checked == "confirmed"

    def test_a_directive_the_plan_never_mentions_is_not_claimed_as_confirmed(self, tree):
        # logrotate's plan says nothing about `compress`, so blanking a live
        # one also leaves the plan unchanged. Without the control that tests
        # the winner too, this would be reported as a measured fact.
        tree.log("a.log")
        tree.top(
            f"""
            {tree.logs}/a.log {{
                compress
                nocompress
                weekly
                rotate 4
            }}
            """
        )
        result = analyse(tree.conf)
        assert result.confirmed == 0
        assert result.invisible == 1
        assert result.sorted_findings()[0].checked == "invisible"

    def test_a_live_directive_is_not_reported(self, tree):
        tree.log("a.log")
        tree.top(
            f"""
            {tree.logs}/a.log {{
                monthly
                maxsize 1M
                rotate 4
            }}
            """
        )
        assert analyse(tree.conf).findings == []

    def test_the_check_runs_over_a_copy_and_leaves_the_config_alone(self, tree):
        tree.log("a.log")
        path = tree.top(
            f"""
            {tree.logs}/a.log {{
                weekly
                monthly
                rotate 4
            }}
            """
        )
        before = open(path).read()
        analyse(tree.conf)
        assert open(path).read() == before

    def test_no_verify_still_reports_the_finding_unchecked(self, tree):
        tree.log("a.log")
        tree.top(
            f"""
            {tree.logs}/a.log {{
                weekly
                monthly
                rotate 4
            }}
            """
        )
        result = analyse(tree.conf, verify=False)
        assert kinds(result) == [("overridden-directive", "weekly")]
        assert result.verification == "skipped"
        assert result.sorted_findings()[0].checked == ""

    def test_the_mirror_reproduces_the_original_plan(self, tree):
        """If it did not, nothing measured in the copy would be about the
        config the user asked about -- so this is the precondition the
        deletion check refuses to run without."""
        tree.log("a.log")
        tree.log("b.log")
        tree.top(
            f"""
            daily
            rotate 4
            include {tree.include_dir}
            """
        )
        tree.drop_in(
            "app",
            f"""
            "{tree.logs}/a.log" {{
                weekly
                monthly
            }}
            """,
        )
        tree.drop_in("other", f"{tree.logs}/b.log {{\n    hourly\n}}\n")
        result = analyse(tree.conf)
        assert result.verification == "checked"
        assert result.confirmed == 1


class TestTabooExtensions:
    """A config file logrotate silently never reads.

    The 15 patterns are measured, not taken from the man page. `.orig`,
    `.old` and `.conf` are not among them, which is the half of this that a
    hardcoded list tends to get wrong.
    """

    SKIPPED = [
        ".bak",
        ".cfsaved",
        ".disabled",
        ".dpkg-bak",
        ".dpkg-dist",
        ".dpkg-new",
        ".dpkg-old",
        ".rpmnew",
        ".rpmorig",
        ".rpmsave",
        ".swp",
        ".ucf-dist",
        ".ucf-new",
        ".ucf-old",
        "~",
    ]
    READ = [".orig", ".old", ".conf", ".logrotate", ""]

    def _tree_with(self, tree, name: str):
        tree.log("a.log")
        tree.top(f"daily\nrotate 4\ninclude {tree.include_dir}\n")
        tree.drop_in(name, f"{tree.logs}/a.log {{\n    weekly\n    monthly\n}}\n")
        return analyse(tree.conf, verify=False)

    @pytest.mark.parametrize("extension", SKIPPED)
    def test_a_taboo_name_is_reported_as_never_read(self, tree, extension):
        result = self._tree_with(tree, f"nginx{extension}")
        assert kinds(result) == [("config-never-read", f"nginx{extension}")]
        # And the block inside it produced no findings of its own, because
        # logrotate never read it.
        assert all(f.kind == "config-never-read" for f in result.findings)

    @pytest.mark.parametrize("extension", READ)
    def test_a_name_that_is_not_taboo_is_read_normally(self, tree, extension):
        result = self._tree_with(tree, f"nginx{extension}")
        assert ("config-never-read", f"nginx{extension}") not in kinds(result)
        assert ("overridden-directive", "weekly") in kinds(result)

    def test_a_subdirectory_is_reported_too(self, tree):
        tree.log("a.log")
        tree.top(f"daily\nrotate 4\ninclude {tree.include_dir}\n")
        os.makedirs(os.path.join(tree.include_dir, "conf.d"))
        result = analyse(tree.conf, verify=False)
        assert kinds(result) == [("config-never-read", "conf.d")]


class TestDuplicates:
    def test_a_log_named_twice_names_the_block_that_got_it(self, tree):
        tree.log("a.log")
        tree.top(f"daily\nrotate 4\ninclude {tree.include_dir}\n")
        first = tree.drop_in("a-first", f"{tree.logs}/a.log {{\n    weekly\n}}\n")
        second = tree.drop_in("b-second", f"{tree.logs}/a.log {{\n    monthly\n}}\n")
        result = analyse(tree.conf, verify=False)

        duplicates = [f for f in result.findings if f.kind == "duplicate-log-entry"]
        assert len(duplicates) == 1
        assert duplicates[0].file == second
        assert duplicates[0].instead == f"{first}:1"

        # And the second block is reported as rotating nothing, because it is.
        assert any(f.kind == "rotates-nothing" and f.file == second for f in result.findings)

    def test_logrotate_reports_a_duplicate_and_exits_one(self, tree):
        tree.log("a.log")
        tree.top(
            f"{tree.logs}/a.log {{\n    weekly\n}}\n{tree.logs}/a.log {{\n    monthly\n}}\n"
        )
        code, output = _logrotate(tree)
        assert "duplicate log entry" in output
        assert code == 1


class TestPatternsThatRotateNothing:
    def test_a_glob_matching_nothing(self, tree):
        tree.log("a.log")
        tree.top(f"{tree.logs}/ghost-*.log {{\n    weekly\n    rotate 4\n}}\n")
        result = analyse(tree.conf)
        assert kinds(result) == [("pattern-matches-nothing", f"{tree.logs}/ghost-*.log")]

    def test_a_literal_path_that_is_not_there(self, tree):
        tree.top(f"{tree.logs}/gone.log {{\n    weekly\n    rotate 4\n}}\n")
        result = analyse(tree.conf)
        assert kinds(result) == [("log-missing", f"{tree.logs}/gone.log")]

    def test_missingok_is_mentioned_because_it_is_why_nobody_noticed(self, tree):
        tree.top(f"{tree.logs}/gone.log {{\n    missingok\n    weekly\n}}\n")
        result = analyse(tree.conf)
        assert "missingok" in result.sorted_findings()[0].detail

    def test_a_live_pattern_is_not_reported(self, tree):
        tree.log("a.log")
        tree.top(f"{tree.logs}/*.log {{\n    weekly\n    rotate 4\n}}\n")
        assert analyse(tree.conf).findings == []

    @as_root
    def test_a_directory_we_may_not_read_is_undetermined_not_dead(self, tree):
        """The chrony case.

        /var/log/chrony on an Ubuntu box is mode 750 and owned by `_chrony`.
        An ordinary user's glob over it comes back empty and logrotate says
        "No logs found. Rotation not needed." -- the same words it uses when
        an earlier block took the logs. Calling that dead is a tidy, wrong
        answer about a config that is working.
        """
        private = os.path.join(tree.base, "private")
        os.makedirs(private)
        with open(os.path.join(private, "secret.log"), "w") as handle:
            handle.write("x\n")
        os.chmod(private, 0o000)
        try:
            tree.top(f"{private}/*.log {{\n    missingok\n    weekly\n}}\n")
            result = analyse(tree.conf)
            assert result.findings == []
            assert [pattern for pattern, _ in result.unknown_patterns] == [
                f"{private}/*.log"
            ]
        finally:
            os.chmod(private, 0o755)


class TestRelativePatterns:
    """logrotate's own expansion is the one that counts.

    A relative pattern only parses when quoted, and a relative *glob* in an
    included file does not expand at all -- the same block at the top level
    expands fine. unrotated reports what logrotate does, which means
    reporting this one as matching nothing even though a glob() from the same
    working directory would match two files.
    """

    def test_a_relative_glob_in_an_included_file_is_dead(self, tree, monkeypatch):
        tree.log("a.log")
        tree.log("b.log")
        tree.top(f"daily\nrotate 4\ninclude {tree.include_dir}\n")
        dropped = tree.drop_in("glob", '"logs/*.log" {\n    monthly\n}\n')
        monkeypatch.chdir(tree.base)

        plan = plan_for(tree.conf, os.path.join(tree.base, "state"))
        assert plan.blocks[0].considered == ["logs/*.log"]

        result = analyse(tree.conf, verify=False)
        assert kinds(result) == [("pattern-matches-nothing", "logs/*.log")]
        assert result.sorted_findings()[0].file == dropped

    def test_the_same_pattern_at_the_top_level_does_expand(self, tree, monkeypatch):
        tree.log("a.log")
        tree.log("b.log")
        tree.top('"logs/*.log" {\n    monthly\n    rotate 4\n}\n')
        monkeypatch.chdir(tree.base)
        plan = plan_for(tree.conf, os.path.join(tree.base, "state"))
        assert sorted(plan.blocks[0].considered) == ["logs/a.log", "logs/b.log"]
        assert analyse(tree.conf).findings == []


class TestIncludes:
    def test_an_include_that_is_not_there(self, tree):
        tree.log("a.log")
        path = tree.top(
            f"{tree.logs}/a.log {{\n    weekly\n    rotate 4\n}}\n"
            f"include {tree.base}/nope.d\n"
        )
        result = analyse(tree.conf, verify=False)
        assert kinds(result) == [("include-missing", f"{tree.base}/nope.d")]
        assert result.sorted_findings()[0].file == path
        assert result.sorted_findings()[0].line == 5


class TestCleanConfig:
    def test_a_config_with_nothing_wrong_reports_nothing(self, tree):
        tree.log("a.log")
        tree.top(
            f"""
            daily
            rotate 4
            include {tree.include_dir}
            """
        )
        tree.drop_in("app", f"{tree.logs}/a.log {{\n    weekly\n    compress\n}}\n")
        result = analyse(tree.conf)
        assert result.findings == []
        assert result.errors == []
        assert result.unknown_patterns == []
