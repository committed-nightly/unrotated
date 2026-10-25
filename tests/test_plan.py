"""Reading `logrotate -d` output.

These are the tests about not reporting a clean config because the output
stopped making sense. Every unreadable shape must raise.
"""

from __future__ import annotations

import pytest

from unrotated.plan import LogrotateError, parse_output

PREAMBLE = "reading config file /etc/logrotate.conf\n"


def plan(body: str, preamble: str = PREAMBLE):
    return parse_output(preamble + "\nHandling 1 logs\n\n" + body, "/etc/logrotate.conf")


class TestHeader:
    @pytest.mark.parametrize(
        ("printed", "schedule"),
        [
            ("hourly", "hourly"),
            ("after 1 days", "after 1 days"),
            ("after 14 days", "after 14 days"),
            ("weekly", "weekly"),
            ("monthly", "monthly"),
            ("yearly", "yearly"),
            ("104857600 bytes", "104857600 bytes"),
        ],
    )
    def test_every_criterion_logrotate_prints(self, printed, schedule):
        result = plan(f"rotating pattern: /a.log  {printed} (4 rotations)\n")
        assert result.blocks[0].schedule == schedule
        assert result.blocks[0].rotations == 4

    def test_no_old_logs_kept_is_the_other_tail(self):
        result = plan("rotating pattern: /a.log  weekly (no old logs will be kept)\n")
        assert result.blocks[0].rotations is None
        assert result.blocks[0].schedule == "weekly"

    def test_a_header_spanning_lines_is_read_whole(self):
        # logrotate echoes the pattern text out of the config verbatim,
        # newlines included. A line-at-a-time reader splits this wrongly and
        # then fails to match the block to the config.
        result = plan(
            'rotating pattern: /a.log /b.log\n"/c d.log"\n weekly (4 rotations)\n'
            "empty log files are rotated, old logs are removed\n"
        )
        assert len(result.blocks) == 1
        assert result.blocks[0].patterns_normalised == '/a.log /b.log "/c d.log"'
        assert result.blocks[0].schedule == "weekly"

    def test_a_criterion_we_do_not_know_raises(self):
        # The point of the test: a future logrotate printing "fortnightly"
        # must stop this program, not make it report a clean config.
        with pytest.raises(LogrotateError, match="rotating pattern"):
            plan("rotating pattern: /a.log  fortnightly (4 rotations)\n")

    def test_a_header_with_no_tail_raises(self):
        with pytest.raises(LogrotateError):
            plan("rotating pattern: /a.log  weekly\n")

    def test_output_with_no_handling_line_raises(self):
        with pytest.raises(LogrotateError, match="Handling"):
            parse_output("reading config file /etc/logrotate.conf\n", "/etc/logrotate.conf")


class TestBlockDetail:
    def test_options_considered_and_missing(self):
        result = plan(
            "rotating pattern: /a.log /b.log  weekly (4 rotations)\n"
            "empty log files are not rotated, old logs are removed\n"
            "considering log /a.log\n"
            "considering log /b.log\n"
            "  log /b.log does not exist -- skipping\n"
        )
        block = result.blocks[0]
        assert block.options == "empty log files are not rotated, old logs are removed"
        assert block.considered == ["/a.log", "/b.log"]
        assert block.missing == ["/b.log"]

    def test_stat_failure_is_a_missing_log_too(self):
        result = plan(
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "empty log files are rotated, old logs are removed\n"
            "considering log /a.log\n"
            "error: stat of /a.log failed: No such file or directory\n"
        )
        assert result.blocks[0].missing == ["/a.log"]

    def test_no_logs_found(self):
        result = plan(
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "empty log files are rotated, old logs are removed\n"
            "No logs found. Rotation not needed.\n"
        )
        assert result.blocks[0].no_logs is True
        assert result.blocks[0].options.startswith("empty log files")

    def test_no_logs_found_is_not_mistaken_for_the_options_line(self):
        result = plan(
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "No logs found. Rotation not needed.\n"
        )
        assert result.blocks[0].no_logs is True
        assert result.blocks[0].options == ""

    def test_a_failed_su_marks_the_block_and_nothing_else(self):
        result = plan(
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "empty log files are rotated, old logs are removed\n"
            "switching euid from 1001 to 0 and egid from 1001 to 4\n"
            "error: error switching euid from 1001 to 0 and egid from 1001 to 4 "
            "(pid 1): Operation not permitted\n"
        )
        block = result.blocks[0]
        assert block.privilege_blocked is True
        assert block.missing == []
        assert block.considered == []

    def test_detail_stops_at_the_next_header(self):
        result = plan(
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "empty log files are rotated, old logs are removed\n"
            "considering log /a.log\n"
            "\n"
            "rotating pattern: /b.log  monthly (2 rotations)\n"
            "empty log files are rotated, old logs are removed\n"
            "considering log /b.log\n"
        )
        assert [block.considered for block in result.blocks] == [["/a.log"], ["/b.log"]]


class TestConfigFiles:
    def test_a_taboo_file_is_recorded_with_its_reason(self):
        result = plan(
            "",
            preamble=(
                "reading config file /etc/logrotate.conf\n"
                "including /etc/logrotate.d\n"
                "Ignoring nginx.dpkg-dist, because of *.dpkg-dist pattern match\n"
                "reading config file apt\n"
            ),
        )
        assert len(result.ignored_configs) == 1
        ignored = result.ignored_configs[0]
        assert ignored.name == "nginx.dpkg-dist"
        assert ignored.directory == "/etc/logrotate.d"
        assert "*.dpkg-dist" in ignored.reason

    def test_a_directory_in_the_include_dir_is_recorded(self):
        result = plan(
            "",
            preamble=(
                "reading config file /etc/logrotate.conf\n"
                "including /etc/logrotate.d\n"
                "Ignoring subdir because it's not a regular file.\n"
            ),
        )
        assert result.ignored_configs[0].name == "subdir"
        assert "regular file" in result.ignored_configs[0].reason

    def test_an_unreachable_include(self):
        result = plan(
            "",
            preamble=(
                "reading config file /etc/logrotate.conf\n"
                "including /etc/logrotate.d.local\n"
                "error: cannot stat /etc/logrotate.d.local: No such file or directory\n"
            ),
        )
        assert result.unreachable_includes == [
            ("/etc/logrotate.d.local", "No such file or directory")
        ]

    def test_a_duplicate_entry_keeps_its_file_and_line(self):
        result = plan(
            "",
            preamble=(
                "reading config file /etc/logrotate.conf\n"
                "error: /etc/logrotate.conf:12 duplicate log entry for /var/log/syslog\n"
            ),
        )
        assert len(result.duplicates) == 1
        duplicate = result.duplicates[0]
        assert (duplicate.file, duplicate.line, duplicate.path) == (
            "/etc/logrotate.conf",
            12,
            "/var/log/syslog",
        )

    def test_a_duplicate_is_not_also_filed_as_a_syntax_error(self):
        result = plan(
            "",
            preamble=(
                "reading config file /etc/logrotate.conf\n"
                "error: /etc/logrotate.conf:12 duplicate log entry for /var/log/syslog\n"
                "error: found error in file /etc/logrotate.conf, skipping\n"
            ),
        )
        assert result.config_errors == []

    def test_a_syntax_error_is_recorded(self):
        result = plan(
            "",
            preamble=(
                "reading config file /etc/logrotate.conf\n"
                "error: /etc/logrotate.conf:3 unknown option 'wekly' -- ignoring line\n"
            ),
        )
        assert result.config_errors == [
            ("/etc/logrotate.conf", 3, "unknown option 'wekly' -- ignoring line")
        ]


class TestSignature:
    def test_the_signature_ignores_state_timestamps(self):
        timed = (
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "empty log files are rotated, old logs are removed\n"
            "considering log /a.log\n"
            "  Now: 2026-10-24 00:26\n"
            "  Last rotated at 2026-10-24 00:00\n"
            "  log does not need rotating (log has already been rotated)\n"
        )
        other = timed.replace("2026-10-24 00:26", "2027-01-01 13:00")
        assert plan(timed).signature() == plan(other).signature()

    def test_the_signature_moves_when_the_schedule_does(self):
        one = "rotating pattern: /a.log  weekly (4 rotations)\nopts\n"
        two = "rotating pattern: /a.log  monthly (4 rotations)\nopts\n"
        assert plan(one).signature() != plan(two).signature()

    def test_the_signature_moves_when_the_options_do(self):
        one = "rotating pattern: /a.log  weekly (4 rotations)\nempty log files are rotated\n"
        two = (
            "rotating pattern: /a.log  weekly (4 rotations)\n"
            "empty log files are not rotated\n"
        )
        assert plan(one).signature() != plan(two).signature()
