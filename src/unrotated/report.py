"""Output. One block per finding, in the order you would fix them."""

from __future__ import annotations

import json
import textwrap

from .analyse import Result

#: Width that keeps a finding readable in a split terminal.
WRAP = 78


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=WRAP, initial_indent=indent, subsequent_indent=indent)


def _where(finding) -> str:
    return finding.file if finding.line == 0 else f"{finding.file}:{finding.line}"


def error_lines(result: Result) -> list[str]:
    """Diagnostics, for stderr. Never part of any mode's stdout."""
    lines = [f"unrotated: {error}" for error in result.errors]
    if result.blocked_blocks:
        count = len(result.blocked_blocks)
        plural = "" if count == 1 else "s"
        lines.append(
            f"unrotated: could not check the logs of {count} block{plural}: logrotate "
            "would not switch to the user their `su` names, so it stopped before "
            f"looking. Re-run as root. ({', '.join(result.blocked_blocks)})"
        )
    lines += [
        f"unrotated: cannot say whether `{pattern}` matches anything: {reason}"
        for pattern, reason in result.unknown_patterns
    ]
    if result.verification == "unavailable":
        lines.append(f"unrotated: no deletion check: {result.verification_note}")
    return lines


def text(result: Result, quiet: bool = False) -> str:
    findings = result.sorted_findings()

    if quiet:
        return "\n".join(
            f"{_where(finding)}: {finding.kind}: {finding.detail}" for finding in findings
        )

    lines: list[str] = []
    read = ", ".join(result.files_read) if result.files_read else "nothing"
    lines.append(f"{result.config}: logrotate read {read}.")
    lines.append("")

    for finding in findings:
        header = f"{_where(finding)}: {finding.kind}"
        if finding.checked == "invisible":
            header += " (not confirmed)"
        lines.append(header)
        lines.append(_wrap(finding.detail, "    "))
        if finding.instead:
            lines.append(f"    logrotate used: {finding.instead}")
        if finding.checked == "invisible":
            lines.append(
                _wrap(
                    "logrotate's plan never mentions this directive, so deleting it "
                    "proves nothing either way. This finding is the config text, not "
                    "a measurement.",
                    "    ",
                )
            )
        lines.append("")

    if findings:
        count = len(findings)
        verb = "has" if count == 1 else "have"
        plural = "" if count == 1 else "s"
        lines.append(f"{count} line{plural} here {verb} no effect on what logrotate does.")
    else:
        lines.append("Every rule unrotated can check rotates something.")

    candidates = result.confirmed + result.invisible + len(result.rejected)
    if result.verification == "checked" and candidates:
        lines.append(
            f"{result.confirmed} of them confirmed by blanking the line and running "
            f"logrotate again ({result.logrotate_runs} logrotate runs)."
        )
        if result.invisible:
            plural = "s" if result.invisible != 1 else ""
            subject = "it" if result.invisible == 1 else "them"
            lines.append(
                f"{result.invisible} directive{plural} could not be confirmed either "
                f"way: logrotate's plan does not mention {subject}."
            )

    if result.rejected:
        lines.append("")
        plural = "s" if len(result.rejected) != 1 else ""
        lines.append(f"{len(result.rejected)} candidate{plural} withdrawn after checking:")
        for note in result.rejected:
            lines.append(f"  {note}")

    return "\n".join(lines)


def as_json(result: Result) -> str:
    return json.dumps(
        {
            "config": result.config,
            "logrotate_version": result.version,
            "files_read": result.files_read,
            "findings": [
                {
                    "kind": finding.kind,
                    "file": finding.file,
                    "line": finding.line,
                    "subject": finding.subject,
                    "detail": finding.detail,
                    "instead": finding.instead,
                    "checked": finding.checked,
                }
                for finding in result.sorted_findings()
            ],
            "verification": result.verification,
            "verification_note": result.verification_note,
            "confirmed": result.confirmed,
            "unconfirmable": result.invisible,
            "rejected": result.rejected,
            "logrotate_runs": result.logrotate_runs,
            "blocks_not_checked": result.blocked_blocks,
            "patterns_not_checked": [
                {"pattern": pattern, "reason": reason}
                for pattern, reason in result.unknown_patterns
            ],
            "errors": result.errors,
        },
        indent=2,
        sort_keys=False,
    )
