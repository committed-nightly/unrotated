"""Command line. Exit 0 nothing to report, 1 findings, 2 no answer."""

from __future__ import annotations

import argparse
import sys

from . import report
from .analyse import AlignmentError, analyse
from .parse import ParseError
from .plan import LogrotateError

DEFAULT_CONFIG = "/etc/logrotate.conf"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unrotated",
        description=(
            "Say which of your logrotate rules never rotate anything, and which of "
            "their directives a later line always beats."
        ),
        epilog=(
            "Exit code is 0 when there is nothing to report, 1 when there is, and 2 "
            "when unrotated could not get an answer out of logrotate."
        ),
    )
    parser.add_argument(
        "config",
        nargs="?",
        default=DEFAULT_CONFIG,
        help=f"logrotate config to read (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="one line per finding")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the deletion check, which is what makes this slow on a big config",
    )
    parser.add_argument(
        "--logrotate",
        default="logrotate",
        metavar="PATH",
        help="the logrotate to ask (default: the one on PATH)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = analyse(
            args.config,
            binary=args.logrotate,
            verify=not args.no_verify,
        )
    except (LogrotateError, AlignmentError, ParseError) as error:
        print(f"unrotated: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"unrotated: {error}", file=sys.stderr)
        return 2

    for line in report.error_lines(result):
        print(line, file=sys.stderr)

    if args.json:
        print(report.as_json(result))
    else:
        rendered = report.text(result, quiet=args.quiet)
        if rendered:
            print(rendered)

    return 1 if result.findings else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
