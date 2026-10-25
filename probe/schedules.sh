#!/usr/bin/env bash
# Measure the strings logrotate prints for a resolved rotation criterion, and
# which config file names it silently refuses to read.
#
# Both lists are hardcoded in src/unrotated/plan.py and src/unrotated/parse.py.
# They are hardcoded because unrotated has to recognise them at runtime, not
# because anybody read them off a man page: this script is where they came
# from, and it is how you check them against the logrotate you actually have.
#
#     ./probe/schedules.sh
#
# Writes nothing outside its own temporary directory and rotates nothing --
# every logrotate run here is `-d`, which only prints a plan.

set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/logs" "$work/d"
printf 'a line\n' > "$work/logs/a.log"

logrotate --version | head -1
echo

plan() { # plan <directives>
	printf '%b\n' "$work/logs/a.log {\n$1\n}" > "$work/c"
	rm -f "$work/state"
	logrotate -d -s "$work/state" "$work/c" 2>&1 |
		sed -n 's/^rotating pattern: .*\.log  //p'
}

echo "== rotation criteria, as logrotate prints them =="
for directive in hourly daily weekly 'weekly 3' monthly yearly 'size 1k'; do
	printf '%-12s -> %s\n' "$directive" "$(plan "$directive\nrotate 7")"
done
echo
echo "The one to notice: 'size' replaces the criterion and 'maxsize' does not."
printf '%-12s -> %s\n' 'daily+size' "$(plan 'daily\nsize 1k\nrotate 7')"
printf '%-12s -> %s\n' 'daily+maxsize' "$(plan 'daily\nmaxsize 1k\nrotate 7')"
echo
echo "And a block with no 'rotate' uses the other tail:"
printf '%-12s -> %s\n' 'weekly only' "$(plan 'weekly')"

echo
echo "== config file names logrotate will not read from an include dir =="
printf 'include %s\n' "$work/d" > "$work/top"
for suffix in .dpkg-dist .dpkg-old .dpkg-new .dpkg-bak .rpmsave .rpmorig \
	.rpmnew .swp .disabled .bak .ucf-old .ucf-dist .ucf-new .cfsaved \
	'~' .orig .old .conf .logrotate ''; do
	printf '%s/logs/a.log {\n weekly\n}\n' "$work" > "$work/d/cand$suffix"
done
mkdir -p "$work/d/subdir"
rm -f "$work/state"
output=$(logrotate -d -s "$work/state" "$work/top" 2>&1 || true)
printf '%s\n' "$output" | sed -n 's/^Ignoring /  skipped: /p' | sort
printf '%s\n' "$output" | sed -n 's|^reading config file cand|  read:    cand|p' | sort
echo
echo "Anything under 'read' is a name that looks like a backup and is not"
echo "treated as one. '.orig' and '.old' are the two that catch people out."
