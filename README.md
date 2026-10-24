# unrotated

Say which of your logrotate rules never rotate anything, and which of their
directives a later line always beats.

If you have inherited an `/etc/logrotate.d` and want to know which of it is
still doing something, this tells you. Not by reasoning about logrotate's
precedence rules — by reading the plan logrotate itself prints, and then
blanking each suspect line and asking it again to confirm nothing changed.

## Install

```sh
pip install -e .
```

Needs `logrotate` on `PATH`. Python 3.10+, no dependencies.

## Use

```sh
unrotated                        # /etc/logrotate.conf
unrotated path/to/logrotate.conf
unrotated -q                     # one line per finding
unrotated --json
unrotated --no-verify            # skip the deletion check
```

Exit code is 0 when there is nothing to report, 1 when there is, and 2 when
unrotated could not get an answer. On exit 2 nothing is printed to stdout, so
a run that failed can never be read as a clean config.

Nothing here writes to your config or your logs. Every logrotate run is `-d`,
with a throwaway state file, and the deletion check edits a copy.

## Why this isn't just `logrotate -d`

Because for most of what it finds, logrotate is quiet. Eleven cases, measured
against logrotate 3.21 — the table is
[a test](tests/test_against_logrotate.py), not a claim:

| what is wrong | logrotate's exit | error printed |
| --- | --- | --- |
| an interval a later one overrides | 0 | none |
| a `rotate N` a later one overrides | 0 | none |
| an interval replaced by `size` | 0 | none |
| `compress` then `nocompress` | 0 | none |
| a config file it never read (`nginx.dpkg-dist`) | 0 | none |
| a dead glob, with `missingok` | 0 | none |
| a missing log, with `missingok` | 0 | none |
| a dead glob, no `missingok` | 1 | yes |
| a missing log, no `missingok` | 1 | yes |
| a duplicate log entry | 1 | yes |
| an `include` that is not there | 1 | yes |

`missingok` is the hinge, and nearly every packaged drop-in sets it. That is
how a rule for a log that stopped existing two years ago survives in
`/etc/logrotate.d` indefinitely: logrotate looks at it every night, finds
nothing, and exits 0 without a word.

## An example

`examples/` is a plausible setup with the dead rules that accumulate in a real
one. Log paths there are quoted and relative so it runs from a clone —
logrotate rejects an *unquoted* relative pattern outright.

```
$ cd examples && unrotated logrotate.conf
logrotate.conf: logrotate read logrotate.conf, logrotate.d/app, logrotate.d/catchall, logrotate.d/ghost, logrotate.d/legacy, logrotate.d/sized.

logrotate.conf:16: include-missing
    `include logrotate.d.local` reads nothing: logrotate cannot stat it. This
    one is not silent -- logrotate reports it and exits 1 -- but from a cron
    job that nobody reads, the effect is the same

logrotate.d/app:2: overridden-directive
    `weekly` has no effect: `monthly` later in the same block sets the same
    thing, and logrotate keeps the last one
    logrotate used: logrotate.d/app:3

logrotate.d/app:4: overridden-directive
    `rotate 2` has no effect: `rotate 9` later in the same block sets the same
    thing, and logrotate keeps the last one
    logrotate used: logrotate.d/app:5

logrotate.d/app:6: overridden-directive (not confirmed)
    `compress` has no effect: `nocompress` later in the same block sets the
    same thing, and logrotate keeps the last one
    logrotate used: logrotate.d/app:7
    logrotate's plan never mentions this directive, so deleting it proves
    nothing either way. This finding is the config text, not a measurement.

logrotate.d/catchall:3: duplicate-log-entry
    logrotate already had logs/app.log from an earlier block, so this one does
    not rotate it. logrotate reports this and exits 1, which from a nightly
    cron job is a mail nobody reads
    logrotate used: logrotate.d/app:1

logrotate.d/catchall:3: rotates-nothing
    logrotate reports 'No logs found. Rotation not needed.' for this block:
    every log it names was already claimed by an earlier block, and a log
    belongs to exactly one of them

logrotate.d/ghost:1: log-missing
    logrotate found nothing to rotate for `logs/ghost.log`: it does not exist
    on this machine, and `missingok` means logrotate exits 0 over it without a
    word

logrotate.d/legacy:1: log-missing
    logrotate found nothing to rotate for `logs/legacy.log`: it does not exist
    on this machine. logrotate does report this one, and exits 1

logrotate.d/nginx.dpkg-dist: config-never-read
    logrotate found this file in logrotate.d and did not read it, because its
    name matches the taboo pattern *.dpkg-dist. Every directive in it is dead,
    and outside -d or -v logrotate says so to nobody

logrotate.d/sized:2: overridden-directive
    `daily` never decides a rotation: `size 100M` in the same block replaces
    the interval outright rather than adding to it. `maxsize` is the one that
    keeps the interval
    logrotate used: logrotate.d/sized:3

10 lines here have no effect on what logrotate does.
3 of them confirmed by blanking the line and running logrotate again (10 logrotate runs).
1 directive could not be confirmed either way: logrotate's plan does not mention it.
```

## The deletion check, and its control

An `overridden-directive` starts as a reading of the config: two assignments
to the same thing in one block, so the earlier one loses. To confirm it,
unrotated copies the whole config set to a temporary directory, blanks that
one line, and runs logrotate again. If the plan is byte-identical, the line
had no effect.

That check needs a control, because logrotate's plan does not mention every
directive it honours. `compress` does not appear in it at all, so blanking a
*live* `compress` also leaves the plan unchanged — and a checker without the
control would read that silence as proof and stamp "confirmed" on every
`compress` it was handed. So each candidate is tested twice: blank the loser,
then blank the winner. Only a candidate whose winner moves the plan has been
tested at all. The rest are reported as `(not confirmed)`, which means the
finding is the config text and unrotated is telling you so.

In practice the plan shows the interval, `rotate`, `maxsize`, `minsize` and
`ifempty`. It does not show `compress`, `copytruncate`, `create`, or the
weekday argument to `weekly`.

## What it will not tell you

- **Run it as root if you can.** logrotate drops privileges to the user a
  block's `su` names, and when it cannot, it stops before looking at that
  block's logs. unrotated falls back to the filesystem for those, says on
  stderr which blocks were affected, and distinguishes "no file matches" from
  "I was not allowed to look" — the second is reported as undetermined, not
  as dead. On this machine an unprivileged run found 8 of the 9 findings a
  root run did, and declined the ninth with a reason rather than guessing it.
- A pattern whose matches live under a directory that is readable but has an
  unreadable subdirectory is a gap in that fallback: `glob` skips what it
  cannot see, so the pattern can look emptier than it is. Only reachable on
  blocks logrotate itself would not settle.
- `missingok` findings on a machine where the package simply is not installed
  are working as intended. They are reported because the rule still rotates
  nothing, and because that is indistinguishable from the case you do care
  about until you read the name.
- Anything that depends on when logrotate last ran. unrotated always uses a
  fresh state file, so it is answering "what does this config do", not "what
  will happen tonight".
- Whether a `postrotate` script works. Script bodies are skipped, not run.

## Licence

MIT.
