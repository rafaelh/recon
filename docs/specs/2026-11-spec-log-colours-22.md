# Spec 22: log colours and line format

## Goal

Someone watching a run can tell progress from problems at a glance, and can redirect the log apart
from the summary. Console output follows `docs/log-colors.md` except where this spec says
otherwise.

## Behaviours

B1. **Streams.** During a run in human mode, stdout carries only the end-of-run summary. The run
    header, stage lines, `+` found lines, count lines and warnings are log lines on stderr. The
    authorisation prompt and the run-ending `error:` line stay on stderr with no timestamp or
    level. A run that ends without a summary (interrupted, stopped by the netblock limit, or ended
    by an error) writes nothing to stdout.

B2. **Line layout.** On an uncoloured stream a log line is `HH:MM:SS | LEVEL | message`, with the
    level padded to 5, so the message follows the first 19 characters. On a coloured stream the
    separators are `│`, the level is a 7-cell badge, the timestamp and separators take the
    palette's chrome colours, and the message follows the first 21 cells. The time is the run's
    clock shown in the local time zone (`TZ`). The second and later lines of a multi-line message
    are indented by that many spaces (19 or 21), with no timestamp or level. No message of a run
    has more than one line today, so the palette sheet (B12) shows one.

B3. **Levels.** The run header, found lines, count lines and the lines of stages that are running,
    done, done-previously or not-configured are INFO. The line of a failed stage is ERROR. Every
    warning is WARN and is shown without any flag: for example a truncated result, a spent quota,
    addresses skipped because their owner is unknown, technology detection being off, or an
    interrupted run, and any warning a later spec adds. Per-check failure lines are DEBUG only:
    they are never also written as WARN lines.

B4. **Stages skipped for lack of authorisation.** When a run leaves stages out because
    authorisation was not confirmed, it writes one WARN line that names them and says that
    `--authorised` confirms authorisation. The line names exactly the stages whose stage line
    reads `not-configured (no authorisation)`, so a stage left out by `--skip` is not named. It is
    written once, right after the run header and before any stage line, so an interrupted run
    still shows it. When no stage is in that state, as under `--passive`, there is no line.

B5. **Flags.** By default INFO and above are written; with `--quiet` (`-q`) WARN and above; with
    `--debug` DEBUG and above. `--quiet` together with `--debug` is rejected with exit 2. Both are
    flags only: there is no config setting or `RECON_*` variable for either. `--verbose` is
    removed and is rejected like any unknown flag.

B6. **Message text.** The header, stage and count messages keep today's text (count lines keep
    their two-space indent) and carry no colour. The only colour inside any message is the
    severity badge on a finding's line.

B7. **Found lines.** The message is `+`, a space and the record as today. A finding with a
    severity carries a badge directly after the `+`, and its `[severity]` suffix is gone. The badge
    is the severity exactly as recorded (`high`, `medium`, `low`) padded to 8. On a coloured stream
    it has one more space each side (10 cells) and the palette's severity style: `high` as HIGH,
    `medium` as MEDIUM, `low` as LOW. On an uncoloured stream it is the padded word alone, with no
    brackets. A finding with no severity has no badge. A severity the palette does not know takes
    the DEBUG style; it never fails.

B8. **Summary.** A completed run writes the summary to stdout, with `--quiet` or without. Its
    content is as today with two changes: each listed finding shows the severity badge of B7 in
    place of `[high]`, and the failed-checks heading reads
    `Failed checks (retried on the next run; --debug shows each failure)`. On a coloured stream
    headings are bold, and there is no colour besides the badges.

B9. **Colour decision.** A stream is coloured only when it is a terminal, `NO_COLOR` is unset or
    empty and `TERM` is not `dumb`. stdout and stderr are decided separately, so
    `recon example.com 2> run.log` on a terminal writes a plain log and a coloured summary.
    `FORCE_COLOR` and `CLICOLOR_FORCE` force nothing. An uncoloured stream has no escape bytes.

B10. **Palette and colour depth.** Colours are those of the tables in `docs/log-colors.md`. They
    are written as 24-bit colour when `COLORTERM` is `truecolor` or `24bit`, as the nearest
    256-colour entries when `TERM` contains `256color`, and otherwise as the nearest 16-colour
    entries. These variables choose only the depth on a stream B9 has already decided to colour;
    they never turn colour on. At every depth each badge's foreground differs from its background.

B11. **`--json`.** stdout stays one JSON event per line. Warning events, including the one for B4,
    are in the stream without any flag, and `--quiet` changes nothing. Per-check failures are no
    longer warning events. stderr is empty unless `--debug` is given, which writes only the DEBUG
    lines to stderr (coloured or not by B9) and leaves stdout unchanged.

B12. **`--palette`.** A hidden flag that prints the palette sheet to stdout and exits 0: every
    entry of every table in `docs/log-colors.md` (the level, outcome, severity and HTTP status
    badges, the HTTP method and chrome colours, the semantic text colours), one sample log line
    per level, and one two-line message showing the continuation indent, all through the formatter
    a run uses. It follows B9 and B10, and under `--json` the sheet is uncoloured. Any inputs given
    with it are ignored: it needs no scope, contacts nothing and creates no engagement directory.

B13. **Message handling.** Target-supplied text is sanitised and secrets are redacted as today.
    Lines are never wrapped to the terminal width and never redrawn.

B14. **Docs.** README and `--help` describe `--quiet` and `--debug`, the two streams and the
    colour rule, and no longer mention `--verbose`. The README's authorisation section describes
    the warning of B4.

## Out of scope

- The `{data, meta}` envelope, error codes and the other agent-tools rules. `--json` keeps its
  event stream, with warnings and errors as events on stdout.
- Catching unexpected internal failures and hiding their stack trace unless `--debug` is given. A
  Go panic keeps printing its own trace, as today: recon catches no panics, and checks run on
  worker goroutines, so this is its own change.
- DEBUG lines for each check as it runs or for each outbound request.
- Outcome badges or coloured state words on stage lines: the level badge carries the status.
- A flag that adds detail to the summary. The ranked-candidates spec is amended to list high
  candidates only; the rest are in `candidates.csv`.
- Repeating INFO and WARN lines on stderr under `--json --debug`: they would duplicate the stdout
  events.
- Making each stage skipped for lack of authorisation a WARN line: one line per run names them all.
