# Log colours and line format

A language-neutral spec for the console log layout and colour palette. Implement it with whatever
your language offers: raw ANSI escapes, or a styling library.

## Where it applies

This covers the log lines a tool writes to stderr, and the badge styles a human-mode table may
borrow. In a tool built to [Agent tools](agent-tools/README.md), those rules come first:

- **The flags decide which lines appear** ([Flags](agent-tools/0001-flags.md)):

  | Flags | Levels written |
  |---|---|
  | none | INFO and above |
  | `--quiet` | WARN and above |
  | `--json` | none; warnings travel in `meta.warnings` |
  | `--debug` | DEBUG and above, with or without `--json` |

- **The error that ends a run is not a log line.** It is written once, in the error format in
  [Output](agent-tools/0003-output.md#errors-on-stderr), with no timestamp or badge. Don't log an
  ERROR line for the same failure as well: the caller would pay for it twice, and under `--json`
  the extra line breaks the parse.
- **Tracebacks and stack traces appear only under `--debug`.**
- **Lines only.** No spinner, redraw or cursor movement, on a terminal or off it.

## Principles

1. **One palette, looked up by meaning.** Code asks for "level / WARN" or "severity / HIGH",
   never for a hex value. Categories reuse the same few base styles, so yellow always means
   "caution" and red always means "bad".
2. **Badges for status, plain text for content.** Status words (level, outcome, severity, HTTP
   status class) are *badges*: a light foreground on a dark tint of the same hue. The message
   itself uses the terminal's default foreground.
3. **Muted chrome.** Timestamps and separators are grey so the eye lands on the badge and message.
4. **Logs go to stderr; stdout is for data.** Piped JSON on stdout stays clean while stderr is
   coloured.
5. **Colour is optional.** Every line has a plain form with identical content, used for files,
   pipes and `NO_COLOR`.

The palette is designed for dark terminal backgrounds.

## Palette

### Base badge styles

| Style | Foreground | RGB | Background | RGB | Bold |
|---|---|---|---|---|---|
| DEBUG (grey) | `#a9b1c6` | 169,177,198 | `#2a2f3a` | 42,47,58 | no |
| INFO (blue) | `#8fb3ff` | 143,179,255 | `#1f2c4d` | 31,44,77 | no |
| WARN (yellow) | `#ecd08f` | 236,208,143 | `#3d3420` | 61,52,32 | no |
| ERROR (red) | `#f08a92` | 240,138,146 | `#4a2226` | 74,34,38 | no |
| CRIT (white on red) | `#f6f6f6` | 246,246,246 | `#a3343c` | 163,52,60 | **yes** |
| PASS (green) | `#a8d38a` | 168,211,138 | `#24361f` | 36,54,31 | no |
| DRY RUN (cyan) | `#8fd6e3` | 143,214,227 | `#1d3a40` | 29,58,64 | no |
| MEDIUM (orange) | `#f0b47c` | 240,180,124 | `#45301c` | 69,48,28 | no |

### Categories

Each category maps its labels onto the base styles above.

| Category | Label → style |
|---|---|
| `level` | DEBUG → DEBUG, INFO → INFO, WARN → WARN, ERROR → ERROR, CRIT → CRIT |
| `outcome` | PASS → PASS, FAIL → ERROR, SKIP → WARN, DRY RUN → DRY RUN |
| `severity` | CRITICAL → CRIT, HIGH → ERROR, MEDIUM → MEDIUM, LOW → WARN, INFO → INFO |
| `http_status` | 2xx → PASS, 3xx → DEBUG, 4xx → WARN, 5xx → ERROR (class = status code ÷ 100) |

### Foreground-only styles

No background, not bold.

| Category | Label | Foreground | RGB |
|---|---|---|---|
| `http_method` | GET | `#7dcfff` | 125,207,255 |
| `http_method` | POST | `#c099f0` | 192,153,240 |
| `http_method` | PATCH, PUT | `#e5a265` | 229,162,101 |
| `http_method` | DELETE | `#e06c75` | 224,108,117 |
| `chrome` | TIMESTAMP | `#7c8191` | 124,129,145 |
| `chrome` | SEPARATOR | `#4a4f5c` | 74,79,92 |

### Semantic text colours

For coloured running text (not badges), use only the **foreground** of a badge style, with no
background and no bold:

| Name | Foreground of |
|---|---|
| success | PASS `#a8d38a` |
| error | ERROR `#f08a92` |
| warning | WARN `#ecd08f` |
| info | INFO `#8fb3ff` |

## Lookup rules

- Lookup is **case-insensitive** (`"dry run"` finds `DRY RUN`); the rendered label is always the
  canonical upper-case one.
- **Synonyms**, tried when the name is not in the category:

  | Input | Renders as | Style |
  |---|---|---|
  | INFORMATIONAL | `INFO` | severity INFO |
  | CLEAN | `PASS` | outcome PASS |
  | UNKNOWN, NONE | its own text | DEBUG |

- An unknown name is an **error** by default. Callers rendering vendor-supplied values can opt in
  to a fallback: the name keeps its own text and takes the DEBUG style.
- **A badge that shows a field of a record only styles it.** The text is the value exactly as
  `--json` emits it, in its own case, padded to the category's width. Only the style is looked up:
  no synonym, no upper-casing, no override, no truncation. A human table that showed `INFO` where
  the record says `informational` would give a caller a value that `--filter` rejects. The fallback
  is always on here, so a value the vendor adds later renders in the DEBUG style instead of failing
  in human mode while `--json` succeeds.

## Badges

A badge is the label left-aligned and space-padded to the **widest label in its category**, with
one extra space each side, all carrying the style's foreground and background:

```
" " + pad_right(label, widest_in_category) + " "
```

So every badge in a category has the same width, and columns line up:

| Category | Widest label | Badge width |
|---|---|---|
| `level` | 5 (`DEBUG`) | 7 cells |
| `outcome` | 7 (`DRY RUN`) | 9 cells |
| `severity` | 8 (`CRITICAL`) | 10 cells |
| `http_status` | 3 (`2xx`) | 5 cells |

A caller may override the text shown (e.g. `200` in the 2xx style); padding and style stay the same.

## Log line format

### Coloured (terminal)

```
HH:MM:SS │  LEVEL  │ message
```

| Part | Content | Style |
|---|---|---|
| Timestamp | local time, 24-hour `HH:MM:SS`, no date | chrome TIMESTAMP |
| Separator | space, `│` (U+2502), space | chrome SEPARATOR |
| Badge | space + level label padded to 5 + space (7 cells) | level badge |
| Separator | space, `│`, space | chrome SEPARATOR |
| Message | the text, verbatim | terminal default |

The message starts at column 21 for every level.

### Plain (files, pipes, no colour)

```
HH:MM:SS | LEVEL | message
```

Same fields, an ASCII `|` instead of `│`, the label padded to 5 with no extra badge spaces, and no
escape codes at all. The message starts at column 19.

```
14:02:07 | DEBUG | resolving secret from keyring
14:02:07 | INFO  | fetched 212 detections
14:02:08 | WARN  | rate limited, retrying in 2s
14:02:09 | ERROR | request failed
14:02:09 | CRIT  | cannot continue
```

### Level labels

Levels are shortened to at most 5 characters so the column never moves:

| Numeric severity (Python scale) | Usual names | Label | Style |
|---|---|---|---|
| 10 | DEBUG, TRACE, VERBOSE | `DEBUG` | DEBUG |
| 20 | INFO | `INFO` | INFO |
| 30 | WARNING, WARN | `WARN` | WARN |
| 40 | ERROR | `ERROR` | ERROR |
| 50 | CRITICAL, FATAL | `CRIT` | CRIT |

A custom level that falls between two standard ones shows **its own name truncated to 5
characters**, in the style of the nearest standard level below it. Anything below DEBUG uses the
DEBUG style.

### Multi-line messages, tracebacks, stack traces

- Append any exception traceback and stack text after the message, then split on newlines.
- The first line gets the full prefix. Every following line is **indented with spaces to the
  message column** (21 coloured, 19 plain), with no timestamp or badge.

```
14:02:09 | ERROR | request failed
                   Traceback (most recent call last):
                     File "client.py", line 42, in fetch
                   TimeoutError: timed out
```

### Message handling

- Print the message **literally**: never interpret it as markup or style tags, and do not
  auto-highlight numbers, URLs or paths.
- Do not hard-wrap long lines to the terminal width; emit one line and let the terminal wrap it.
- Redact secrets before the line reaches the formatter, so the console and file outputs are both
  clean. The formatter itself does no redaction.

## When to use colour

Whether a stream gets colour is decided once per stream, at start-up, by the rule in
[Output](agent-tools/0003-output.md#human-mode). That rule is not repeated here, so the two can't
drift. This document adds only what is particular to logs:

- Log **files** always get the plain layout.
- On terminals without 24-bit colour, downgrade each colour to the nearest entry in the 256- or
  16-colour palette. Check that each badge's foreground still differs from its background after
  downgrading.

## ANSI reference

For implementations writing escape codes directly (`ESC` is byte `0x1b`):

| Effect | Sequence |
|---|---|
| Foreground `r,g,b` | `ESC[38;2;r;g;bm` |
| Background `r,g,b` | `ESC[48;2;r;g;bm` |
| Bold | `ESC[1m` |
| Reset | `ESC[0m` |

A WARN line, with `␛` standing for `ESC`:

```
␛[38;2;124;129;145m14:02:08␛[0m␛[38;2;74;79;92m │ ␛[0m␛[38;2;236;208;143;48;2;61;52;32m WARN  ␛[0m␛[38;2;74;79;92m │ ␛[0mrate limited, retrying in 2s
```

Reset after every styled span so the message and anything printed afterwards use the terminal
default.

## Implementation checklist

- [ ] Palette defined once as data (category → label → fg/bg/bold); nothing else holds a hex value.
- [ ] Case-insensitive lookup, synonyms, and an opt-in DEBUG-style fallback for unknown names.
- [ ] Badge helper that pads to the widest label in the category plus one space each side.
- [ ] Foreground-only helper for running text.
- [ ] One formatter producing both the coloured and the plain line from the same record.
- [ ] Continuation lines indented to the message column.
- [ ] Colour decided once per stream, by the rule in Output.
- [ ] Logs on stderr; file output plain; message printed literally.
- [ ] Levels follow `--quiet`, `--json` and `--debug`; the exit error bypasses the formatter.
- [ ] Record values in badges keep their own text, with the fallback on.
- [ ] A "palette sheet" command that prints every entry through the real formatter, for eyeballing
      a new terminal or theme.
