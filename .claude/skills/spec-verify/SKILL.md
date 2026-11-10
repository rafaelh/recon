---
name: spec-verify
description: >
  Verify that a specification file has been implemented correctly. Use after a specification has
  been implemented.
argument-hint: Which spec.md are we verifying?
context: fork
background: false
model: opus
metadata:
  version: "1.4"
---

Check that the specification file at $ARGUMENTS has been implemented correctly. If no complete
specification file was supplied, say which file is missing and stop. Don't stash, reset or commit.
Don't return until every sub-agent you, or a skill you run, started has reported and its findings
are handled; a status line is not a result.

The implementation is every file that differs from the default branch (usually `main`) on this
branch, whether committed, uncommitted or untracked. Run `git add -N` on untracked files so they
show in the diff, then list the files with
`git diff --name-only $(git merge-base <default branch> HEAD)`.

Judge the implementation against the goal, the behaviours (as amended) and `## Out of scope`. Use
`# Design` only as a map to find the code, and read the docs listed under `## Conventions`. Treat
`# Implementation` as claims to check, not as evidence. A behaviour, or part of one, listed under
`## Known limitations` is not met, or only partly met, unless `## Out of scope` shows the user
agreed to leave it out.

Report any discrepancies between the specification and the implementation, including missing
behaviours, incorrect behaviours, or any other issues that prevent the implementation from meeting
the specification.

If you identify any bugs that can be fixed without deviating from the spec, fix them and confirm
that the tests still pass.

Write `# Verification` in the specification file, using the skeleton's headings. Under
`## Result`, briefly describe to what degree the code met each behaviour and the goal, and
summarise anything you changed or corrected up to this point.

When you are finished:
- Run `/code-review high --fix` on the files listed above. Wait for its result before continuing.
- Check each fix it applied against the spec. Undo by hand any fix that changes behaviour the spec
  doesn't ask for or edits a test that pins a behaviour, and list it as left unfixed.
- Confirm the tests still pass. If a code-review fix broke a test, fix it before continuing.
- Write a short `## Code review` section that says what was fixed, which behaviour each fix
  touched, and what was left unfixed and why.
- Rewrite `# Follow-ups` as the last section of the file: one ordered list of everything left for
  a person, such as manual steps, live runs and decisions only the user can make, gathered from
  every section of the file. Give each item the exact command or place to do it. If there is
  nothing, write "None."
- If the project's instructions say where to archive finished specification files, copy the file
  there.
- Then stop.

# Uploading the specification file
Run the following command outside the sandbox:
```
uv run --frozen blob upload specifications <spec-name>.md local-path/to/<spec-name>.md --confirm
```
