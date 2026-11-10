---
name: spec-simplify
description: >
  Run /simplify on every file changed on the branch, in a forked context. Use during spec-develop,
  after the tests pass.
context: fork
background: false
model: opus
metadata:
  version: "1.4"
---

Don't stash, reset or commit.

1. Find the change: every file that differs from the default branch (usually `main`) on this
   branch, whether committed, uncommitted or untracked. Run `git add -N` on untracked files so they
   show in the diff, then list the files with
   `git diff --name-only $(git merge-base <default branch> HEAD)`.

2. Run /simplify on those files. Wait until every reviewer it starts has reported, then apply or
   reject each finding yourself. Don't move on while any reviewer is still running.

3. Add a short `## Simplify` section at the end of `# Implementation` in the specification file at
   $ARGUMENTS that says what was fixed and what was skipped.

4. Only once steps 2 and 3 are done, return a short list of what was fixed and what was skipped.
   A status line such as "the reviewers are running" is not a result.
