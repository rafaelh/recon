---
name: spec-develop
description: >
  Implement a specification file into code and tests. Use after a plan has been made and the user
  wants to implement it.
argument-hint: "<spec.md> [--wt] [--writepr]"
model: sonnet
metadata:
  version: "1.4"
---

Implement a specification file into code and tests. The arguments are the specification file and,
optionally, the `--wt` flag. If a complete specification file is not supplied, ask the user to
provide one and stop.

For a specification file to be considered complete, it must have a `# Design` section with all
decisions resolved. If the specification file is missing a `# Design` section, ask the user to run
`/spec-design` and stop.

Implement the specification file by:

1. **Set up a worktree.** Only if `--wt` was passed; without the flag, skip this step.
   - Bring local `main` up to date: run `git fetch origin`, then find the worktree that has `main`
     checked out with `git worktree list --porcelain`. If one does, run
     `git -C <that worktree> merge --ff-only origin/main`; if none does, run
     `git fetch origin main:main`. If `main` can't fast-forward, tell the user and stop.
   - Create a worktree on a new branch from `main`, named after the spec's goal with a
     conventional-commit prefix:
     `git worktree add -b feat/<short-name> .claude/worktrees/<short-name> main`. Then call
     `EnterWorktree` with that `path`, so every later step, including the forked skills, runs in
     the worktree.
   - Set up the worktree's environment the way the project's instructions (e.g. `CLAUDE.md`) say
     to, such as installing dependencies, without changing any lockfile.
   - Copy the spec file's current contents to the same relative path in the worktree, whether or
     not git tracks it, and use that copy as `<spec file>` from here on.

2. **Read the conventions.** Read the docs listed under `## Conventions`, if any.

3. **Map behaviours to tests.** List every behaviour in the spec next to the test(s) that will pin
   it, using `## Tests`, including its failure-path tests. Every behaviour needs at least one test.

4. **Write the tests.** Only test files change in this step, apart from the stubs in step 5.
   If you split steps 4 to 7 across sub-agents, spawn each as the `spec-develop-worker` agent and
   brief it with only its group's behaviours, owned files and tests; the agent already carries the
   standing rules and report format. Keep every git write to yourself, and check a worker's claims
   against the tree before you repeat them.

5. **Watch them fail on an assertion.** Run the new tests and show the user that they fail. A test
   that fails only because a module, function or file doesn't exist yet proves nothing, so add the
   smallest stubs that let the tests load and fail on their assertions. A test that pins existing
   behaviour may pass already; say which ones do.

6. **Write the code.** Write code to implement the behaviours.

7. **Confirm the tests pass.** Confirm all the tests pass.

8. **Update the specification file.** Write `# Implementation` using the skeleton's headings:
   - `## Develop`: a short, concise account of how the specification was implemented, how each
     behaviour was tested, any deviations from the plan, and any external fact that turned out
     different from `## External facts`.
   - `## Known limitations`: any behaviour, or part of one, that isn't fully met, and edge cases
     that weren't addressed, each naming its behaviour. Never move these into `## Out of scope`;
     that section holds only what the user agreed to leave out.
   - Add anything left for a person to do to `# Follow-ups`.

9. **Simplify the code.** Run `/spec-simplify <spec file>` and show the user its summary of what
   was fixed and what was skipped. If it returns before its sub-agents have reported, wait for
   their reports and handle the findings before continuing.

10. **Confirm the tests still pass.** If a simplification broke a test, fix it before continuing.

11. **Check the tests can fail.** Do this now, once the code has stopped moving, so each check runs
    once. For each behaviour `## Tests` marks for a mutation check, break the code that implements
    it by hand, for example by removing a guard or inverting a condition. Run the tests and confirm
    at least one fails, then undo your edit by hand. Don't undo it with git, which would also
    discard other uncommitted work. If no test fails, add one that does. Record the results in
    `## Develop`.

12. **Verify the implementation.** Run `/spec-verify <spec file>` and show the user its summary of
    what was fixed and what was skipped, and its follow-ups list. If it returns before its
    sub-agents have reported, wait for their reports and handle the findings before continuing.

13. **Stop.** If `--wt` was passed, tell the user the worktree path and branch, and leave the
    worktree in place. Then stop.
