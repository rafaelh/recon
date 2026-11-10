---
name: spec-writepr
description: >
  Raise draft pull requests for the current branch, in a forked context, splitting changes over
  5000 added lines into a GitHub stacked PR, then fix CoPilot AI Code Review comments and CI
  failures and mark each PR ready for review once it is clean.
argument-hint: "[spec.md]"
context: fork
background: false
model: sonnet
metadata:
  version: "1.4"
---

Raise draft pull requests for the current branch, fix CoPilot AI Code Review comments and CI
failures on every one of them, and mark each ready for review only once it is clean.

If a specification file is given at $ARGUMENTS, read its goal to understand what the PR is for.

# Process

1. If the current branch is the default branch (usually `main`), create a branch named after the
   change, e.g. `feat/<short-name>`.

2. Commit all uncommitted and untracked work on the branch with a conventional-commit message,
   working through any test failures, pyright issues, or ruff linting issues that arise from the
   pre-commit hooks.

3. **Size the change.** Sum the added lines with `git diff --numstat origin/main...HEAD`, ignoring
   binary files (`-`). Deleted lines don't count. If 5000 or fewer lines are added, raise one PR
   from the branch and skip to step 5.

4. **Split into a GitHub stacked PR.** Plan the fewest parts that each add at most 5000 lines:
   - Each part must pass the pre-commit gate on its own, so keep tests with the code they test and
     order parts by dependency: `pkg/common` and `pkg/api` first, then `actions/` and `ai_agents/`,
     then `schedulers/`, workflows, and docs.
   - Put deletions in the part that lands their replacement, whatever their size.
   - A single file adding more than 5000 lines gets a part of its own; tell the user about it.

   Build the stack with the `gh stack` extension (`gh extension install github/gh-stack` if
   `gh stack` is missing), setting `GH_STACK_NO_UPDATE_NOTIFIER=1`. Start with
   `gh stack init <branch>-part-1` (its trunk is `main`), then `gh stack add <branch>-part-k` for
   each later part. On each part, bring its added and modified files across with
   `git checkout <branch> -- <paths>`, remove its deleted files, including rename sources, with
   `git rm -- <paths>`, and commit, letting the pre-commit hooks run. Confirm
   `git diff <branch> <branch>-part-N` is empty, then raise every part as a draft with
   `gh stack submit --auto`.

5. **Raise the PR as a draft** with `gh pr create --draft` (a stack was already raised by
   `gh stack submit --auto`), then set each PR's title and body with `gh pr edit`:
   - **Title:** conventional-commit format describing the goal of the change, e.g.
     `feat(githubsec): flag repos without branch protection`. Suffix stacked PRs with
     `(part k/N)`.
   - **Body:** follow the repo's PR template if it has one (e.g. `.github/pull_request_template.md`),
     dropping its HTML comments once filled in. Otherwise, write one plain-language sentence on the
     goal of the PR, then at most five `Key changes` bullets, grouping related changes.
   - Don't add a Claude Code footer or any other attribution line.

6. **Monitor every PR** in one loop rather than one at a time:
   - CoPilot AI Code Review comments, which are normally posted within two minutes. If a PR has
     no CoPilot review after ten minutes, request one with
     `gh pr edit <number> --add-reviewer @copilot` and wait up to ten minutes more.
   - Failing CI checks (other than needing human approval).

7. If CoPilot AI Code Review comments are found, review them and if they are a real issue, fix
   them and push the changes. Respond to each comment with a one line summary of what was fixed or
   why it was skipped and mark the comment as resolved.

8. If any CI check fails, fix it and push the changes. Add a comment to the PR with a concise
   summary of what failed and how it was fixed.

   In a stack, commit each fix on the lowest part it belongs to, then run `gh stack rebase` to
   carry it up the stack and `gh stack push` to push every part. If the rebase stops on a conflict
   (exit code 3), resolve it, `git add` the files, and run `gh stack rebase --continue`.

9. Make at most three rounds of fixes in total across steps 7 and 8, where a round covers every PR.

10. **Mark clean PRs ready.** A PR is clean when CoPilot has completed a review, `gh pr checks`
    shows no failing or pending checks other than human approval, and every review thread is
    resolved. Run `gh pr ready <number>` on each clean PR, and leave any PR that isn't clean as a
    draft, including one whose CoPilot review timed out.

11. Notify the user with each PR URL and whether it is ready or still a draft, what was fixed, and
    anything left unresolved, then stop.
