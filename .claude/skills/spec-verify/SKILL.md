---
name: spec-verify
description: >
  Verify that a specification file has been implemented correctly. Use after a specification has
  been implemented.
argument-hint: Which spec.md are we verifying?
model: opus
---

Validate that a specification file has been implemented correctly. If a complete specification file
is not supplied, ask the user to provide one and stop.

Review the goal in the specification file and the agreed behaviours. The `# Design` section is not
important for this step, only that the desired behaviours and goal have been met.

Report any discrepancies between the specification and the implementation, including missing
behaviours, incorrect behaviours, or any other issues that prevent the implementation from meeting
the specification.

If you identify any bugs that can be fixed without deviating from the spec, fix them and confirm
that the tests still pass.

Write a short, concise `# Verification` section in the specification file that describes to what
degree the code met the defined behaviours and goal, along with a summary of anything you changed
or corrected.

When you are finished:
- Tell the user the last steps are to run `/simplify` and then `/code-review`, running `/clear`
  or creating a new conversation between each. And then stop.
