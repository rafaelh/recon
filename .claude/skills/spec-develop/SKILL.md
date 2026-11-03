---
name: spec-develop
description: >
  Implement a specification file into code and tests. Use after a plan has been made and the user
  wants to implement it.
argument-hint: Which spec.md are we implementing?
model: sonnet
---

Implement a specification file into code and tests. If a complete specification file is not
supplied, ask the user to provide one and stop.

For a specification file to be considered complete, it must have a `# Design` section with all
decisions resolved. If the specification file is missing a `# Design` section, ask the user to run
`/spec-design` and stop.

Implement the specification file by:

1. **Map behaviours to tests.** List every behaviour in the spec next to the test(s) that will pin
   it, using the test plan in `# Design`. Every behaviour needs at least one test.
2. **Write the tests.** Only test files change in this step.
3. **Watch them fail.** Run the new tests and show the user that they fail.
4. **Write the code.** Write code to implement the behaviours.
5. **Confirm the tests pass.** Confirm all the tests pass.
6. **Refactor the code.** Refactor the code.
7. **Confirm the tests still pass.** Confirm the tests still pass.
8. **Update the specification file.** Update the specification file with a short, concise
   `# Implementation (Develop)` section that describes how the specification was implemented, how
   each behaviour was tested, and any deviations from the plan. Add any known limitations or edge
   cases that were not addressed to the `# Out of Scope` section.
9. **Stop** Tell the user the next step is to run `/spec-verify` and stop.
