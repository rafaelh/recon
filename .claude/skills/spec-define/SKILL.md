---
name: spec-define
description: >
  Writes a specification for a code change which clarifies the goal and desired behaviours. Use
  before making a significant change.
argument-hint: What are you trying to achieve? Write your goal and any desired behaviours.
model: opus
metadata:
  version: "1.3"
---

Interview the user to establish what their goal is and help them write into a document a
specification that clearly identifies what behaviour they are trying to achieve in order to reach
that goal. A specification doesn't have to be long, 2 lines is sufficient for a simple change. Name
observable behaviour, meaning what a user or test would see, and leave mechanisms such as
class, event, file and field names to `/spec-design`, including when they come from the critic.


# Workflow

1. Ask the user what their goal is if it wasn't included in the prompt. Interview them relentlessly
   until a shared understanding of that goal is reached.

2. Iterate on defining the desired behaviours to achieve the goal with the user. Start by proposing
   behaviours based on the goal that the user can accept, or allow the user to propose their own.
   Continue proposing behaviours and asking for user input until there are no more behaviours
   necessary to reach the goal or the user asks you to stop.

3. Launch the `critic-specification` agent with the goal and the agreed behaviours pasted verbatim
   into its prompt. Don't summarise them; the critic reviews exactly what will be written. Sort its
   findings into two groups:
     - **Improvements** keep what the user chose and make it clearer, for example rewording a vague
       behaviour, making a behaviour testable, or defining how an edge case should be handled. Apply
       these without asking, then list each one with the change you made so the user can challenge
       it. If the user challenges one, undo it or settle it with them.
     - **Decisions** depart significantly from what the user chose: they change the goal, add or
       remove a behaviour, change what a behaviour does, or choose between alternatives the user
       hasn't assessed. Present each with its proposed rewrite or question, in groups as large as
       the question tool allows, so the user can weigh related choices side by side; never merge two
       decisions into one question. Put the most critical decisions first, along with any whose
       answer could change other decisions. Apply only the ones the user accepts. Go back to step 2
       to agree any new behaviours they need.

   If you can't tell which group a finding belongs in, treat it as a decision. Run the critic a
   second time only if an accepted decision changed the goal or added a behaviour. Improvements
   never cause a second pass. On every pass after the first, also give the critic each decision the
   user declined and each improvement they challenged, with their reason when they gave one, and
   tell it not to raise these again unless the revised spec gives a new reason to. On those passes,
   don't ask the user any questions: apply the improvements, and list each decision in one line
   without applying it, so the user can raise any they want. Don't run more than two passes unless
   requested by the user. After the last pass, apply the improvements and accepted decisions and
   move on to step 4.

4. Write the goal, the agreed behaviours and `## Out of scope` using the skeleton below.
   `## Out of scope` lists what was agreed to leave out, including each critic decision the user
   declined with a one-line reason, so later steps don't raise it again.

   Save the file in the folder the project keeps specifications in (check its instructions and any
   existing spec files); if there is none, use `output/specs/`. Name it `YYYY-MM-spec-<goal>.md`,
   where `<goal>` reflects the user's goal; for example, "allow users to reset their password"
   might be `2026-10-spec-user-password-reset.md`.

   If it is a large set of behaviours, propose breaking them into a series of smaller specs, and
   follow the user's instructions. Number a series in the filename (`-1`, `-2`, …) and the title.
   Each spec in a series has its own `## Goal`: the outcome of that slice alone, judged without the
   other specs, plus a line naming the specs it depends on. A goal for the whole series can be
   stated in the first spec, but it never replaces a spec's own goal.

5. Tell the user that the next step is to run `/spec-design` and stop.

# Skeleton

Every step writes only its own sections, with exactly these headings, in this order. A step that
adds a section puts it before `# Follow-ups`.

```markdown
# Spec: <title>                 (in a series: # Spec <n> of <m>: <title>)
## Goal
## Behaviours                   (numbered B1, B2, …)
## Out of scope
# Design                        (spec-design)
## External facts
## Decisions                    (numbered D1, D2, …)
## Files
## Tests
## Conventions
## Handed to later specs        (series only)
# Implementation                (spec-develop)
## Develop
## Known limitations
## Simplify                     (spec-simplify)
# Verification                  (spec-verify)
## Result
## Code review
# Follow-ups                    (any step adds; spec-verify finalises)
```

`## Out of scope` holds only what the user agreed to leave out. Gaps found while building go in
`## Known limitations`, and anything left for a person to do goes in `# Follow-ups`.
