---
name: spec-define
description: >
  Writes a specification for a code change which clarifies the goal and desired behaviours. Use
  before making a significant change.
argument-hint: What are you trying to achieve? Write your goal and any desired behaviours.
model: opus
---

Interview the user to establish what their goal is and help them write into a document a
specification that clearly identifies what behaviour they are trying to achieve in order to reach
that goal. A specification doesn't have to be long, 2 lines is sufficient for a simple change. Name
observable behaviour, meaning what a player, user or test would see, and leave mechanisms such as
class, event, file and field names to `/spec-design`, including when they come from the critic.


# Workflow

1. Ask the user what their goal is if it wasn't included in the prompt. Interview them relentlessly
   until a shared understanding of that goal is reached.

2. Iterate on defining the desired behaviours to achieve the goal with the user start by proposing
   behaviours based on the goal that the user can accept or allow the user to propose their own.
   Continue proposing behaviours and getting for user input until there are no more behaviours
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
   tell it not to raise these again unless the revised spec gives a new reason to. Don't run more
   than two passes unless requested by the user. After the last pass, apply the improvements and
   accepted decisions and move on to step 4.

4. Write the goal and the agreed behaviours to `output/YYYY-MM-spec-<goal>.md` (where <goal> is related to
   the user's goal; for example, if the goal is "allow users to reset their password", the file
   might be named `output/2026-10-spec-user-password-reset.md`). If it is a large set of behaviours, propose
   breaking them into a series of smaller spec documents, and follow the user's instructions. If
   multiple specs should run in a sequence, include a `-#` in the filename, with `#` being the
   number of the spec. After that, tell the user that the next step is to run `/spec-design` and
   stop.
