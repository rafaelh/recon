---
name: spec-design
description: >
  Interview the user to create a technical plan or design based on a specification. Use when
  creating a technical plan or design to implement the behaviours and goal described in a
  specification file.
argument-hint: Which spec.md are we making a plan for?
model: opus
metadata:
  version: "1.3"
---

Create a technical implementation plan for a user's specification, supplied in a markdown file. If a
specification file is not supplied, ask the user to provide one and stop.

Once you have the specification file, read it and Interview the user until every real decision in
the plan has an explicit answer. If you can answer your questions by reading the codebase, do so in
preference to asking the user.

Keep your context for the decisions. A search that sweeps many files or directories (where
something lives, how an existing feature does it, what calls a module) goes to an `Explore` agent,
which returns its conclusion and the file paths it rests on. Ask it a specific question and say
how thorough to be. Launch independent searches in one message so they run in parallel. Read a
file yourself when you already know which one you need and want its detail.

## Process

1. **Read the spec file.** Read the specification file and understand the goal, and required
   behaviours. If it is part of a series, also read the earlier specs' `## Handed to later specs`,
   `## Known limitations` and `# Follow-ups`.

2. **Enumerate the technical decisions.**
   - Identify every technical decision necessary to plan the implementation of the required
     behaviours from the specification.
   - Cut decisions where one option is clearly right or which the codebase already answers. List
     them in a short summary with the rationale for each answer.

3. **Check the external facts.** List every fact about something outside this codebase that the
   plan relies on: a vendor API's request and response shapes, its error responses, limits and
   paging, or how a third-party tool or platform behaves. Tag each one *confirmed live*, *from
   docs* or *assumed*. Before settling a decision that rests on an *assumed* fact, or on a *from
   docs* fact that would change the design if it were wrong, confirm the fact with a read-only
   probe: a read call, the tool's `--help`, or its source. If confirming it needs something only
   the user can do, such as credentials, a write or data they must create, ask for it now rather
   than leaving it for `/spec-develop`. Facts that still can't be confirmed keep their tag.

4. **Ask** Use `AskUserQuestion` and put every decision whose answer doesn't depend on another open
   decision into one call (up to four). Hold dependent decisions back until their roots are
   answered; they go in the next batch. A decision that changes what a behaviour says is always
   the user's to make.

5. **After each answer, re-scan for new branches** the answer opened up and add them to the queue.

6. **Stop** when every decision has an answer. Answers can be from those that are clearly right,
   from reading the codebase, or from the user.

7. **Get an adversarial review.** For plans that produce code, spawn the `critic-architecture` agent
   before the handoff. It starts cold, so the prompt must carry the whole settled plan: the goal,
   each decision with its answer and rationale, the modules and files it touches, what tests are
   needed to pin the desired behaviour and what is out of scope. Ask it to challenge
   over-engineering, missed requirements and simpler alternatives. Then triage what comes back, the
   same way as step 2:
   - **Wrong about the codebase or a missed requirement** — fix the plan and say what changed.
   - **Contradicts a decision the user made** — don't quietly overrule either side. Put it back to
     them as one new decision, with your recommendation and what the critic's alternative would
     change.
   - **Taste, or already weighed and rejected** — drop it, with a line saying why.
   Report the outcome briefly: what changed, what you dropped, what you're asking. Don't paste the
   critic's output. Skip this step for plans that produce no code, and run it once — a second pass
   on a revised plan only if the revisions were substantial. On a second pass, don't ask the user
   any questions: fix what's wrong, and list each finding that contradicts a user decision in one
   line without applying it, so the user can raise any they want.

8. **Write the plan.** Use the section headings from the skeleton in `/spec-define`. The next steps
   start in a new session with only this file, so write:
   - **Amended behaviours.** When an agreed decision changes what a behaviour says, edit that
     behaviour in `## Behaviours` and end it with `(amended by Dn)`, so later steps judge against
     the current wording. Add anything the user agreed to drop to `## Out of scope`.
   - `## External facts`: each fact from step 3 with its tag.
   - `## Decisions`: each decision, its answer and why.
   - `## Files`: the files and modules to change.
   - `## Tests`: the tests that pin each behaviour. For each behaviour, cover each of these that
     can happen, or say why it can't:
     - an error or unexpected response from each external dependency it uses;
     - one item failing in a batch: the rest are still processed and the failure is reported;
     - a crash or interrupt part-way: no secret leaks and cleanup still runs;
     - a re-run after success or after a partial failure: the result is the same, and checks run
       in the right order.

     Mark the behaviours where a bug would do the most harm, such as security, data loss or writes
     to live systems, for a mutation check in `/spec-develop`.
   - `## Conventions`: the project's convention docs and decision records that apply, if it has
     any.
   - `## Handed to later specs`, in a series only: what this spec deliberately leaves to a later
     one, naming which.
   - `# Follow-ups`: any manual step a person must take, such as a setting only an admin can change.

9. **Notify the user.** Tell the user the next step is to start a new session or run `/clear`, to
   set the model to Sonnet and run `/spec-develop <spec file>` and stop.
