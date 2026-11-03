---
name: spec-design
description: >
  Interview the user to create a technical plan or design based on a specification. Use when
  creating a technical plan or design to implement the behaviours and goal described in a
  specification file.
argument-hint: Which spec.md are we making a plan for?
model: opus
---

Create a technical implementation plan for a user's specification, supplied in a markdown file. If a
specification file is not supplied, ask the user to provide one and stop.

Once you have the specification file, read it and Interview the user until every real decision in
the plan has an explicit answer. If you can answer your questions by reading the codebase, do so in
preference to asking the user.

## Process

1. **Read the spec file.** Read the specification file and understand the goal, and required
   behaviours.
2. **Enumerate the technical decisions.**
  - Identify every technical decision necessary to plan the implementation of the required
    behaviours from the specification.
  - Cut decisions where one option is clearly right or which the codebase already answers. List them
    in a short summary with the rationale for each answer.
3. **Ask** Use `AskUserQuestion` and put every decision whose answer doesn't depend on another open
   decision into one call (up to four). Hold dependent decisions back until their roots are
   answered; they go in the next batch.
4. **After each answer, re-scan for new branches** the answer opened up and add them to the queue.
5. **Stop** when every decision has an answer. Answers can be from those that are clearly right,
   from reading the codebase, or from the user.
6. **Get an adversarial review.** For plans that produce code, spawn the `critic-architecture` agent
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
   on a revised plan only if the revisions were substantial.
7. **Write the plan.** Write the settled plan to a `# Design` heading in the specification
   file. Tell the user the next step is to run `/spec-develop` and stop.
