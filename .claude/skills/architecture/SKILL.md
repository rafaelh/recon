---
name: architecture
description: >-
  Find deepening opportunities in a codebase, informed by the domain language in CONTEXT.md. Use
  when the user wants to improve architecture, find refactoring opportunities, consolidate
  tightly-coupled modules, reduce how many files or rules a typical change involves, or make a
  codebase easier to change by hand, more testable, or more AI-navigable. Also use to create or
  update a CONTEXT.md, CONTEXT-MAP.md or ADRs from the codebase.
---

# Architecture

Surface architectural friction and propose refactors that turn shallow modules into deep ones (a lot of behaviour behind a small interface). The aims are readability, testability, AI-navigability, and keeping the code easy for a developer to change by hand: making a change shouldn't require knowing many things, and adding functionality shouldn't mean editing many files. When two designs offer similar depth, prefer the one that is easier to read and change by hand.

"Interface" here means everything a caller must know to use a module: types, invariants, error modes, ordering, config. Not just the signature.

## Domain docs

- `CONTEXT.md`: the domain glossary. Name modules after its concepts.
- `CONTEXT-MAP.md` (repo root, when there are several contexts): points to each context's `CONTEXT.md` and settles clashes between them. Read it first; its resolutions win.
- `docs/adr/`: decisions not to re-litigate. Invariants in the repo's agent instructions (`CLAUDE.md`, `AGENTS.md`) count the same.

If these are missing, flag it and work from the code's own vocabulary. If the user asks for the docs themselves rather than a review, skip to "Writing domain docs".

## Process

**Scope first.** If the user asked for an architecture review, explore broadly. If they pointed at a specific area or friction, scope to that area only and look for the smallest deepening that resolves it. Manufacturing global findings during a small feature is the failure mode to avoid. If unclear, ask.

### 1. Explore

Read the domain docs for the area. Then review the codebase. Beyond the usual smells, look for:

- Understanding one concept requires bouncing between many small modules.
- A typical change touches many files in lockstep, or depends on rules that aren't written down (registration order, a key that must encode a setting, a list kept in step with another). Walk through one or two of the changes this codebase most often gets, noting the files touched and what the developer must already know.
- Files that repeatedly change together in git history, especially across packages. This measures what walking through a change only estimates.
- Shallow modules: interface nearly as complex as the implementation.
- Pure functions extracted just for testability, while the real bugs hide in how they're called.
- One module doing several unrelated things behind a single interface, or mixing concepts from several contexts.
- Code vocabulary drifting from the domain docs. Either the docs are stale or the architecture is muddier than the domain model suggests.

**Deletion test** before keeping any candidate: imagine deleting the suspect module. If complexity vanishes, it was a pass-through. If it reappears across N callers, it was earning its keep. Only keep candidates where deepening concentrates complexity rather than just moving it.

**One adapter is a hypothetical seam; two is a real one.** Don't propose an interface/port unless at least two implementations are justified (typically production + test fake).

### 2. Present candidates

A numbered list of every candidate worth doing, ranked by payoff against risk. Don't cap it, and don't pad it: an empty list is a valid result. For each:

- **Files**: the modules involved
- **Evidence**: `file:line` references, or the files that co-change in git history
- **Problem**: why the current shape causes friction
- **Solution**: plain-English description of what would change
- **Benefits**: for callers, for maintainers (where change and bugs concentrate), for readability, and how tests would improve
- **Change cost**: files touched and things to know for a representative change, before and after. Say so if the refactor makes this worse (deepening can hide rules a developer then has to discover).

If a candidate contradicts an ADR or a stated invariant, surface it only when the friction is real enough to reopen the decision, and mark it as such.

Don't propose interfaces yet. Ask which candidate to explore. Offer to record the worthwhile candidates the user doesn't pick in the repo's deferred-work list, so they aren't lost when the conversation ends.

### 3. Planning loop

Once the user picks a candidate, create a plan. Once tests exist at the deepened module's interface, delete the old unit tests on the shallow modules it absorbed; don't layer the two.

**Alternative interfaces.** When the interface has real tension (several legitimate shapes with meaningful trade-offs), spawn 3+ agents in parallel, each with a different constraint:

- Minimise the interface: 1–3 entry points.
- Maximise flexibility and extension.
- Make the most common caller's case trivial.

Ask each for what adding a typical feature would touch, alongside the interface and its trade-offs. Compare them, then give an opinionated recommendation (or a hybrid), not a menu. For straightforward cases, sketch alternatives inline instead.

**Doc updates are plan outputs, not afterthoughts.** Before finalising, ask "what vocabulary does this change?" and name in the plan the updates to the owning `CONTEXT.md` and to `CONTEXT-MAP.md` (create the map if a second context appears). Also name any section of the agent instructions or `README.md` the refactor makes stale.

**ADRs.** If the user rejects a candidate for a reason a future reviewer would need, offer to record it so it isn't re-suggested.

## Writing domain docs

Draft from the code, then interview the user only on what the code can't settle: which of several names wins, whether two things are one concept, where one context ends and the next begins, and why a decision was made. Lead each question with your recommended answer. Match an existing file's format.

- `CONTEXT.md`: only concepts specific to this domain, each with one-sentence definitions and the aliases to avoid. General programming concepts don't belong even if the code uses them heavily.
- ADRs: `docs/adr/NNNN-slug.md`, one paragraph unless more earns its place. Only for decisions that are hard to reverse, surprising without context, and the result of a real trade-off.
