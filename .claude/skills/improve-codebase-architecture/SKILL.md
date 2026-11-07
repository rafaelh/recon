---
name: improve-codebase-architecture
description: Find deepening opportunities in a codebase, informed by the domain language in CONTEXT.md and the decisions in docs/adr/. Use when the user wants to improve architecture, find refactoring opportunities, consolidate tightly-coupled modules, or make a codebase more testable and AI-navigable. Process: (1) explore the codebase for friction, (2) present deepening candidates, (3) use /plan to refine the chosen candidate's design.
---

# Improve Codebase Architecture

Surface architectural friction and propose **deepening opportunities** — refactors that turn shallow modules into deep ones. The aims are readability, testability, and AI-navigability. When two designs offer similar depth and leverage, prefer the one that is easier to read and understand.

## Glossary

Use these terms exactly in every suggestion. Consistent language is the point — don't drift into "component," "service," "API," or "boundary." Full definitions in [language.md](references/language.md).

- **Module** — anything with an interface and an implementation (function, class, package, slice).
- **Interface** — everything a caller must know to use the module: types, invariants, error modes, ordering, config. Not just the type signature.
- **Implementation** — the code inside.
- **Depth** — leverage at the interface: a lot of behaviour behind a small interface. **Deep** = high leverage. **Shallow** = interface nearly as complex as the implementation.
- **Seam** — where an interface lives; a place behaviour can be altered without editing in place. (Use this, not "boundary.")
- **Adapter** — a concrete thing satisfying an interface at a seam.
- **Leverage** — what callers get from depth.
- **Locality** — what maintainers get from depth: change, bugs, knowledge concentrated in one place.
- **Cohesion** — whether a module has a single, clear reason to exist. Depth without cohesion is a junk drawer behind a small door.
- **Cognitive load** — how many things a developer must hold in their head to understand or change a piece of code.

Key principles (see [language.md](references/language.md) for the full list):

- **Deletion test**: imagine deleting the module. If complexity vanishes, it was a pass-through. If complexity reappears across N callers, it was earning its keep.
- **The interface is the test surface.**
- **One adapter = hypothetical seam. Two adapters = real seam.**

This skill is _informed_ by the project's domain model. The domain language gives names to good seams; ADRs record decisions the skill should not re-litigate.

## Process

**Scope first.** Before exploring, identify how this skill was invoked:

- **Standalone / global review** (user explicitly asked to look at architecture): explore broadly.
- **Mid-feature (user came from `/tdd`'s friction note, or pointed at a specific area)**: scope to that area only. Don't open a global review. The right question is "what's the smallest deepening that resolves the noted friction?", not "what's everything worth deepening in this codebase?"

If unclear, ask. Manufacturing global findings during a small feature is the failure mode this skill must avoid.

### 1. Explore

Read the project's domain glossary (`CONTEXT.md`) and any ADRs in the area you're touching first. If the glossary or ADRs are missing or incomplete, flag this for the user and proceed with assumptions based on the codebase.

Then use the Agent tool with `subagent_type=Explore` to walk the codebase. Focus on areas with high coupling, low test coverage, or shallow modules, and note where you experience friction:

- Where does understanding one concept require bouncing between many small modules? (high **cognitive load**)
- Where are modules **shallow** — interface nearly as complex as the implementation?
- Where have pure functions been extracted just for testability, but the real bugs hide in how they're called (no **locality**)?
- Where do tightly-coupled modules leak across their seams?
- Which parts of the codebase are untested, or hard to test through their current interface?
- Where is unnecessary indirection making the code harder to follow — wrapper classes, middleman modules, premature generalization? (over-abstraction)
- Where do modules have misleading or vague names that don't match what they actually do?
- Where do dependencies flow in the wrong direction — circular dependencies, or stable modules depending on volatile ones?
- Where do callers consistently misuse a module — a sign the interface promises one thing but requires callers to know something extra?
- Where does a module do many unrelated things behind a single interface? (low **cohesion**)
- Where does the codebase's vocabulary drift from `CONTEXT.md`? Terms that exist in code but not in the glossary, the same word used with different meanings in adjacent modules, or a `CONTEXT.md` collision not yet flagged in `CONTEXT-MAP.md` are all signals: either the docs are stale or the architecture is muddier than the domain model would suggest. Both call for the same kind of fix.

Apply the **deletion test** to anything you suspect is shallow or over-abstracted: would deleting it concentrate complexity, or just move it? A "yes, concentrates" is the signal you want.

### 2. Present candidates

Present a numbered list of deepening opportunities. For each candidate:

- **Files** — which files/modules are involved
- **Problem** — why the current architecture is causing friction
- **Solution** — plain English description of what would change
- **Benefits** — explained in terms of locality, leverage, and readability, and also in how tests would improve

**Use CONTEXT.md vocabulary for the domain, and [language.md](references/language.md) vocabulary for the architecture.** If `CONTEXT.md` defines "Order," talk about "the Order intake module" — not "the FooBarHandler," and not "the Order service."

**ADR conflicts**: if a candidate contradicts an existing ADR, only surface it when the friction is real enough to warrant revisiting the ADR. Mark it clearly (e.g. _"contradicts ADR-0002 — but worth reopening because…"_). Don't list every theoretical refactor an ADR forbids.

Do NOT propose interfaces yet. Ask the user: "Which of these would you like to explore?"

### 3. Planning loop (`/plan`)

Once the user picks a candidate, **invoke `/plan` via the Skill tool** to drive the design conversation. `/plan` will grill the user one decision at a time; this skill stays paused until that conversation finishes. (You're not "becoming `/plan`" — you hand off, then resume here to surface the doc-update side effects below once the plan is final.)

Within the plan, walk the design tree — constraints, dependencies, the shape of the deepened module, what sits behind the seam, what tests survive. Read [references/deepening.md](references/deepening.md) when classifying the deepened module's dependencies (in-process / local-substitutable / remote-but-owned / true-external) and choosing its test strategy. Read [references/interface-design.md](references/interface-design.md) when interface design has real tension — multiple legitimate shapes with meaningful trade-offs.

Side effects happen inline as decisions crystallize. **Treat `CONTEXT.md` and `CONTEXT-MAP.md` updates as deliberate outputs of the plan, not afterthoughts.** Architectural changes routinely create, sharpen, or remove vocabulary — and if the docs don't reflect that, the next explorer (human or AI) loses the seam-finding signal the docs were meant to provide. Before finalising the plan, ask explicitly: *"what vocabulary does this change, and where does that get recorded?"*

The cases (any that apply must be named in the plan, not left implicit):

- **Naming a deepened module after a concept not in `CONTEXT.md`?** Add the term to the relevant per-context `CONTEXT.md` (see [context-format.md](assets/context-format.md)). Create the file lazily if it doesn't exist.
- **Sharpening a fuzzy term during the conversation?** Update its definition in `CONTEXT.md` in place.
- **New cross-context relationship introduced (e.g. a new data flow between two domains, a new event boundary)?** Add a bullet to `CONTEXT-MAP.md`'s "Relationships" section.
- **Vocabulary collision discovered between contexts** (the same word used differently in two places)? Add it to `CONTEXT-MAP.md`'s "Cross-context vocabulary clashes" with a resolution.
- **New bounded subdomain emerging from the refactor**? Create a new `CONTEXT.md` for it and register it in `CONTEXT-MAP.md`'s "Contexts" list.
- **Concept absorbed, merged, or removed by the refactor**? Strike it from `CONTEXT.md` (and any cross-references in `CONTEXT-MAP.md`) so future readers don't go looking for a term that no longer exists.
- **User rejects the candidate with a load-bearing reason?** Offer an ADR, framed as: _"Want me to record this as an ADR so future architecture reviews don't re-suggest it?"_ Only offer when the reason would actually be needed by a future explorer to avoid re-suggesting the same thing — skip ephemeral reasons ("not worth it right now") and self-evident ones. See [adr-format.md](assets/adr-format.md).
- **Want to explore alternative interfaces for the deepened module?** Read [references/interface-design.md](references/interface-design.md) when the user asks about alternative interface shapes, or when more than one viable interface emerges during planning.

## Gotchas

- **Scope first.** When invoked mid-feature (user came from `/tdd`'s friction note, or pointed at a specific area), find the smallest deepening that resolves the noted friction — not a global review. Manufacturing global findings during a small feature is the failure mode this skill must avoid.
- **Apply the deletion test before keeping a candidate.** If deleting the supposedly-shallow module wouldn't concentrate complexity across N callers, it's a pass-through — leave it alone. This filters out the "always finds something" failure mode.
- **One adapter = hypothetical seam. Two adapters = a real one.** Don't introduce a port unless at least two adapters are justified (typically production + test). A single-adapter seam is just indirection — surface area without leverage.
- **ADR conflicts: only surface when friction is real enough to revisit the ADR.** Don't list every theoretical refactor an ADR forbids. If you do surface one, mark it clearly (e.g. _"contradicts ADR-0002 — but worth reopening because…"_) and let the user decide.
- **`CONTEXT.md` and `CONTEXT-MAP.md` updates are deliberate plan outputs, not afterthoughts.** Before finalising, ask explicitly: *"what vocabulary does this change, and where does that get recorded?"* If the docs don't reflect the new shape, the next explorer loses the seam-finding signal.
- **Use `language.md` vocabulary for architecture (seam, adapter, leverage), `CONTEXT.md` vocabulary for the domain.** Don't drift into "component", "service", "API", or "boundary" — those are overloaded and erase the distinctions this skill depends on.
