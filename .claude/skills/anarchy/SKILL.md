---
name: anarchy
description: >-
  Identify unintended rules that pin behaviour that is tangential to the aim of the codebase.
---

In agent built codebases, code often contains rules that have arisen unintentionally. The user
makes a supporting decision to get to an outcome because they are asked, but the user's choice isn't
an intended requirement that needs to be kept going forward as long as the overall aim is achieved.

Review the code provided by the user. If the user does not provide any code, walk the codebase and
do a general review. Your aim is to identify unintended rules that pin behaviour that is tangential
to the aim of the codebase.

Ask yourself the question: Would the user have asked specifically for this behaviour? Does it make
sense as a direct consequence of the code's aim?


## Where to look

A rule is pinned when something fails if it changes: usually a test, sometimes a doc that is treated
as a contract (README, help text, agent instructions). Start from the statements of rules and check
what pins them.

- Comments and docs that say "must", "never", "always" or "only".
- Tests that assert something does *not* happen, or that enumerate edge cases nobody would hit in
  real use.
- Special-case functions that carve out a named exception (a list of paths, a flag spelling).
- Code that re-implements a library's behaviour to keep a rule literally true in a corner case.
- Asymmetry: two similar inputs treated differently for no stated reason. One path was usually
  written first and the other added later.
- A rationale that points at a past event (a migration, a bad record, a one-off bug) rather than at
  the aim of the codebase.


## Presenting candidates

Once you have identified 1-5 candidates, ask the user to confirm whether they are intended or not.
For each one, give:

- where the rule lives and what pins it (the code, and the test or doc that would fail);
- why you think it is unintended;
- examples of how the code would change if the rule was removed. The change doesn't need to be
  large; the flexibility that comes from removing an unintended invariant is good enough.

Also list, briefly, the candidates you considered and kept, with the reason. It shows the user what
was checked and lets them disagree.


## Acting on the answers

The user's answer is not always yes or no. Expect three outcomes:

- **Unintended.** Remove the rule (see below).
- **Intended.** Keep it, and write the user's reason next to the rule (a comment, or the doc that
  states it) unless a reason is already there. A rule with its reason attached won't be flagged by
  the next review.
- **A real intent, implemented too broadly.** The user wanted something narrower, and the rule
  overshoots it. Restate the actual intent, replace the rule with one that matches it, and check
  whether the narrower rule makes something newly possible.

When removing a rule:

- Remove it from every place it is stated: code, tests, user docs, help text and agent
  instructions.
- If the user isn't sure what the right behaviour is, don't swap one pin for its opposite. Pick the
  simplest behaviour consistent with the rest of the code, and test only the property that matters
  rather than the incidental choice.
- Check for state produced under the old rule (cached results, completed work, stored data) that
  won't be redone automatically, and tell the user how to refresh it.
- Look for improvements the removal makes possible: duplicated paths that can merge, helpers that
  can go, features the rule was blocking.


## Examples

Example #1:

Code Comment: "The register must say truthfully where an assessment lives. The register is the only
index of that, so a row asserting a location it does not have is the one failure nothing downstream
can recover from."

Answer: This rule likely came from an error when gathering data, and this rule was put in place as
part of the work around.

Rationale: The user wouldn't ever ask for a register that wasn't correct; they would expect that to
be implied. Secondly, there are no specifics about why this rule is needed. The next step would be
to analyse the code and see if there are specific things that would make this rule necessary. If
there are, then the rule should be supplemented with that rationale. If there aren't, then the rule
should be removed. In this scenario it is unlikely that the code would need to change, since a
register that is correct is the behaviour you would expect of any source of truth.


Example #2:

Code Comment: "Enforcement classifications this CLI reads can be strings, lists, or null. Functions
must be able to handle all three types."

Answer: This rule likely came from bad source data. If the vast majority of the data fits one type,
then it's likely that it should all be that type and this rule exists to satisfy the existence of
an example record or an empty record.

Rationale: The user's main goal is likely to enforce certain classifications, not to handle multiple
data types. If the code can be refactored to assume a single data type or provide a more streamlined
approach, it would simplify the implementation and reduce complexity.


Example #3:

Code Comment: "The crawl never reads robots.txt or sitemap.xml." A test asserts that neither path is
requested, even when a page links to it.

Answer: A real intent, implemented too broadly. The user didn't want the crawl limited by what
robots.txt disallows. That became "never request robots.txt", which also throws away the URLs that
robots.txt and the sitemaps list.

Rationale: The narrower rule is "read robots.txt, don't obey it". Replacing the rule both removes a
special case and gives the crawl a new source of URLs.
