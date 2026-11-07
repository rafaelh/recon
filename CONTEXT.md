# recon

Passive-first reconnaissance of one authorised engagement: stages discover what the target exposes, and findings rank the obvious exposures among it.

## Language

### Engagement and scope

**Engagement**:
One named recon target, with its own directory, state database and stored scope inputs; re-runs add to it.
_Avoid_: project, job, run (a run is one execution against an engagement)

**Scope input**:
A root domain, organisation, ASN or netblock the user gave, or an exclusion.
_Avoid_: target, seed (a seed is a generator's derived input)

**Scope**:
The classification of any host or address as in scope, a candidate or excluded, built from the scope inputs and what has been resolved.

**Candidate**:
Something found that relates to the engagement but is not in scope; never contacted.
_Avoid_: out-of-scope, related

**Port-eligible**:
An address the port sweep may contact: in scope, not excluded, with a known, dedicated owner.

### Discovery

**Stage**:
One discovery step, contacting either third parties or the target (its contact), that turns checks into observations.
_Avoid_: module, plugin, source (a source is a third-party host a stage calls)

**Check**:
One unit of a stage's work, keyed by everything that changes the work done; completed or failed, never half-done.

**Observation**:
A fact one check found, of a record kind, under a key.

**Record**:
Everything observed under one kind and key, merged across checks; current while at least one completed check still observes it.
_Avoid_: row, entry, result

**Record kind**:
The type of a record (hostname, web_service, open_port, finding, ...), which fixes its attributes and how its records are shown.
_Avoid_: type, category (a category is a summary heading or a finding category)

**Shown**:
Whether a current record is counted, printed, written to the files and used for findings; decided when it is read, from the current scope.
_Avoid_: visible, displayed, filtered

**Inventory**:
What the current records say about hosts and addresses: resolutions, owners, providers, wildcards.

### Exposures

**Evidence**:
A record a stage stores for findings to be derived from (takeover_http, storage, sensitive_hit, email_posture, ...).
_Avoid_: risk, finding

**Finding**:
An obvious exposure derived from evidence on read, with a category, type, severity and target; never stored by a stage.
_Avoid_: risk, vulnerability, issue

**Finding category**:
The family a finding belongs to (takeover, storage, email, ...), which names its file, `risk-<category>.csv`.

**Attribution**:
Whether something in scope references a storage bucket; an unattributed bucket was only guessed from a scope input.

## Relationships

- An **Engagement** has many **Scope inputs**, which build one **Scope** per pass
- A **Stage** yields many **Checks**; a completed **Check** makes zero or more **Observations**
- Each **Observation** belongs to exactly one **Record**, of one **Record kind**
- Whether a **Record** is **Shown** depends on its **Record kind**, the **Scope** and the **Inventory**
- A **Finding** is derived from **Shown** **Evidence**; a **Finding** that is no longer derived stays on record, not current

## Example dialogue

> **Dev:** "The takeover stage found a fingerprint match. Does it store a **Finding**?"
> **Domain expert:** "No. It stores **Evidence**, a takeover_http **Record**. The **Finding** is derived from it, and only while the web service is **Shown**."
> **Dev:** "So if the user excludes that host later, the **Finding** goes away?"
> **Domain expert:** "It stops being current. It stays in `risk-takeover.csv` as not current, so the history isn't lost."

## Flagged ambiguities

- "risk" names the files (`risk-*.csv`), the evidence stages (`internal/stages/risk`) and, loosely, findings. Resolved: the concept is **Finding**; `risk-` is only the file prefix, and the stage package keeps its name for now.
- "visible" was used for the showing rules (`output.Visible`, `WebVisibility`). Resolved: the term is **Shown**, and the rules live with the **Record kind** table in `internal/kinds`.
- "kinds" the package is more than a lookup table: it defines every **Record kind**, the attributes its **Observations** carry, and the rules for showing its records.
