---
name: coding-discipline
description: >
  Behavioral guardrails against common LLM coding pitfalls: overengineering, hidden
  assumptions, drive-by edits, vague execution, post-hoc documentation, diagnosing a
  runtime failure by re-reading source instead of observing it, and unsafe git commits
  (outside workspace; main/master without asking). Activate on all implementation tasks
  alongside security-baseline, and when a bug resists its first explanation. Derived from
  Andrej Karpathy's observations on LLM coding failure modes.
---

# Coding Discipline

Behavioral guidelines to reduce common LLM coding mistakes. These address failure modes where the code is not technically wrong but is overcomplicated, assumes too much, changes more than it should, or leaves product/API docs to a later commit.

Use this skill as part of the default implementation-time skill set defined in the core agent instructions. It should be active before writing code on every implementation task, alongside `security-baseline` and `code-quality`.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks (typo fixes, obvious one-liners), use judgment.

## Related Skills

- `code-quality` — Default maintainability and readability guardrails used during implementation and review
- `testing-strategy` — Test-first verification patterns
- `EXAMPLES.md` — Before/after examples kept beside this skill so they travel with the copied package

## Checklist

### Before Writing Code
- [ ] Assumptions stated explicitly — nothing guessed silently
- [ ] Ambiguous requests clarified — multiple interpretations presented, not picked silently
- [ ] Simplest viable approach identified — pushed back if a simpler way exists
- [ ] Success criteria defined and verifiable — not "make it work"
- [ ] **Owning docs identified** — resolve via project `docs/docs-owners.md` (or equivalent) when present; otherwise repo `docs/`, API contract, glossary, skill-facing narrative — or explicitly **N/A** for pure internals. List paths **before** coding when docs apply.

### During Implementation
- [ ] Every changed line traces to the request
- [ ] Artifact-level simplicity, complexity, and readability checks applied from `code-quality` (activated alongside this skill)
- [ ] **Docs co-authored with code** when owning docs apply — edit narrative in the same work batch as the implementation, not after the user asks "did you update docs?"

### After Implementation (before claiming done or committing)
- [ ] Orphaned imports/variables from YOUR changes cleaned up
- [ ] Pre-existing dead code left alone (mentioned, not deleted)
- [ ] Existing code style matched (quotes, spacing, naming)
- [ ] No drive-by improvements to adjacent code
- [ ] **Doc co-delivery check** (below) — required docs are already in the working tree with the code
- [ ] **Completeness:** re-read final behavior against each owning doc surface — not “some docs touched earlier”

### Before Any User-Requested Commit (fail-closed)

Run this **before** `git add` / `git commit`. Do **not** treat “no doc files in `git status`” as “docs N/A.”

1. [ ] **Repo is inside the active workspace** (or a path the user explicitly named) — never commit elsewhere
2. [ ] **Branch is not `main`/`master`** (or production default) unless the user explicitly authorized that branch after you asked
3. [ ] **Resolve owning docs for this intent** (project owner map → fallback list). Contract/UX/tool/API/harness/naming changes require owners; pure internals may be N/A
4. [ ] **Open / re-read each owning path** even if the file is clean in git — patch if the final behavior is not reflected
5. [ ] **Stage docs with code** in the same per-intent commit (when docs apply)
6. [ ] Commit message covers behavior **and** doc surface when both changed
7. [ ] No "code commit now, docs later" split for the same intent
8. [ ] **Emit the Docs commit report** (below) in the reply that performs or summarizes the commit

#### Docs commit report (mandatory in the commit reply)

```text
Owning docs: <path>[, <path>…] | N/A because <one-line reason>
Completeness: re-read final behavior → each owner still true (Y/N)
Umbrella glossary: updated | N/A | unversioned path only (<path>)
```

- If **Completeness = N** → **do not** `git commit`. Fix docs first, then one intent commit.
- If required owners were never opened this turn → Completeness cannot be Y.
- Partial mid-session doc edits do **not** satisfy Completeness; re-check against **final** behavior.

## Documentation co-delivery (HARD)

Owning documentation is part of the implementation unit whenever behavior is load-bearing for humans or other agents.

### When docs are required (non-exhaustive)

- Public or chat-facing **contracts** (API fields, tool result shapes, CLI)
- User-visible **flows** (composer panels, inventoring, recap, nav)
- Agent/tool **harness** narrative (`agentic-chat`, skills that describe tools)
- Cross-repo **glossary / naming** when terms or inventory units change
- Architecture or design decisions that future agents must not re-discover from code alone

### When docs are N/A

- Pure internal refactors with identical external behavior
- Typos, log lines, private helpers with no contract/UX change
- State N/A briefly if asked; do not invent doc churn

### Rules

1. **Same work batch as code.** Update owning docs while implementing (or in the same continuous session before "done"), not as a follow-up commit after the user notices drift.
2. **Same commit as code** when the user asks to commit that intent. Do not land code-only commits and a later docs-only commit for the same feature/fix unless the user explicitly asks to split.
3. **Identify owners first.** Prefer the repo's documented SSOT:
   - **`docs/docs-owners.md`** (domain → paths) when the project maintains one
   - else `docs/agentic-chat.md`, API contract, `docs/README.md` index, umbrella glossary
   - Touch only docs that must stay true
4. **Completeness, not presence.** Editing *some* related prose earlier is insufficient. Before commit, each owning surface must still match the **final** behavior (search rules, field shapes, UI affordances).
5. **Status-driven staging is not enough.** `git status` only lists files already modified. If docs were never edited, open owners, update, then stage — do not skip because status is empty of docs.
6. **No ceremony dumps.** Short, surgical doc edits that match the code delta. No unsolicited README novels.
7. **Multi-repo:** each child repo that changes contracts/UX updates its own docs in **that** repo's intent commit.
8. **Umbrella / unversioned glossary:** when shared naming or inventory units change, update the umbrella glossary path used by the workspace (e.g. `docs/naming-glossary.md` at umbrella root). If that path is **not** inside a git repo, still update it on disk and state in the Docs commit report: `Umbrella glossary: unversioned path only (…)`. Do **not** pretend child-repo commits version it. Prefer a child-repo pointer or copy only when the project already has one as SSOT.
9. **Commit gate:** if docs were required and are missing from the staged set **or** Completeness is N → **stop**, fix docs, then commit once. Never answer "I'll document next" after a code commit for the same intent.

## Patterns

### Assumption Surfacing

When a request is ambiguous, surface assumptions before implementing:

```
Before implementing, I need to clarify:

1. **Scope**: [what's unclear about scope]
2. **Format**: [what's unclear about approach]
3. **Constraints**: [what's unclear about boundaries]

Simplest approach: [your recommendation]
What's your preference?
```

### Goal Transformation

Transform vague requests into verifiable goals:

| Instead of... | Transform to... |
|--------------|-----------------|
| "Add validation" | "Write tests for invalid inputs, then make them pass" |
| "Fix the bug" | "Write a test that reproduces it, then make it pass" |
| "Refactor X" | "Ensure tests pass before and after" |
| "Make it faster" | "Measure current perf, set target, verify after change" |

### Incremental Verification

For multi-step tasks, verify at each step:

```
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
3. [Step] -> verify: [check]
```

Each step is independently verifiable. Don't batch all verification to the end.

### Diagnosis From Evidence

A failure you cannot observe is not diagnosed by reading the code again. The first explanation drawn from source is a hypothesis. The second, drawn from the same source, is usually another hypothesis rather than a correction - source reading pattern-matches into a plausible story, and it will produce a fresh story every pass.

**The trigger is one wrong explanation, not four.** When a runtime symptom outlives your first theory, stop reading and make the failure describe itself:

```
1. Name every branch that could produce the symptom
2. Make each one say so - log which test rejected the input, and the values it computed
3. Run it; read which branch actually fired
4. Fix that cause, and delete the instrumentation in the same change
```

Passing types and passing unit tests are not evidence that a wired path works: a transport can hold its own green tests while the path through it is broken end to end. Ask what was actually observed, not what compiles.

When the behavior is only reachable somewhere you cannot run it - behind a login, on another machine, in someone else's browser - say so on the **first** failure and ask for the observation. Turns spent theorizing about state you cannot reach are turns spent producing confident wrong answers.

Observed 2026-09-02: four successive rounds of source reading produced four confident and incorrect causes for one UI defect; roughly twenty lines of branch logging identified it on the next round.

### Docs-with-code batch

```
1. Implement behavior + tests
2. Resolve owning docs (owner map) and update them against final behavior
3. Only then claim complete / accept "commit" for that intent
4. On commit: Docs commit report → stage code + docs → one intent commit
```

### Commit-time owner open (contract / UX / tools)

```
User: "commit"
Agent:
  1. Classify intent (contract/UX/tool vs pure internal)
  2. Load docs/docs-owners.md or fallback owners for that domain
  3. Read each owner; patch if stale vs final tree
  4. Docs commit report (Completeness Y)
  5. git add code + docs; commit once
```

## Verification

- [ ] Diff review: every changed line traces to the request (no drive-by edits)
- [ ] Complexity check: would a senior engineer say this is overcomplicated?
- [ ] Style check: existing conventions preserved (quotes, spacing, patterns)
- [ ] Orphan check: only YOUR orphans cleaned up, pre-existing dead code untouched
- [ ] Doc co-delivery: required docs present with code (or N/A stated)
- [ ] Doc completeness: final behavior reflected in every owning surface
- [ ] Commit reply includes Docs commit report when a commit was made
- [ ] Runtime claims rest on something observed - a log, a run, a report - not on source reading

## Anti-Patterns

Artifact-level anti-patterns (over-abstraction, speculative features, over-parameterization) are owned by `code-quality`. Worked before/after examples for all of them live in `EXAMPLES.md` beside this skill.

### Speculative Diagnosis

Explaining a runtime failure from source, repeatedly, without observing it. Every pass yields a fresh plausible cause and no evidence, and the confident tone hides that nothing has been established. Instrument after the first wrong answer.

### Drive-By Refactoring
**Wrong:** While fixing an empty-email crash, also add username validation, change comments, add docstrings, and "improve" email validation.
**Right:** Fix only the lines that handle empty emails. Mention other issues separately.

### Style Drift
**Wrong:** While adding logging to a function, also change single quotes to double quotes, add type hints, add a docstring, and reformat boolean returns.
**Right:** Add only the logging lines. Match existing quote style, spacing, and patterns.

### Hidden Assumptions
**Wrong:** "Add a feature to export user data" -> immediately implement JSON + CSV export to local files with hardcoded fields.
**Right:** Ask about scope (all users?), format (file download? API endpoint?), fields (which ones? sensitive data?), and volume (pagination needed?).

### Post-Commit Documentation
**Wrong:** Ship code + tests, commit when asked, then update docs only after the user asks "did you update the docs?"
**Right:** Treat owning docs as part of the implementation unit; stage them with the code in the same intent commit; emit Docs commit report.

### Status-Only Doc Gate
**Wrong:** `git status` shows no `docs/` changes → assume docs N/A and commit code-only for a contract/UX change.
**Right:** Resolve owners, open them even if clean, update if final behavior drifted, then stage with code.

### Partial Docs = Done
**Wrong:** Updated glossary mid-session; left API contract saying "headword only" after form search shipped; commit code.
**Right:** Completeness re-read of **each** owner against final behavior before commit.

### Commit Outside Workspace
**Wrong:** While working in project A, also `git commit` in `~/skill-forge` or another sibling repo because you edited it for tooling.
**Right:** Only commit in the workspace (or path) the user is working in / named. If another repo must change, ask first with the full path.

### Commit on main/master Without Asking
**Wrong:** User says "commit"; agent is on `main` and commits without checking the branch.
**Right:** Run `git branch --show-current`. If `main`/`master` (or production default), stop and ask for explicit confirmation before committing.
