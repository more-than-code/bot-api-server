# Examples

Concrete examples of the Karpathy-derived behavioral rules used in this repo. These are for maintainers and reviewers: the goal is to show what bad agent behavior looks like and what a disciplined response looks like instead.

---

## 1. Think Before Coding

### Example: Hidden Assumptions

**User request:** "Add a feature to export user data"

**Bad response**
- Assumes export means all users
- Assumes file output instead of an API or UI download
- Assumes safe fields without checking privacy or volume

**Better response**
```text
Before implementing, I need to clarify:

1. Scope: all users or a filtered subset?
2. Format: API response, file download, or background job?
3. Fields: which fields are required, and are any sensitive?
4. Volume: does this need pagination or batching?

Simplest approach: start with a paginated JSON API once scope is confirmed.
```

### Example: Multiple Interpretations

**User request:** "Make search faster"

**Bad response**
- Silently picks one meaning of "faster"
- Adds caching, indexes, and async code in one pass

**Better response**
```text
"Faster" could mean lower latency, higher throughput, or better perceived UX.
Current behavior should be measured first, then optimize the dimension that matters.
```

---

## 2. Simplicity First

### Example: Over-Abstraction

**User request:** "Add a function to calculate discount"

**Bad response**
- Adds strategy interfaces, config objects, and multiple classes for a single formula

**Better response**
```python
def calculate_discount(amount: float, percent: float) -> float:
    return amount * (percent / 100)
```

Add abstraction later only if multiple discount behaviors actually appear.

### Example: Speculative Features

**User request:** "Save user preferences to the database"

**Bad response**
- Adds merge flags, validation toggles, notifications, and caching

**Better response**
```python
def save_preferences(db, user_id: int, preferences: dict) -> None:
    db.execute(
        "UPDATE users SET preferences = ? WHERE id = ?",
        (json.dumps(preferences), user_id),
    )
```

---

## 3. Surgical Changes

### Example: Drive-By Refactoring

**User request:** "Fix the bug where empty emails crash validation"

**Bad response**
- Fixes the email bug
- Changes comments and quote style
- Adds username validation and new docstrings

**Better response**
- Fix only empty-email handling
- Keep unrelated validation logic unchanged
- Mention adjacent issues separately instead of changing them

### Example: Style Drift

**User request:** "Add logging to this function"

**Bad response**
- Adds logging
- Converts single quotes to double quotes
- Adds type hints and reformats nearby code

**Better response**
- Add only the logging lines
- Match the surrounding code style exactly

### Example: Post-Commit Documentation

**User request:** "Fix inventoring so the Add panel stays open, then commit"

**Bad response**
1. Implements panel persistence in code
2. Commits code-only when asked
3. Updates `docs/` only after "did you update the docs?"

**Better response**
1. Implements panel persistence
2. Updates owning docs (`agentic-chat`, webapp inventoring note, glossary) **in the same work batch**
3. On "commit", stages **code + docs** in one per-intent commit (or one commit per repo, each including that repo's docs)
4. Reply includes Docs commit report with Completeness: Y

### Example: Status-Only Doc Gate (empty git status for docs)

**User request:** "Surface form values in dict search, then commit"

**Bad response**
1. Implements form search in code + tests
2. On commit: `git status` shows no `docs/` → stages only `src/` and tests
3. Leaves API contract saying "list q = headword only"

**Better response**
1. Implements form search
2. Resolves owners from `docs/docs-owners.md` (personal dictionary domain)
3. **Opens** API contract + agentic-chat even if clean; updates list-q prose
4. Stages code + docs together
```text
Owning docs: docs/ttd-api-contract.md, docs/agentic-chat.md
Completeness: Y
Umbrella glossary: updated | unversioned path only (../docs/naming-glossary.md)
```

### Example: Partial Docs ≠ Completeness

**User request:** (after multi-turn dictionary work) "commit changes"

**Bad response**
- Glossary was touched mid-session for countability
- Commits without re-checking API contract / list search wording
- Follow-up docs commit after user asks "did you update docs?"

**Better response**
- Before commit: re-read **final** behavior against **each** owner
- Patch any stale sentence (e.g. form search, noun_classes)
- One intent commit with code + all required docs; Docs commit report Completeness: Y

### Example: Commit Outside Workspace / on main

**User request:** (workspace = tutored) "commit changes so far"

**Bad response**
- Commits in `tutored/ttd-webapp` **and** silently commits in `~/workspace/skill-forge` on `main`

**Better response**
- Commits only under the active workspace repos the user meant
- If Skill Forge inventory also needs a commit: ask, with path + branch (`dev` vs `main`)
- Never commit on `main`/`master` without an explicit yes after naming that branch

---

## 4. Goal-Driven Execution

### Example: Bug Fix

**User request:** "Fix the crash when payload is missing `email`"

**Bad response**
- Edits production code first
- Declares success after manual inspection

**Better response**
```text
1. Write a test that reproduces the crash.
2. Run it and confirm it fails on current code.
3. Fix the root cause.
4. Re-run the new test and relevant existing tests.
```

### Example: Refactor

**User request:** "Refactor the parser"

**Bad response**
- Rewrites the parser without defining what must stay the same

**Better response**
```text
Goal: improve readability while preserving inputs, outputs, and error behavior.
Verify: existing parser tests pass before and after the refactor.
```


## 5. Diagnosis From Evidence

### Example: A Defect You Cannot Reproduce

**Situation:** A user reports that a control never appears in one context, while the same control works elsewhere. The agent cannot run that context itself.

**Bad response**
- Reads the component; explains the event listener is probably not attached
- Told it still fails; reads the same component; now explains the container reference is wrong
- Told it still fails; reads it again; now blames a scroll handler
- Each answer is confident, none is checked, and each costs the user a round trip

**Better response**
```text
My first explanation was wrong, so I am going to stop guessing and make the failure
report itself rather than read the file a third time.

There are five ways this function returns nothing. I have made each one log which
test rejected the input, and log the coordinates when it gets through. Reload,
reproduce it once, and paste what appears.

I cannot run this context myself - it is behind a login I do not have - so one line
of your console output is worth more than anything further I can infer.
```

Then: read the branch that actually fired, fix that cause, and remove the logging in the same change.

**Why it matters:** the instrumentation showed the control was being created all along and positioned off-screen - a cause none of the three readings had proposed, and one no further reading was likely to reach.
