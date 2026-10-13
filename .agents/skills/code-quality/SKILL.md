---
name: code-quality
description: >
  Review code for design quality, clarity, duplication, naming, error handling, and
  refactoring opportunities. Activate by default on implementation tasks for
  readability and maintainability, and during Tier 2/3 code quality and refactoring
  review lenses.
---

# Code Quality & Refactoring

Treat this skill as a default implementation-time guardrail, not only a review lens. Optimize for code that a human can read, trace, and modify safely without reconstructing hidden context.

## Checklist

### Design
- [ ] Single responsibility — each function/class does one thing
- [ ] Clear interfaces — public API obvious, internals hidden
- [ ] No circular dependencies
- [ ] Error handling complete — no swallowed exceptions, no silent failures
- [ ] Naming is precise — describes what, not how

### Simplicity
- [ ] No premature abstractions (class hierarchies, Strategy/Factory patterns for single use cases)
- [ ] No speculative features beyond what was requested
- [ ] No error handling for impossible scenarios
- [ ] Code length proportional to problem complexity (50 lines beats 200 if both solve the problem)
- [ ] No "flexibility" or "configurability" that wasn't requested
- [ ] Abstractions justified by repeated need, not by speculation

### Complexity
- [ ] Functions under 30 lines (guideline)
- [ ] Cyclomatic complexity under 10
- [ ] Max 3 levels of nesting
- [ ] No more than 4 parameters per function
- [ ] No boolean flag parameters that change behavior

### Duplication
- [ ] Same logic doesn't appear in 3+ places
- [ ] Shared patterns extracted to utilities
- [ ] No copy-paste with minor variations

### Readability
- [ ] Code self-documenting — good names, clear structure
- [ ] Comments explain *why*, never *what*
- [ ] No magic numbers or strings — named constants
- [ ] Consistent formatting with project conventions
- [ ] Control flow easy to trace end-to-end
- [ ] Indirection limited and justified — no spaghetti wiring across modules/functions
- [ ] Optimize for human comprehension first, then agent convenience

## Gotchas

- Extracting a helper after seeing it twice is premature — wait for 3 occurrences. The third reveals the real abstraction.
- Boolean parameters (`process(data, verbose=True)`) almost always mean the function does two things. Split it.
- "Self-documenting code" doesn't excuse missing *why* comments on business rules. `if balance < 0` is clear; *why* negative balances are allowed is not.
- Parallelized work merged in completion order produces non-deterministic output. Always merge in source encounter order.

## Patterns

### Output Determinism
When same inputs must produce same outputs:
- Use content-derived identifiers over random IDs
- Preserve source encounter order — don't sort by convenience
- Parallelize work, but merge results in deterministic order (source order, not completion order)

## Anti-Patterns

- **Premature abstraction** — don't extract until you see the pattern 3 times.
- **Over-parameterization** — adding `merge`, `validate`, `notify` flags to a function when only the core operation was requested.
- **Speculative features** — caching, event systems, plugin architectures for single-use code.
- **Clever code** — if it needs a comment to explain *what* it does, rewrite it.
- **Spaghetti code** — logic distributed across too many helpers, flags, callbacks, or layers to follow safely.
- **Non-deterministic output** — random IDs, completion-order merges, or unstable sorts that make diffing between runs impossible.

Change-scope anti-patterns (drive-by refactoring, style drift) are owned by `coding-discipline`.
