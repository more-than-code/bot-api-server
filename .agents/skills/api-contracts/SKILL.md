---
name: api-contracts
description: >
  Enforce API contract versioning, backward compatibility, and consumer-driven contract
  testing. Activate for Tier 3 changes modifying public APIs, output schemas, or shared
  interfaces where consumers cannot all update simultaneously.
---

# API Contracts & Versioning

## Related Skills
- **migration-deprecation:** For contract changes with active consumers.
- **production-readiness:** When multiple services consume the contract.

## Checklist

- [ ] Contract change documented (before/after diff)
- [ ] Change classified: additive (safe) vs breaking (requires migration)
- [ ] Consumer impact assessed
- [ ] Versioning strategy chosen and applied
- [ ] Backward compatibility preserved during transition
- [ ] Sunset timeline defined for old version
- [ ] Consumer-driven contract tests added (if applicable)
- [ ] Documentation updated (API docs, schemas, examples)

## Gotchas

- Adding a new enum value is only safe if consumers use a default/unknown handler. Many deserializers throw on unknown values — treat new enums as potentially breaking.
- Changing a field from `null` to `[]` (or vice versa) looks additive but breaks consumers that check `if field is None`.
- Removing a field from documentation but not from the response doesn't help — consumers already depend on it.
- Error response format changes are breaking even though they're not "data." Consumers parse errors too.

## Patterns

### Default: additive-only changes
Prefer additive changes (new optional fields, new endpoints). This avoids versioning entirely. Only version when you must make a breaking change.

For breaking changes, use **URL path versioning** (`/v1/users` → `/v2/users`) — it's explicit and debuggable. Header-based versioning is an option for cleaner URLs but harder to test and debug.

### Sunset process
1. Announce deprecation with timeline
2. Add deprecation headers (`Sunset`, `Deprecation`)
3. Monitor usage of deprecated version
4. Return 410 Gone or redirect after sunset
5. Remove code after grace period

## Plan-Validate-Execute

Before shipping a contract change:
1. **Plan:** Document the before/after contract diff
2. **Validate:** Run consumer-driven contract tests against the new schema. If no contract tests exist, check all known consumers' parsing code.
3. **Execute:** Ship the change. Monitor error rates in consumers for 24h before declaring success.

## Anti-Patterns

- **Removing fields without versioning** — consumers get undefined/null/crash.
- **Changing semantics without renaming** — invisible breakage.
- **No sunset timeline** — old versions accumulate forever.
