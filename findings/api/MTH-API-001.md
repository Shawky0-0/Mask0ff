---
tags: [security, flash, advisories, method, api, access-control, maskoff]
updated: 2026-08-12
sources:
  - "https://x.com/mdp_sec/status/2085187655101530370 read in full 2026-08-12"
  - "security/maskoff/repo/SKILL.claude.md, the owner-matrix section"
  - "security/advisories-api/entries/APIDS-0001.md"
---

# MTH-API-001: the object graph, and why changing an ID is not a finding

**The technique in one line.** Before claiming broken access control, record four facts
about the object: which request created it, which account owns it, which accounts should be
able to reach it, and what the tested account actually got.

## The discovery signal

You are looking for a **gap between two identifiers in the same request**. Almost every API
handler that goes wrong this way takes both:

* a **scope**: a volume, a workspace, a tenant, a course, an organisation, a project;
* an **object ID**: the specific thing to act on.

The handler authorises against the scope and then loads by the ID. Nobody checks that the
loaded object is inside the authorised scope. **The permission check passes and proves
nothing.**

The signal in code review: an authorisation call and a fetch call that use different
variables. The signal in black box testing: an endpoint whose response changes when you
alter the ID but not the scope.

## The mechanism

Two questions look like one question:

1. May this account write to scope X? (usually checked)
2. Is the object it is writing to actually inside scope X? (usually not)

A correct answer to question 1 is often mistaken for an answer to both.

## Why this is the method and not just a bug

Two independent practitioners converged on the same discipline. mask0ff added `owner-matrix`
in 2.0. Marius du Preez built the same recording step into his system and described it in
almost identical words. Both drew the same line:

> **"I changed an ID in the URL and something happened"** is an observation.
> **"This object was created by that request, it belongs to that owner, this account should
> not reach it, and it did"** is a finding.

The difference is not rigour for its own sake. It is that the first version gets rejected by
a vendor and the second does not, because the first cannot rule out that the account already
held the authority through a legitimate path. That ruling out is gate `E1`, authority delta.

## How to run it safely

1. **Two accounts, two scopes.** Attacker account with access to scope 1 only. Victim
   account owning an object in scope 2.
2. **Create the object through the product's own interface**, and record which request
   created it. That request is the evidence for who should own it.
3. **Write down the expected answer before testing.** Which accounts should reach this
   object? If you cannot state that, you cannot call anything a violation.
4. **Touch a marker field only.** Never delete, never move real data, never touch a third
   party. A canary string in a title field is enough.
5. **Record what the tested account actually got**, including partial results: a 200 with an
   empty body is a different finding from a 200 with the object.
6. **Rule out legitimate authority.** Did the attacker account already hold a global or
   administrative capability that makes this intended? On WordPress, check the capability
   the role already has before calling anything escalation.

## The false positive control

The one that kills most claims: **intended sharing**. A workspace tool where any member can
edit any document in the workspace is working as designed, and "I edited a document I did
not create" is not a finding there. That is gate `T1`, and it is answered by the product's
own claim about what it promises, not by a guess.

The second control: **caching and reflection**. A response that echoes your input is not
proof you reached anything. Re read the object with a separate authenticated request as the
owner and confirm the change persisted.

## Where else this shape appears

Every operation that takes a scope and an ID together: update, transfer, move, attach,
share, duplicate, export, invite, assign. Export is the most commonly missed, because it is
often written as a reporting feature rather than an object operation.

management system is course, cohort, enrolment and submission boundaries repeated a dozen
times, and nobody has reviewed it. See

## Recall question

Why is "I changed the ID and got someone else's data" not yet a finding, and what four facts
turn it into one?
