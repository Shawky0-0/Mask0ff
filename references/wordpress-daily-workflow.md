# WordPress daily workflow

Use this only for a WordPress target in the user's current authorized scope:
an owned local lab, clone, staging site, or production engagement with written
scope. Do not permanently bind this workflow to an earlier target. When the
user changes target, access, or allowed actions, record the revised scope and
work under those current boundaries.

## 1. Start state

Record target, work mode, assessment mode, account role, test data, prohibited
actions, rate limit, snapshot or restore point, and stop line. Use a separate
engagement-map folder for reconnaissance and a separate finding bundle for each
candidate.

## 2. Engagement map

Use safe reads first. Record only non-secret facts:

- WordPress core version and web root
- active, inactive, and must-use plugins; themes; update state
- user roles and test accounts
- ownership and write scope for code and `wp-content/uploads`
- PHP handler, Apache or Nginx rules, and directory-index behavior
- public routes: home, login, REST, XML-RPC, uploads, readme, custom plugin
  endpoints, and only explicitly scoped APIs
- relevant access and error-log lines

Classify every result as one of:

- `normal observation`: expected behavior, no candidate
- `exposure`: a fact that may matter only with another condition
- `candidate`: observed boundary failure worth one hypothesis
- `refuted`: a safe test or control disproved the hypothesis
- `finding`: evidence gates support a bounded security impact

## 3. Candidate choice

Prefer the signal with a direct trust-boundary question. Examples:

- upload directory lists files or permits PHP execution
- lower role reaches an Administrator-only action
- custom route lacks nonce, capability, ownership, or input validation
- plugin version is known vulnerable and reachable
- XML-RPC or REST behavior violates documented scope or role boundaries
- backup, configuration, or source artifact is publicly served

Do not create a finding merely because a default endpoint exists, a product
version is visible, or a plugin is inactive.

## 4. One-candidate loop

1. Write H1 with actor, input, missing decision, boundary, and predicted result.
2. Capture B1 normal behavior using synthetic data.
3. Run P1 with minimum safe proof. Prefer one harmless marker, one owned
   object, or one request.
4. Run C1 with a distinct negative, wrong-role, patched, or differential
   control.
5. Restore clean state and repeat once for R1 only if P1 passed.
6. Bound I1 to demonstrated impact. Do not infer root or server takeover from
   a parser error or exposed endpoint.
7. Assess. If refuted, stop this entry point and return to engagement map.

## 5. Daily handoff

End every session with:

```text
Scope and mode:
Target and role:
Snapshot or restore status:
Completed map or finding bundle:
Verified finding / refuted hypothesis:
Evidence IDs:
Current state and confidence:
Next exact safe action:
Stop line:
```

## 6. WordPress-specific stop lines

Stop before real credential attacks, account takeover, bulk enumeration,
malware, persistent shells, mass content changes, third-party data access,
destructive database writes, or service disruption. On a company clone, stop
before sending email, webhooks, payment actions, or production-bound
integrations.
