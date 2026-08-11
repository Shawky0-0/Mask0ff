# Threat-model assessment

The most common reason a technically correct report is closed as `Informative` is not bad evidence — it is a mismatch with the vendor's threat model. This reference exists to prevent that: assess security significance before submission, using the vendor's own statements as prior art.

## The five questions

Answer all five from evidence. Failure on any question means the finding is `not-reportable` even when reproduction is perfect.

1. **Attacker control** — Name the actor and the source they control. If the only actors are the application operator, the developer, or the system itself, there is no adversary. Explicit disclaimers in your own report ("no attacker-controlled destination", "working as designed") are fail signals, not safety caveats.
2. **Cross-principal boundary** — The boundary must separate different trust principals: user vs user, tenant vs tenant, app vs model, host vs host, unauthenticated vs authenticated. If the "attacker" and the affected capability share a principal (an App and the server that implements its tools; an operator and their own config), no security boundary is crossed.
3. **Demonstrable impact** — The impact must be observable: command output, unauthorized response, file contents, state delta. "Could potentially", "may include", "in a realistic case" is speculative impact and fails.
4. **Contrary to documented design** — Find the vendor's documentation of the behavior. If the behavior is documented, intentional, or a stated trade-off ("admin may pre-approve", "not a security boundary"), it is working-as-designed, not a vulnerability. Surprising design is not a bug.
5. **Vendor threat model** — Collect the vendor's own scope statements before testing: security page, product docs, HackerOne/Bugcrowd program policy, previous triage decisions (public or from prior engagements), accepted report classes. Rank your hypothesis against this prior art, the same way D1 ranks against CVE prior art.

## Prior-art sources for threat models

- Program policy page and FAQ (explicit in-scope/out-of-scope classes and "not a vulnerability" examples).
- Vendor security documentation and architecture pages (what they call a "security boundary").
- Public triage decisions: "informative" closures, acknowledgment threads, changelogs describing security model changes.
- The product's own stated threat model (cloud trust model, extension/app model, SDK threat model).
- Prior reports in the same class on the same product and adjacent products.
- Your own outcome ledger: `outcome search --program <vendor>` returns every recorded triage decision for that vendor, and `outcome stats` gives the empirical acceptance rate per class.

Record what you found with dates and URLs in the evidence bundle before active testing of the class.

## Program threat-model profile

Persist the research as `program-threat-model.json` (template in `assets/evidence-bundle/`):

- `security_boundary_classes`: what this vendor treats as a defended boundary (cross-tenant access, arbitrary-recipient sends, cross-principal tool invocation).
- `excluded_classes`: classes this vendor consistently rejects (functional correctness, UI visibility metadata, operator config not preserved, approval policy for non-arbitrary recipients).
- `documented_design_behaviors`: exact behaviors the vendor calls working-as-designed, with the documentation reference (your Informative reports are the best source).
- `prior_triage_decisions`: report id, class, verdict, and reason for every recorded outcome.
- `accepted_classes`: classes with historical bounty acceptance.
- `consent_semantics`: which admin configuration is intentionally loosenable (managed toolPolicy allow rules, admin pre-approval, etc.).

Check a claimed class against the profile before deep validation:

```powershell
.\scripts\mask0ff.cmd profile threat-model E:\research\program-threat-model.json --class-name "mcp-tool-authorization"
```

The result is `likely-informative` (excluded, documented design, or previously rejected), `likely-accepted` (historical acceptance), or `unknown` (research the vendor threat model first). `triage --threat-model` applies the same model to a report automatically.

## Red flags in a candidate finding

- The report's own prose disclaims attacker control or a security boundary.
- The "impact" section is written in hedged language with no observable effect.
- The behavior is the documented purpose of the feature.
- The boundary is between a component and itself (or a component and the content it authored).
- The affected principal and the acting principal are identical.
- The failure requires the victim to misconfigure, and the vendor documents the behavior.
- The consequence is delivered to a principal the vendor documents as an intended recipient (organizer, attendees).

## Decision

Apply before D1/Q1: run the five questions; on failure, mark the hypothesis refuted or not-reportable and preserve the analysis. Do not convert a rejected-class finding into a higher-severity narrative to make it pass — that is gaming, not research.
