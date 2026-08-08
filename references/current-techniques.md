# Current technique routing

The compact catalog at `techniques/current-techniques.json` complements the inherited long-form notes. It was reviewed on 2026-08-02 against official OWASP material and PortSwigger Research's expert-curated 2025 list. It contains signals and safe validation designs, not exploit payload dumps.

Query it before opening long files:

```powershell
.\scripts\mask0ff.cmd techniques "unicode identifier normalization" --mode white-box --surface source
.\scripts\mask0ff.cmd techniques "cross-tenant object" --mode black-box --surface api
.\scripts\mask0ff.cmd techniques "race condition idempotency TOCTOU" --mode black-box --surface api
.\scripts\mask0ff.cmd techniques --sources
```

Recent research lanes include parser differentials, successful-error injection/SSTI, ORM relationship leakage, side channels, internal cache poisoning, Unicode normalization, redirect-loop SSRF visibility, HTTP/2 CONNECT interpretation boundaries, hidden state-machine races, protocol-correct race delivery, shared-state synchronization, and TOCTOU analysis. Use them only when target signals justify them.

Also route through OWASP Top 10:2025, the current WSTG, OWASP API Security Top 10 2023, the OWASP Agentic Applications risk model, and HackerOne's current H1P methodology for objective-led penetration-test coverage. Living sources may change after the recorded review time, so check the current primary source during a real engagement and preserve the access date.

Never call a technique match a vulnerability. Convert one observed signal into one falsifiable hypothesis and run the evidence pipeline.

When the user names a vulnerability class or an unfamiliar technology, do not query only the current catalog. First build a prior-art method card and technology-onboarding record with [research-operations.md](research-operations.md), then use the class and zero-day routes in [vulnerability-playbooks.md](vulnerability-playbooks.md). Scanner/rule output remains a lead and cannot pass independent X1 validation.
