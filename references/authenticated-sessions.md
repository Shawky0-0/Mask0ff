# Authenticated sessions and secrets

Do not refuse an authorized target merely because registration, login, a password, an API token, a cookie, OAuth, a client certificate, or an already signed-in browser session is required.

## Secret handling

Accept user-provided researcher credentials for an in-scope target, then:

1. Treat them as secrets immediately; do not quote, summarize, or repeat their values.
2. Prefer an already signed-in browser session or a product-provided secret input channel.
3. Otherwise reference environment-variable names in a session profile. Never put the value in command arguments, JSON, Markdown, evidence logs, reports, shell history, source control, or agent memory files.
4. Use the credential only for the recorded target, role, tenant, and session purpose.
5. Redact Authorization headers, cookies, API keys, passwords, signed URLs, and private keys from derived evidence.
6. Preserve a raw trace only when the engagement's data-handling rules allow it; never attach the raw secret-bearing trace to a report.

If a user pastes a secret into chat, continue the authorized task without moralizing. Avoid repeating it, recommend rotation after the engagement if chat is not an approved secret channel, and move to a reference-only session profile.

## Session profiles

Create a reference that stores environment-variable names, not values:

```powershell
.\scripts\mask0ff.cmd session init E:\research\member-session.json `
  --label member-a --base-url https://app.example.com --role member --tenant tenant-a `
  --auth-type password --username-env MASK0FF_USER_A --secret-env MASK0FF_PASS_A

.\scripts\mask0ff.cmd session verify E:\research\member-session.json --check-environment
.\scripts\mask0ff.cmd bundle session E:\research\finding E:\research\member-session.json
```

For browser-based testing, use `--auth-type browser-session --browser-profile signed-in-member-a`. The profile is safe to preserve because it contains only labels and references.

Use two controlled principals when authorization or workflow behavior depends on role, tenant, ownership, invitation state, or account lifecycle. Use a fresh session for repeat runs and record which profile produced each artifact.
