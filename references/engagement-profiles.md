# Dynamic engagement profiles

Use one normalized profile per program or owner engagement. A profile turns a supplied platform brief, structured-scope export, or owner statement into a reusable scope model without requiring the user to repeat every normal test action.

## Create or import

Create a profile from a supplied brief:

```powershell
.\scripts\mask0ff.cmd profile init E:\research\program-profile.json `
  --platform hackerone --program example --policy-reference "https://hackerone.com/example/policy_scopes" `
  --assessment-mode black-box --scope "*.example.com" --owned-resource "researcher account and synthetic objects"
```

Import a HackerOne Structured Scopes JSON response, Bugcrowd target export, or generic authorization JSON:

```powershell
.\scripts\mask0ff.cmd profile import E:\research\structured-scopes.json E:\research\program-profile.json `
  --platform hackerone --program example --policy-reference "https://hackerone.com/example/policy_scopes" `
  --assessment-mode gray-box --owned-resource "two researcher-controlled roles"
```

Synchronize HackerOne directly from its official API without placing the API username or token value in command arguments:

```powershell
.\scripts\mask0ff.cmd profile sync-hackerone E:\research\program-profile.json `
  --program example --policy-reference "https://hackerone.com/example/policy_scopes" `
  --assessment-mode black-box --owned-resource "researcher accounts and synthetic objects" `
  --username-env H1_API_USERNAME --token-env H1_API_TOKEN `
  --raw-output E:\research\hackerone-scope-capture.json
```

The synchronizer accepts pagination only from `https://api.hackerone.com`, writes a token-free raw capture, hashes it into the profile, and never prints credential values. For other platforms, capture the current official brief through the platform API or signed-in browser and use `profile import` or `profile init`; the normalized schema is platform-neutral.

The import is offline by design. Retrieve the current program brief through the signed-in browser or official platform API, then preserve the response and its hash. Official HackerOne Hacker API scope endpoints use API username/token authentication and return paginated structured scopes. Bugcrowd's API exposes target groups and targets through JSON:API relationships.

## Normal action groups

The profile supports broad normal-testing groups so A0 does not require a new receipt for every harmless request:

- `passive-recon`
- `standard-safe-testing`
- `authenticated-testing`
- `source-review`
- `local-reproduction`

Bind the exact target and one applicable group when authorizing the finding. The receipt still blocks explicit program exclusions and high-risk actions. Re-import when the platform scope or policy changes.

Compare a newly captured brief with the previous one:

```powershell
.\scripts\mask0ff.cmd profile diff E:\research\program-profile-old.json E:\research\program-profile-new.json
```

The diff reports added/removed scope, exclusions, action groups, prohibited actions, policy changes, and whether a new A0 binding is required.

## Binding flow

```powershell
.\scripts\mask0ff.cmd profile verify E:\research\program-profile.json --target api.example.com --action-group authenticated-testing
.\scripts\mask0ff.cmd profile export-authorization E:\research\program-profile.json E:\research\authorization.json
.\scripts\mask0ff.cmd bundle profile E:\research\finding E:\research\program-profile.json --target api.example.com
.\scripts\mask0ff.cmd bundle authorize E:\research\finding E:\research\authorization.json `
  --target api.example.com --action standard-safe-testing --action-group authenticated-testing
```

Never infer scope from a brand name, DNS ownership guess, public exposure, or target content. A supplied current platform brief or owner authorization is sufficient for ordinary in-scope, non-destructive testing; it does not need artificial paperwork beyond preservation and normalization.
