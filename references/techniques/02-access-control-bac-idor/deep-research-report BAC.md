# Authentication & Session Management Flaws

Modern applications often use complex authentication systems (OAuth/OIDC, SAML, JWTs, magic‐links, 2FA, etc.), and even subtle misconfigurations can lead to high-impact account takeovers. Below we cover real-world patterns observed in bug bounty disclosures and research.

## OAuth/OIDC and Social Login Misconfigurations

**Vulnerability:** Improper OAuth/OIDC or social-login integration allowing account takeover.  
**Example:** An attacker uses one signup method to hijack the flow of another. For instance, Aswin K. V. discovered a site where Google OAuth **did not check for existing accounts by email**. The attacker first created an account with the victim’s email via normal signup; when the victim later logged in via Google OAuth with that email, the application merged them into the attacker’s session【24†L62-L70】. In short, the attacker “pre-registered” the victim’s email. Now the attacker could log in using the victim’s credentials or OAuth token, achieving account takeover. Aswin noted this as a **pre-account takeover**: “someone can register using the unregistered victim’s account… verification process is bypassed and the attacker can log in”【24†L62-L70】. 

**Root Cause:** The backend failed to enforce *unique account linkage*. When handling an OAuth login callback, the system didn’t check “does this email already belong to another user?” before logging in. This allowed two separate auth flows to collide. 

**Attack Scenario:**  
- *Victim (Account A):* No prior account, will attempt to log in via Google OAuth.  
- *Attacker (Account B):* Signs up with the victim’s email via normal email-password. Now Account B owns victim@gmail.com.  
- *Exploitation:* Victim logs in with Google OAuth (as if using `victim@gmail.com`). Because the site doesn’t check existing accounts, it ends up logging Victim *into Account B*. Meanwhile, Attacker has chosen the password for Account B. The attacker can now access the “victim” account at will.  

**Impact:** Full account takeover without knowing the victim’s credentials (just an email). This was deemed **high severity**【24†L62-L70】. Attack can steal PII, perform transactions, etc. 

**Detection Difficulty:** Hard to find by static analysis. Only by testing the OAuth flow against pre-existing accounts or looking at merged sessions. Scanners usually miss logic issues like “duplicate email check on OAuth.”

**Real-World Cases:** The above is from a Bugcrowd program writeup【24†L62-L70】. PortSwigger’s blog also documented similar OAuth account-takeover bugs (e.g. “OAuth standard exploited for account takeover”【24†L62-L70】).

## Magic Link & Password Reset Abuse

**Vulnerability:** Insecure “magic link” or password-reset implementations can leak tokens to attackers.

- **Magic Link Interception:**  In one case, a magic-login email contained a callback URL that could be altered. The researcher intercepted the “Send Magic Link” response, modified the redirect URL to point to an attacker-controlled domain, and waited for the victim to click. When the victim clicked the compromised link, the login token was sent to the attacker’s server, enabling a 1-click takeover【13†L58-L66】【13†L68-L75】.  In their words, altering the URL parameter in the magic link “allow[s] attackers to steer victims to a malicious page… the token will be transmitted to the attacker’s server”【13†L58-L66】【13†L68-L75】.  

  - *Attack Flow (Magic Link ATO):*  
    1. Victim requests magic link to email “alice@example.com”.  
    2. Attacker intercepts the HTTP POST for sending magic link. They drop it and craft a new one:  
       ```http
       POST /auth/send-magic-link
       Host: app.example.com
       Content-Type: application/json

       { "email": "alice@example.com", "redirect": "https://attacker.com/callback" }
       ```  
    3. Victim clicks the email link, but it points to attacker.com. The victim’s valid login token is sent to attacker.com.  
    4. Attacker uses that token to authenticate as Alice.  

  **Impact:** Full account takeover (no password needed). This was shown by Elcapitano’s writeup as “1-click ATO via Forget Password”【13†L58-L66】【13†L68-L75】.

- **Password Reset Token Exposure:** In another case, the password-reset flow **returned the reset token in the API response** instead of only emailing it. Medusa observed that after submitting the forgot-password form, the JSON response contained a plaintext `reset_token` for the user【17†L98-L107】. The attacker simply triggered reset for `victim@example.com` and immediately saw the token in the response:

   ```http
   POST /api/reset-password-request
   Content-Type: application/json

   { "email": "victim@example.com" }
   ```
   **Response (leaked token):**
   ```json
   {
     "status": "ok",
     "reset_token": "8dd88d54...",
     "message": "Reset link sent"
   }
   ```
   With that token, the attacker crafted the password-reset URL (`https://www.example.com/Account-SetNewPassword?token=8dd88d54...`) and reset the victim’s password【17†L98-L107】【17†L121-L124】. This bypasses email entirely. Medusa reported it as a **full account takeover flaw**: *“the reset token was exposed directly in the API response… attacker could take over any account”*【17†L98-L107】.

  **Root Cause:** Sensitive tokens were disclosed to the client. In a secure design, password reset tokens should only be sent via email, not returned in API output. 

  **Real-World Cases:** The above example is from an August 2025 bug bounty writeup【17†L98-L107】. Similar flaws have appeared in other programs: e.g., leaked password-reset tokens or PIN codes via forgotten-password APIs.

## Multi-Factor Authentication (MFA) Bypasses

**Vulnerability:** Improper handling of 2FA/OTP can allow bypass. In a notable case, Mohsin Khan found that the JWT token used during login was **issued before OTP verification**【15†L67-L75】. He observed:

```http
POST /api/verify-otp HTTP/1.1  
Host: redacted.com  
Content-Type: application/json  
Authorization: Bearer eyJhbGci...<JWT>...
{ "otp": "123456" }
```

He dropped the OTP request entirely. Because the server had already included a JWT for the session in that request (even though OTP wasn’t validated), simply replaying the JWT allowed full access to all endpoints【15†L67-L75】【15†L95-L100】. In Mohsin’s words, “the JWT token in the Authorization header was the key… I hypothesized that the token might still be valid” and indeed *“I gained access to all API endpoints without completing the OTP verification”*【15†L67-L75】【15†L95-L100】. 

**Attack Scenario:**  
- Victim logs in with correct password, system presents OTP prompt.  
- Attacker captures or predicts the JWT (maybe from initial login response). If the JWT is valid prior to OTP, attacker can use it. In this case, by dropping the verify-OTP request, Mohsin retained a valid token and bypassed OTP.  
- After fix, he still found a single endpoint (`GET /payment/order/transaction`) that did not check OTP. By directly forcing the browser to that URL (bypassing the OTP page), he accessed a protected payment function without OTP【15†L118-L122】【15†L129-L134】. 

**Impact:** Full bypass of 2FA, leading to account compromise and access to sensitive actions (payments, data). The researcher earned a $6k bounty for this chain【15†L118-L122】【15†L129-L134】.

**Common Mistake:** Generating or returning authenticated tokens (session cookie or JWT) **before** completing all auth steps. All endpoints must independently verify 2FA state.

## Single Sign-On (SSO) and Session Confusion

**Vulnerability:** Flawed SSO/session handling across domains can short-circuit verification. Tinopreter reported an SSO issue between a main financial app and a sub-domain forum【19†L118-L127】. The flow was: after entering username/password on the main app, the user was sent to OTP verification (`/v2/verify-blah`). The attacker **opened the forum site in another tab before completing OTP**. The forum used the same session cookie (SSO) and saw the initial session token as valid, logging the user in on the forum *without* OTP. In other words, the initial session (pre-OTP) was enough for the forum. As Tinopreter explains: *“I was fully authenticated. Mind you, I hadn’t verified the OTP on the main app… if I haven’t bypassed the OTP verification page… I shouldn’t have access to the forum”*【19†L118-L127】.

Because the forum allowed access with just the pre-OTP token, the attacker then accessed sensitive forum features (downloading logs of the victim’s account data, IPs, tokens, etc.). The writeup notes the root cause: “the main app assigned an initial session token upon valid username:password, and this initial token was enough to get access to the forum”【19†L131-L139】.

**Impact:** Even without full login on main app, attacker leverages shared session to gain authenticated access on a “less critical” SSO app (forum). This violated expected multi-factor logic and allowed data exfiltration. Tinopreter considered it worth at least $150【19†L118-L127】【19†L131-L139】.

**Prevention:** Ensure that all SSO-connected subdomains enforce the same auth state (e.g. OTP complete) before granting access.

## Token and Session Mismanagement

Beyond the above, many auth flaws stem from tokens/cookies:

- **Session Fixation:** Rarely publicized, but one might exploit if an attacker sets a victim’s session ID ahead of login and the server doesn’t regenerate a new one after auth.  
- **JWT Role/Scope Misuse:** If a JWT includes roles/scopes and the server fails to validate them properly, an attacker can craft tokens (if signing key known) or replay tokens for unauthorized endpoints (as in the 2FA case above【15†L67-L75】).  
- **Mobile/MFA-specific:** Mobile apps may embed secrets or use custom schemes. Attackers often intercept mobile app OAuth flows (deep link redirection, PKCE bypasses, etc.).

These were all recurring themes in bug bounties: token issuance at wrong time, leakage in logs or API, and trusting client-supplied tokens without server-side checks.

# Broken Access Control & Authorization Flaws

Once authenticated, many vulnerabilities arise from improperly enforced permissions. We summarize common real-world patterns and examples:

## Insecure Direct Object References (IDOR / BOLA)

**Vulnerability:** Objects (user data, resources) referenced by predictable IDs without verifying ownership.  

**Example:** In a well-documented case, a researcher found that changing an ID in an API request gave access to another user’s data. In jedus0r’s writeup, he discovered endpoints like:

```http
PUT /api/v1/cms/405 HTTP/2
...
```
When he changed the ID from his own `405` to another `419`, the request returned `HTTP 200 OK`【9†L143-L151】 – meaning he could update/delete that CMS record even though it belonged to someone else. He then tried `DELETE /api/v1/cms/419` and succeeded in deleting it【9†L166-L173】. Remarkably, he escalated further: by sending `DELETE /api/v1/users/19782` (another user’s ID), he deleted that user account【9†L229-L236】. His final note: *“we have deleted the user… we can do it for all users… so yes it’s critical”*【9†L229-L236】. 

**Attack Flow:**  
1. Attacker intercepts a request, e.g. `PUT /api/v1/cms/405`.  
2. Switches the object ID: `PUT /api/v1/cms/419`.  
3. Receives 200 OK, proving no ownership check【9†L143-L151】.  
4. Performs DELETE likewise: `DELETE /api/v1/cms/419` (success)【9†L164-L173】.  
5. Similarly, attacker tries `DELETE /api/v1/users/19782` and removes a user【9†L229-L236】.  

**Impact:** Data exposure or destructive actions on any user’s account/resources. jedus0r’s IDOR was rated P1 since he could delete all users and steal their data【9†L229-L236】.

**Root Cause:** The server simply used numeric IDs from the request to locate objects, *without verifying that the requesting user “owns” that object*.  

**Detection:** Often found by fuzzing IDs or using tools like Burp Intruder / Repeater to test ID parameter changes. Automated scanners may not try destructive verbs (PUT/DELETE) or may need guidance on ID fields.

## GraphQL Field/Query-Level Authorization Bypass

**Vulnerability:** Incorrect permission checks in GraphQL can leak data not visible via the frontend. Unlike REST, GraphQL lets clients specify exactly which fields to fetch. If certain queries or fields aren’t properly restricted, attackers can discover hidden data.

**Example:** Tinopreter reported a GraphQL access flaw in a SaaS platform. Low-privilege users were not allowed to retrieve private “webhooks” for projects they weren’t in, via the normal query `GetProjectWebhooks(projectId: X)`. That returned a “permission denied” error as expected. However, a global query `GetOrgWebhooks` (intended for admins) returned *all* webhooks, including those for other projects, without checking the user’s project membership【21†L160-L169】. In other words, by changing the root query, the same data became accessible. From the writeup: 

> The API blocks a direct query to the project, but it fails to verify permissions when that same project is accessed through the organization parent… *“By pivoting through the organization object, a restricted user can reach the exact same data that was previously forbidden.”*【21†L160-L169】.

In practice, the attacker performed:
```graphql
query {
  organization(id: "ORG123") {
    webhooks {
      id
      url
      project { id name }
    }
  }
}
```
This returned webhooks for all projects under the organization, including private ones that the user should not see. They could even see owner emails and other PII via associated fields【21†L129-L138】【21†L160-L169】.

**Root Cause:** Inconsistent permission logic. The GraphQL schema allowed “escalation”: checking permissions differently on the `Organization` resolver vs. the `Project` resolver. The direct project query enforced ownership, but the org-level query did not.

**Impact:** Sensitive data leakage (PII, secret URLs, etc.) across role boundaries. Tinopreter earned \$1,500 for this PII leakage. It’s a form of IDOR in GraphQL. 

**Prevention:** Ensure *every* GraphQL query resolves with proper ACL checks, not only at top-level. Limit queries and enforce field-level restrictions.

## Function-Level and RBAC Failures

**Vulnerability:** Missing role or action checks on functions/endpoints. Even if data access is correct, endpoints (like “/admin/delete-user”) may be unprotected.

**Example:** A classic case is an admin-only endpoint not checking the user’s role. For instance, attackers have reported being able to call `/admin/tools/export-all-users` simply by knowing the URL, because no server-side check existed. While we don’t have a specific reference here, in many bug bounties this is called *“Missing Function Level Access Control”*. 

**Detection:** Try authenticated requests to admin-only-looking endpoints with a low-privilege session. Also test changing methods (POST vs GET), or brute-forcing common admin paths.

## Cross-Tenant and Multi-Tenancy Issues

**Vulnerability:** Multi-tenant SaaS apps sometimes fail to isolate tenant contexts. For example, Team/Workspace IDORs or using one org’s ID in another’s context.

**Example:** (General) If URL or request contains a tenant ID (e.g. `tenant=XYZ` or `workspace=123`), altering it can leak data to a wrong tenant. Attackers also find cases where global APIs (like org-wide reports) accidentally include data from other tenants. 

**Prevention:** Always authenticate+authorize including tenant membership. Separate session or token domains per tenant if needed.

## Miscellaneous Flaws

- **Forced Browsing:** Unlinked admin/debug pages (e.g. `/admin/console`, `/debug`) sometimes accessible.  
- **Internal API Exposure:** Multi-service apps might have hidden endpoints (e.g. `/internal/*`) exposed to the web.  
- **Workflow/State Bypass:** Similar to the SSO example, applications with multi-step states (checkout, order processing, enrollment) sometimes allow skipping steps. Attackers check if skipping a status check still lets them perform an action.  
- **Cache or CDN Issues:** Rarely, cached responses might serve sensitive data (e.g. admin page cached for normal user). Not covered by references here.

## Common Themes and Takeaways

From dozens of real reports, recurring patterns emerge:
- **Never trust client input.** Always verify object ownership, user role, and expected state on the server.  
- **Token Timing:** Ensure tokens (JWTs, sessions) are issued only after full authentication. Treat any token as granting “logged in” access.  
- **API Endpoints:** Each endpoint must do its own auth check. Don’t rely solely on UI logic. If an endpoint isn’t exposed in the front-end, still test it directly.  
- **Pattern Recognition:** Attackers often pivot: break a high-level check (like OTP), or try alternate query paths (GraphQL), or combine auth flows. Always test “what if I skip this step?”  

By studying reported cases, a robust pentester will compile checks for each of the above categories. The examples cited here come from real bug bounty writeups and showcase the practical exploit flows【24†L62-L70】【9†L143-L151】【13†L58-L66】【15†L67-L75】【17†L98-L107】【19†L118-L127】【21†L160-L169】. Each pattern should be tested systematically in a black-box audit. 

