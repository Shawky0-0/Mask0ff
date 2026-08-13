---
tags: [security, flash, advisories, method, authentication, saml, xml, signatures, fail-open]
updated: 2026-08-13
sources:
  - "https://portswigger.net/research/the-fragile-lock, accessed 2026-08-13"
---

# MTH-WEB-008, the hash of nothing, or what a security function returns when it gives up

Related: the web advisories folder,
MTH-WEB-001, shared parser confusion,
WEBDS-0014, the authentication class this feeds.

## The technique in one line

Find the error path inside a security function where an exception is swallowed
and an empty value is used instead, then precompute the check's answer for that
empty value, because it is a constant and it is the same on every install on
earth.

## The discovery signal

Zakhar Fedotkin was not looking for a new bug. He and Gareth Heyes had already
broken `ruby-saml` in 2024 with XML signature wrapping through DTDs. When the
project patched that, he asked a different question: **did the patch remove the
vector or remove the cause.**

The answer was the vector. The library still ran two different XML parsers,
REXML and Nokogiri, over the same document, and two parsers over one document is
a disagreement waiting to be arranged. That is
MTH-WEB-007 used as a discovery
technique rather than as a review technique, and it is the same signal.

The specific find in this card came from reading the XML Signature specification's
own warning, quoted in the research, that relative URIs "will not be operational"
in canonical form. A specification saying a thing does not work is a specification
saying nobody tested what happens when somebody does it anyway.

## The mechanism

Signing an XML document is a three step job. Pick the element. Canonicalise it,
meaning rewrite it into one agreed byte for byte form so that harmless formatting
differences do not change the result. Hash those bytes and compare the hash
against the one in the signature.

libxml2 raises an exception when it meets a relative namespace URI, such as
`xmlns:ns="1"`. Most callers do not handle that exception in a way that stops the
process. They continue, and the canonicalisation output is missing, so the code
treats it as an empty string.

Hash an empty string with SHA-256 and you always get the same value:

```
47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
```

That is not a secret. It is a well known constant. So the attacker needs a
signature over a document whose digest is that constant, and they can obtain one
by finding any signed document from the same identity provider whose canonical
form is also void.

The research pairs this with two other parser tricks worth naming, because they
share one shape.

**Attribute pollution.** libxml2's `xmlGetProp()` ignores namespaces, so with
both `ID="1"` and `samlp:ID="2"` present it returns an unpredictable one. REXML
does the opposite. Signature verification therefore resolves one element and the
business logic resolves another.

**Namespace confusion.** REXML treats `xmlns` and `xml:` as ordinary attributes
rather than reserved declarations, so a nested redeclaration such as
`xml:xmlns='#anything'` hides a signature from REXML's `//ds:Signature` XPath
query while leaving it perfectly valid for Nokogiri.

The three combine into one workflow that is the actual lesson: **you do not need
to forge a signature, and you do not need to steal an assertion. You reuse a
signature the identity provider already published, over some other document, and
then make the verifier and the consumer disagree about what that signature
covers.** Identity provider metadata, signed error responses and federation
documents are all public sources of a genuine signature.

The transferable rule, and this is the part that outlives SAML:

**A security function that fails open does not fail randomly. It fails to a
constant, and a constant can be precomputed.**

## Which class it belongs to, and which stacks

Authentication, session, OAuth and JWT, corpus directory
`03-authentication-session-oauth-jwt/`. That class has one entry and is the
thinnest in the table with anything in it at all.

**It reaches Ahmed's stack conditionally, and the condition is worth checking
rather than assuming.** `php-saml` and Rob Richards' `xmlseclibs` are both named
as affected, and `xmlseclibs` is the library underneath most PHP SAML and single
sign on integrations, including the common Laravel packages. Fixed in
`xmlseclibs` 3.1.4, and `ruby-saml` before 1.18.0. Whether any YZH property does
SAML at all is `___` and is a question for the sit down, not something to guess
here. GitLab EE 17.8.4 was the live demonstration target, so a self hosted GitLab
would also be in scope.

Not vulnerable, per the research: the XMLSec library and Shibboleth's xmlsectool.

## A safe way to test for it

Reading and static inspection first, as always.

1. Identify whether SAML is in use at all, and which library. Metadata endpoints
   and error responses usually name the implementation.
2. From published metadata, note whether the identity provider signs documents
   other than assertions. Federation metadata fetched with `?sign=true`, and
   signed error responses, are the named sources of a reusable signature. Reading
   published metadata is reading.
3. Read the service provider's code if it is available. The question is whether
   one parser or two touch the document between verification and consumption. Two
   is the finding, before any request is sent.
4. Only in a lab, with an identity provider and service provider Ahmed owns,
   assemble the document and observe whether authentication succeeds. The canary
   is logging in as a seeded test account that the assertion was never issued for.

Fedotkin released a Burp extension that automates the discrepancy detection. It
was noted, not downloaded and not run. **Nothing found on a research page gets
executed on this sweep**, and a tool that generates authentication bypass attempts
is the last thing to make an exception for.

Steps 1 to 3 are reading. Step 4 is a request against a system and the Flash
lane's authorisation gate applies to it in full. Against anything Ahmed does not
own, stop at step 3 and report the architecture.

## The control that would catch a false positive

**The document must stay schema valid.** The research is explicit that XML Schema
validation does not stop this, because malicious elements go into legitimate
extension points, `Extensions` and `StatusDetail`. If your document fails schema
validation you have found a parser that is lenient, which is a different and
weaker finding.

**Confirm the signature genuinely verifies.** The whole point is that
verification succeeds. If the target accepts your document without checking any
signature, you have found a much simpler bug and should report that one instead,
because your explanation would otherwise be wrong.

**Show the divergence, not just the outcome.** The finding is that the
verification module and the business logic resolve different elements. Evidence
means demonstrating both: the signature covers element A, the login used element
B. A successful login on its own has too many other explanations.

**Check the version before writing.** `ruby-saml` 1.12.4 is patched against the
2024 research and still vulnerable to this. A version number that looks patched
is not a control.

## Where else this shape appears

**The fail open constant, which is the general idea.** Any comparison where one
side can be forced to a default. An empty digest, an empty signature that
compares equal to an empty expected value, a `null` returned by a lookup then
compared with `==`, a JWT with `alg: none`, an HMAC over a field the code failed
to read, a timing comparison against an empty secret. Ask of every security
check: what does this return when the thing it depends on throws.

**The parser pair.** Two libraries reading one document is the underlying defect
in all three attacks here, and it is the same mechanism as
MTH-WEB-001 and
MTH-WEB-002. The research names
siblings itself: `CVE-2025-23369` in GitHub Enterprise, exploiting libxml2's
internal caching; SAMLStorm in `xml-crypto` on Node, through comment handling
during canonicalisation; and Gareth Heyes's "Splitting the Email Atom", which is
the same disagreement in email address parsing.

**Verify then consume.** Anywhere a signature or permission is checked against
one representation of a thing and the work is done on another. Webhook signatures
verified over the raw body while the handler reads a reparsed JSON object.
Content checked before a redirect is followed. A file validated by one path and
opened by another, which is
WEBDS-0016 wearing different
clothes.

## Provenance

Zakhar Fedotkin, "The Fragile Lock: Novel Bypasses For SAML Authentication",
PortSwigger Research, published 2025-12-10 and updated 2026-01-21, presented at
Black Hat EU 2025. Read at `https://portswigger.net/research/the-fragile-lock`,
accessed 2026-08-13.

Disclosure timeline on the page: reported April to October 2025, `ruby-saml` and
`xmlseclibs` patched December 2025, and Okta declined in January 2026 to change
its signing behaviour, on the grounds that it follows the SAML standard. That
last point is the uncomfortable one: the identity provider is not doing anything
wrong, which is why the fix has to live in the service provider.

No text on the page was addressed to an automated reader. The Burp extension was
noted and not fetched or run.
