---
tags: [security, flash, advisories, method, wordpress, rest, access-control]
updated: 2026-08-16
sources:
  - "https://plugins.svn.wordpress.org/ai-engine/tags/3.6.5/labs/mcp-oauth.php, accessed 2026-08-16"
  - "https://plugins.svn.wordpress.org/ai-engine/tags/3.6.6/labs/mcp-oauth.php, accessed 2026-08-16"
  - "https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2026-15988, accessed 2026-08-16"
---

# MTH-WP-010: a routing decision made on a string the attacker can pad

## The technique in one line

Find code that decides **where a request is** by searching for a substring inside
`$_SERVER['REQUEST_URI']`, then find a way to make that substring appear somewhere harmless
in the URL (the query string is usually enough) so the decision fires on a route it was never
meant to cover.

## The discovery signal, what made anybody look there

INCIBE's reference list for CVE-2026-15988 named four line numbers in one file,
`labs/mcp-oauth.php`. That list is the signal, and it is the part of an advisory almost
everybody skips. It pointed straight at the function.

The reusable signal, for when nobody has handed you line numbers, is a **grep with a
proximity condition**: `$_SERVER['REQUEST_URI']` within a few lines of anything that touches
identity. A plugin has very few legitimate reasons to read the raw request URI at all, and
almost none to read it while deciding who the caller is.

The louder version of the same signal: **a plugin calling `wp_set_current_user()` or
`wp_validate_auth_cookie()` by hand.** Core does that. A plugin doing it is claiming it knows
better than core about who the user is, and that claim is worth reading carefully every time.

## The mechanism

Read the vulnerable function, from tag 3.6.5:

```php
public function reauth_for_authorize( $result ) {
  $uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
  if ( strpos( $uri, '/' . $this->namespace . '/oauth/authorize' ) === false ) {
    return $result;
  }
  if ( !is_user_logged_in() ) {
    $user_id = wp_validate_auth_cookie( '', 'logged_in' );
    if ( $user_id ) {
      wp_set_current_user( (int) $user_id );
    }
  }
  return $result;
}
```

registered as:

```php
add_filter( 'rest_authentication_errors', [ $this, 'reauth_for_authorize' ], 200 );
```

Two facts make this dangerous rather than merely sloppy.

**One: the hook is global.** `rest_authentication_errors` runs for **every** REST request the
site serves, not just this plugin's. So the substring test is the only thing standing between
this behaviour and the entire REST surface.

**Two: what it does when the test passes is exactly the protection it is bypassing.**
WordPress refuses a REST request that is authenticated by cookie alone with no valid
`_wpnonce`. That refusal is the reason a link on somebody else's website cannot act as you:
your browser will attach your cookie, but it cannot supply the nonce. This function takes the
cookie, validates it directly, and sets the current user, without ever asking for a nonce.

So the test is answering "should I turn off cross site request forgery protection", and it is
answering it by looking for a piece of text anywhere in an attacker written URL.

`strpos` does not know about paths. It knows about characters. `?x=/mwai/oauth/authorize`
contains the string just as truly as `/wp-json/mwai/oauth/authorize` does.

The fix, at 3.6.6, matches on `rest_route`, the value WordPress resolved after parsing, and
not on the raw text.

## Does it transfer to WordPress, and how

It is a WordPress bug in a WordPress specific place, and the reason it keeps happening is
worth naming: **there is no single obvious way to ask "what route am I on" early in the
request**, so developers reach for the URI, which is always available and always wrong.

WordPress serves REST under at least three shapes depending on permalink settings:
`/wp-json/<ns>/<route>`, `/?rest_route=/<ns>/<route>`, and rewritten variants. That is
precisely why anchoring the match is not a fix, only a narrowing: an attacker needs one shape
to work.

**The grep**, against a plugin tree:

```bash
grep -rn "REQUEST_URI" --include=*.php .
grep -rn -E "wp_set_current_user|wp_validate_auth_cookie" --include=*.php .
grep -rn -E "rest_authentication_errors|determine_current_user" --include=*.php .
```

Any hit from the second or third list is worth reading in full. A hit from the first that
sits near a hit from the second or third is the finding.

It transfers off WordPress unchanged. Any framework, any proxy, any WAF that makes an
allow or deny decision with `contains` rather than an equality test or an anchored, normalised
path match has the same defect.

## A safe way to test for it

Lab only, and the whole test is two requests that change nothing.

1. As a logged in administrator, in the browser, request a REST route that reports identity
   and nothing more, with **no nonce**: `/wp-json/wp/v2/users/me`. It must be refused, with
   `rest_not_logged_in` or similar. **This is the control and it runs first.**
2. Send the same request with the marker appended to the query string:
   `/wp-json/wp/v2/users/me?probe=/<namespace>/oauth/authorize`, still with no nonce.

If request 1 is refused and request 2 returns the administrator's own user object, the
authentication bypass is proved. Nothing was created, changed or deleted, and the only data
read is the tester's own account.

Read the real namespace off the installed build first. It comes from `$this->namespace` and
was not verified this run.

**Stop there.** Turning this into a working account creation means chaining it with the
method override and a state changing route, which is exploitation. The primitive is the
finding.

## The control that catches a false positive

**Request 1 is the control, and running it second would ruin the test.** If the unmarked
request also succeeds, then the site is not enforcing REST nonces for some unrelated reason,
your marked request proved nothing, and the honest conclusion is "inconclusive".

**The routing control.** Put the marker in the query string, not in the path. In the path it
changes which route WordPress resolves, and you get a 404 from a request that never reached
the filter. A 404 is not a finding, and reading one as a negative result is how this test gets
called clean when it is not.

**The plugin control.** Repeat both requests with the plugin deactivated. Both must be
refused. This separates the plugin from the site's own configuration, and it is the step that
turns "this site behaves oddly" into "this plugin causes it".

**The version control.** Repeat both against the patched build. Both must be refused.

## Where else this shape appears

* **Nonce exemption lists.** `if ( strpos( $uri, 'admin-ajax' ) !== false ) { skip_nonce(); }`
  is the same bug with a shorter fuse.
* **Firewall and WAF path rules**, where an allow rule written with `contains` can be
  satisfied by putting the allowed path in a parameter.
* **`is_admin()` substitutes.** Plugins that decide "this is an admin screen" by looking for
  `/wp-admin/` in the URI, and then relax something.
* **Cache exclusion rules**, where a page is served from cache or not based on a URI
  substring. Getting this wrong the other way round produces cache poisoning rather than
  authentication bypass, which is the ground Rachid Allam (`zhero_`) works on and which is
  already on the watchlist.
* **The safe version, in the same file.** `handle_host_root_wellknown()` in this very plugin
  reads `REQUEST_URI` too, but tests `strpos( $path, '/.well-known/' ) !== 0`, anchored at
  position zero, after stripping the query string with `strtok`. **One author wrote both the
  safe and the unsafe version, ten lines apart.** That is the most useful thing on this card:
  the presence of a correct check elsewhere in a file is not evidence that the checks in it
  are correct.

## The general rule worth carrying

**When a check and a transformation sit next to each other, the order and the input are
security decisions.** Here the input is wrong: the code was handed a resolved route by the
framework and chose to read raw text instead.
MTH-WP-009 is the same lesson where the *order* is
wrong instead.

Related: WPDS-0011 is the entry this came from.
</content>
