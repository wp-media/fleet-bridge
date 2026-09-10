# fleet-bridge

Lets a WordPress plugin accept commands from **Fleet**, verified.

## What Fleet is, and why a plugin needs this

Fleet is a WP Media application where an agency manages a plugin across every
site on its licence from one dashboard. Today they open one wp-admin per site.

To read or change a setting, Fleet has to reach the site — and it deliberately
holds **no customer credential**: no WordPress login, no application password,
not even the licence key. An application password would be the easy route and
the wrong one. It authenticates a *user*, so it grants whatever that user can
do rather than "this plugin's allowlisted options", and Fleet would have to
store one secret per site — tens of thousands of secrets whose leak is a
total compromise of every one of them.

So Fleet signs a short-lived token per request, and this package checks it.

## Two proofs, from two parties

Every request must carry both:

| Credential | Header | Signed by | Proves |
|---|---|---|---|
| **command** | `Authorization: Bearer` | Fleet | who is asking, and covers the exact body bytes |
| **consent grant** | your choice | the licence vendor | the owner allows this capability on this site, right now |

Neither substitutes for the other, and the reasons are worth understanding
before changing anything here.

**Fleet must not sign the consent.** It is the party being granted the access.
A grantee attesting its own grant proves nothing at all.

**The consent must not be cached.** An install that remembers "allowed" for a
day keeps accepting commands for a day after the owner withdraws it — and a
permission that takes a day to withdraw is not a permission, it is a delay. So
it arrives *with* each command, minted seconds earlier, and revocation is
immediate.

What *is* safe to cache for a long time is a **key set location**, because a
rotation publishes two keys at once for exactly that reason. That is why the
vendor tells an install where the keys are, not whether it is allowed.

## What it deliberately cannot tell you

**Which of Fleet's own customers asked.** There is no per-site secret shared
with Fleet, so there is nothing to check that against. Isolation between
Fleet's customers is enforced in Fleet, before anything leaves it.

This package verifies that a command is Fleet's, that it names *this* site, and
that the owner allows it. That is the whole of it, and the boundary is
deliberate rather than an omission.

## Using it

```php
use WPMedia\FleetBridge\Bridge;
use WPMedia\FleetBridge\Config;
use WPMedia\FleetBridge\Contract\TrustStore;
use WPMedia\FleetBridge\Exception\NotAuthorised;
use WPMedia\FleetBridge\WordPress\HttpKeySets;
use WPMedia\FleetBridge\WordPress\SystemClock;
use WPMedia\FleetBridge\WordPress\WpdbNonceStore;

$bridge = new Bridge(
    $yourTrustStore,                              // you implement this
    new HttpKeySets(),
    new WpdbNonceStore(),
    new Config( wp_parse_url( home_url(), PHP_URL_HOST ) ),
    new SystemClock()
);

try {
    $bridge->verifyCommand( $request->get_header( 'authorization' ), $request->get_body() );
    $bridge->verifyGrant( $request->get_header( 'x-your-consent-header' ), 'settings:write' );
} catch ( NotAuthorised $refused ) {
    // The reason is for your log. The caller gets Bridge::REFUSED and nothing
    // else — see "One fixed refusal" below.
    error_log( '[fleet] ' . $refused->getMessage() );

    return new WP_Error( 'not_authorised', Bridge::REFUSED, [ 'status' => 401 ] );
}
```

**Type your route against `Contract\Verifier`, not against `Bridge`.** `Bridge`
is `final` — verification is security critical, and a subclass overriding half
a check is a hole that looks like a customisation — which means a route holding
the concrete class cannot be doubled, and the only way left to test the route's
own refusals is to sign real tokens in your suite. That tests this package
again, not your route.

The only thing you must write is a `TrustStore`, because where trust comes from
is your business:

```php
final class MyTrustStore implements TrustStore {
    public function issuer( string $role ): string {
        // From wherever your plugin already talks to its vendor.
        return $role === self::COMMAND ? $this->fleetIssuer() : $this->vendorIssuer();
    }

    public function keySetUrl( string $role ): string { /* … */ }
}
```

**Empty means trust nobody, never trust anybody.** An install that has not yet
polled its vendor is expected to answer empty and refuse everything.

## Design notes worth reading before you change it

**The host's site identity is port free.** `Config` takes a host, and both sides
derive the subject from it. A port in one and not the other is a refusal that
looks like a signature problem.

**Only `EdDSA`, compared by equality.** Not a blocklist — `RS256` and `none`
fail the same check, and a future algorithm name cannot slip past by not being
on a list. Accepting `RS256` would let anyone who can read the published public
key sign their own commands.

**Every published key is tried.** Tokens carry no `kid`, because a rotation
publishes two keys and neither side should have to be redeployed in step with
the other. An empty key set **refuses** — "we could not fetch the keys" must
never read as "no key objected".

**A `ver` claim, refused when unknown.** Everything else here freezes on the
first plugin release — old installs live for years and nobody can patch them —
so a newer signer talking to an older verifier has to be refused cleanly rather
than read with the old meanings. `Config::withAcceptedVersions()` widens it for
a transition; widening it permanently defeats the point.

**The identifier is spent last.** A token that fails a later check is not
burned, so a wrong-scope request is retryable rather than a dead end.

**`WpdbNonceStore` uses a single `INSERT`, not a transient.** `get_transient()`
then `set_transient()` is not atomic: two requests carrying one identifier can
both read "unused" before either writes, and both are honoured — which is
exactly the replay the store exists to prevent. The unique index on
`option_name` is the only place that decision can be made atomically.

**One fixed refusal.** A route using this is reachable by anyone, so every cause
returns `Bridge::REFUSED`. Reflecting the reason turns it into an oracle:
"unknown issuer" against "bad signature" tells an attacker whether their guessed
issuer is the one this site trusts.

**Key sets are fetched over HTTPS only** (`localhost` and `.test` excepted for
development, by host name rather than by a flag — a flag is one wrong
environment variable away from doing it in production). Every key in a fetched
set is tried, so a substituted set would be enough to forge commands.

## Layout

```
src/                 no WordPress. Unit tested without it.
src/Contract/        the four seams a host fills: trust, keys, nonces, clock,
                     plus Verifier, the seam a host depends on
src/WordPress/       adapters. Optional — implement the contracts yourself if
                     you have a better HTTP layer or a durable nonce store.
```

## Tests

```bash
composer install
composer test    # no WordPress, no network
composer lint
```

The suite is written around the **refusals**, and each one says what would
happen *without* the check. A test named for what it allows proves the happy
path; a test named for what it refuses proves the thing an attacker would try.

`src/WordPress/` is not unit tested here — it is integration surface, covered by
the host plugin's own suite where WordPress exists.

## Code style

PSR-12, enforced by `composer lint`. Deliberately not the WordPress standard:
this package is framework agnostic and only its adapters touch WordPress.
