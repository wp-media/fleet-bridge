<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge;

use WPMedia\FleetBridge\Contract\Clock;
use WPMedia\FleetBridge\Contract\KeySets;
use WPMedia\FleetBridge\Contract\NonceStore;
use WPMedia\FleetBridge\Contract\TrustStore;
use WPMedia\FleetBridge\Exception\NotAuthorised;

/**
 * Accept a command from Fleet, on two proofs from two parties.
 *
 * ## The problem this solves
 *
 * Fleet is a WP Media application where an agency manages a plugin across every
 * site on its licence from one dashboard. To read or change a setting it has to
 * reach the site, and it deliberately holds **no customer credential** — no
 * WordPress login, no application password, not even the licence key.
 *
 * An application password would be the easy route and the wrong one: it
 * authenticates a *user*, so it grants whatever that user can do rather than
 * "this plugin's allowlisted options", and Fleet would have to store one secret
 * per site. So Fleet signs a short-lived token per request instead.
 *
 * ## Two proofs, and why neither is enough alone
 *
 * | Credential | Signed by | Proves |
 * |---|---|---|
 * | command | Fleet | who is asking, and covers the exact body bytes |
 * | consent grant | the licence vendor | the owner allows this capability on this site, right now |
 *
 * **Fleet must not sign the consent.** It is the party being granted the
 * access, and a grantee attesting its own grant proves nothing at all.
 *
 * **The consent must not be cached.** An install that remembers "allowed" for a
 * day keeps accepting commands for a day after the owner withdraws it, and a
 * permission that takes a day to withdraw is not a permission. So it arrives
 * with each command, minted seconds earlier, and revocation is immediate.
 *
 * What is safe to cache for a long time is a **key set location**, because a
 * rotation publishes two keys at once for exactly that reason.
 *
 * ## What this deliberately cannot tell you
 *
 * *Which* of Fleet's own customers asked. There is no per-site secret shared
 * with Fleet, so there is nothing to check that against, and isolation between
 * Fleet's customers is enforced in Fleet before anything leaves it. This
 * verifies that a command is Fleet's, that it names this site, and that the
 * owner allows it — and that is the whole of it.
 */
final class Bridge
{
	/**
	 * What a caller is told when anything at all is wrong.
	 *
	 * Fixed text whatever the cause. A route using this is reachable by anyone,
	 * so reflecting the reason turns it into an oracle: "unknown issuer"
	 * against "bad signature" tells an attacker whether their guessed issuer is
	 * the one this site trusts. The reason is on the exception, for the log.
	 */
	public const REFUSED = 'This request is not authorised.';

	/**
	 * Claims every token must carry to be evaluated at all.
	 */
	private const REQUIRED_CLAIMS = [ 'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'ver' ];

	/**
	 * Required in addition of a token that must cover a request body.
	 */
	private const BODY_BOUND_CLAIMS = [ 'digest' ];

	/**
	 * The type segment of a GRND profile GRN, which carries the tag.
	 */
	private const TAG_PATTERN = '[a-zA-Z0-9_-]{1,32}';

	/**
	 * The identifier segment, which carries a single-use nonce.
	 */
	private const NONCE_PATTERN = '[a-zA-Z0-9\-:@_./]{0,127}[a-zA-Z0-9]';

	/**
	 * The shape of a GRND profile GRN.
	 *
	 * Composed from the two segments rather than written as one string, so each
	 * half can be read without counting brackets.
	 */
	private const PROFILE_PATTERN = '#^grn:2@int:grnd::'
		. '(?P<tag>' . self::TAG_PATTERN . ')'
		. '/(?P<nonce>' . self::NONCE_PATTERN . ')$#';

	/**
	 * @var TrustStore
	 */
	private $trust;

	/**
	 * @var KeySets
	 */
	private $keySets;

	/**
	 * @var NonceStore
	 */
	private $nonces;

	/**
	 * @var Config
	 */
	private $config;

	/**
	 * @var Clock
	 */
	private $clock;

	/**
	 * @param TrustStore $trust   Who this install trusts, and where their keys are.
	 * @param KeySets    $keySets How a key set is fetched.
	 * @param NonceStore $nonces  Where a spent identifier is remembered.
	 * @param Config     $config  What counts as valid beyond the signature.
	 * @param Clock      $clock   What time it is.
	 */
	public function __construct(
		TrustStore $trust,
		KeySets $keySets,
		NonceStore $nonces,
		Config $config,
		Clock $clock
	) {
		$this->trust   = $trust;
		$this->keySets = $keySets;
		$this->nonces  = $nonces;
		$this->config  = $config;
		$this->clock   = $clock;
	}

	/**
	 * Verify a command from Fleet.
	 *
	 * @param string $authorization Raw `Authorization` header value.
	 * @param string $body          Raw request body, exactly as received.
	 *
	 * @return Claims
	 *
	 * @throws NotAuthorised When it must not be honoured.
	 */
	public function verifyCommand(string $authorization, string $body): Claims
	{
		return $this->verify(
			$this->bearer($authorization),
			TrustStore::COMMAND,
			$this->config->commandTag(),
			$body,
			null
		);
	}

	/**
	 * Verify a consent grant, and that it covers the capability being used.
	 *
	 * Not bound to the request body, deliberately: a grant authorises a *scope
	 * on a site*, not one particular set of bytes. The command is what binds
	 * the bytes. Replay is prevented by the grant's own single-use identifier
	 * and its short life.
	 *
	 * @param string $grant         The compact JWS the vendor signed.
	 * @param string $requiredScope The capability this request needs.
	 *
	 * @return Claims
	 *
	 * @throws NotAuthorised When it must not be honoured.
	 */
	public function verifyGrant(string $grant, string $requiredScope): Claims
	{
		return $this->verify(
			trim($grant),
			TrustStore::CONSENT,
			$this->config->consentTag(),
			null,
			$requiredScope
		);
	}

	/**
	 * The steps, in an order chosen rather than stumbled into.
	 *
	 * Cheap structural checks, then the issuer is compared against the one this
	 * install was told, then the signature against every key that issuer
	 * publishes, and only then is any claim value acted upon. **Nothing a token
	 * asserts is trusted before its signature is proven** — in particular `iss`
	 * is read only to select a configured expectation, never to locate a key.
	 *
	 * The identifier is spent **last**, so a token that fails a later check can
	 * still be presented again. Only a token that was going to be honoured is
	 * ever burned.
	 *
	 * @param string      $token         Compact serialisation.
	 * @param string      $role          A {@see TrustStore} role.
	 * @param string      $tag           The only GRND tag accepted here.
	 * @param string|null $body          Body the signature must cover, or null.
	 * @param string|null $requiredScope Capability the token must carry, or null.
	 *
	 * @return Claims
	 *
	 * @throws NotAuthorised When it must not be honoured.
	 */
	private function verify(
		string $token,
		string $role,
		string $tag,
		?string $body,
		?string $requiredScope
	): Claims {
		$jws     = Jws::parse($token, Config::MAX_BYTES);
		$payload = $jws->payload();

		$required = null === $body
			? self::REQUIRED_CLAIMS
			: array_merge(self::REQUIRED_CLAIMS, self::BODY_BOUND_CLAIMS);

		foreach ($required as $claim) {
			if (! isset($payload[ $claim ])) {
				throw new NotAuthorised('Missing claim: ' . $claim);
			}
		}

		// Before anything else about the token is believed. A v2 token carries
		// claims a v1 verifier would read with v1 meanings, so refusing an
		// unknown version is what makes this exchange changeable at all —
		// otherwise the first release freezes it forever, on installs nobody can
		// patch.
		$this->assertVersion($payload['ver']);

		$this->assertIssuer((string) $payload['iss'], $role);

		$jws->assertSignedByOneOf($this->keySets->keys($this->trust->keySetUrl($role)));

		$this->assertNames((string) $payload['aud'], $this->config->host(), 'audience');
		$this->assertNames((string) $payload['sub'], $this->config->subject(), 'subject');
		$this->assertTag((string) $payload['jti'], $tag);
		$this->assertFresh((int) $payload['iat'], (int) $payload['exp']);

		if (null !== $body) {
			$this->assertCovers((string) $payload['digest'], $body);
		}

		$claims = new Claims($payload);

		if (null !== $requiredScope && ! in_array($requiredScope, $claims->scopes(), true)) {
			throw new NotAuthorised('The grant does not cover ' . $requiredScope . '.');
		}

		$this->spend($claims->identifier(), (int) $payload['exp']);

		return $claims;
	}

	/**
	 * The token out of a Bearer header.
	 *
	 * @param string $authorization Raw header value.
	 *
	 * @return string
	 *
	 * @throws NotAuthorised When absent or not a Bearer.
	 */
	private function bearer(string $authorization): string
	{
		if ('' === trim($authorization)) {
			throw new NotAuthorised('Missing Authorization header.');
		}

		// Compared case insensitively, because RFC 7235 says the scheme is.
		if (0 !== stripos($authorization, 'Bearer ')) {
			throw new NotAuthorised('Authorization header is not a Bearer.');
		}

		return trim(substr($authorization, 7));
	}

	/**
	 * Does this install speak the version the token was minted under.
	 *
	 * @param mixed $version The `ver` claim.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When the version is unknown here.
	 */
	private function assertVersion($version): void
	{
		if (!is_int($version) && !(is_string($version) && ctype_digit($version))) {
			throw new NotAuthorised('The version claim is not a number.');
		}

		if (!in_array((int) $version, $this->config->acceptedVersions(), true)) {
			throw new NotAuthorised('Unsupported contract version: ' . (int) $version . '.');
		}
	}

	/**
	 * Is this the issuer this install was told to trust for this role.
	 *
	 * @param string $issuer Issuer claim.
	 * @param string $role   A {@see TrustStore} role.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When it is not, or when nothing was configured.
	 */
	private function assertIssuer(string $issuer, string $role): void
	{
		$expected = $this->trust->issuer($role);

		if ('' === $expected) {
			throw new NotAuthorised('No ' . $role . ' issuer has been served to this install.');
		}

		if (! hash_equals($expected, $issuer)) {
			throw new NotAuthorised('Unknown ' . $role . ' issuer.');
		}
	}

	/**
	 * Does a claim name this site, and not another one.
	 *
	 * The check that makes a token useless anywhere but here. A licence covers
	 * up to fifty sites, and without this a token minted for one of them would
	 * drive all fifty.
	 *
	 * @param string $actual   The claim.
	 * @param string $expected What this site answers to.
	 * @param string $what     Which claim, for the log.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When it names somewhere else.
	 */
	private function assertNames(string $actual, string $expected, string $what): void
	{
		if ('' === $expected) {
			throw new NotAuthorised('This site does not know its own host, so it cannot check the ' . $what . '.');
		}

		if (! hash_equals($expected, strtolower($actual))) {
			throw new NotAuthorised('Wrong ' . $what . '.');
		}
	}

	/**
	 * Was this token minted for this purpose.
	 *
	 * @param string $identifier The `jti`, a GRND profile GRN.
	 * @param string $expected   The only tag accepted here.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When malformed or carrying another tag.
	 */
	private function assertTag(string $identifier, string $expected): void
	{
		if (1 !== preg_match(self::PROFILE_PATTERN, $identifier, $matches)) {
			throw new NotAuthorised('The identifier is not a GRND profile GRN.');
		}

		if (! hash_equals($expected, $matches['tag'])) {
			throw new NotAuthorised('Wrong tag: ' . $matches['tag']);
		}
	}

	/**
	 * Is the token current, and was its lifetime reasonable.
	 *
	 * The lifetime is capped **here** rather than trusted from the token: a
	 * signer asking for a year would otherwise get one.
	 *
	 * @param int $issuedAt `iat`.
	 * @param int $expires  `exp`.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When expired, premature, or too long lived.
	 */
	private function assertFresh(int $issuedAt, int $expires): void
	{
		$now    = $this->clock->now();
		$leeway = $this->config->leeway();

		if ($expires < ( $now - $leeway )) {
			throw new NotAuthorised('Expired.');
		}

		if ($issuedAt > ( $now + $leeway )) {
			throw new NotAuthorised('Not valid yet.');
		}

		if (( $expires - $issuedAt ) > $this->config->maxLifetime()) {
			throw new NotAuthorised('Lifetime exceeds the maximum accepted.');
		}
	}

	/**
	 * Does the signature cover the bytes that actually arrived.
	 *
	 * Without this a captured header could be replayed with a different body,
	 * which on a write endpoint means setting a different option.
	 *
	 * @param string $digest The `digest` claim.
	 * @param string $body   Raw request body.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When they do not match.
	 */
	private function assertCovers(string $digest, string $body): void
	{
		if (! hash_equals(Base64Url::digest($body), $digest)) {
			throw new NotAuthorised('Body does not match the signed digest.');
		}
	}

	/**
	 * Spend the identifier, once.
	 *
	 * Remembered only until it would have expired anyway, so the store never
	 * grows beyond the tokens that are still live.
	 *
	 * @param string $identifier The `jti`.
	 * @param int    $expires    `exp`.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When it has already been used.
	 */
	private function spend(string $identifier, int $expires): void
	{
		$ttl = max($expires - $this->clock->now(), $this->config->leeway());

		if (! $this->nonces->spend($identifier, $ttl)) {
			throw new NotAuthorised('Already used.');
		}
	}
}
