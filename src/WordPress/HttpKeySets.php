<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\WordPress;

use WPMedia\FleetBridge\Base64Url;
use WPMedia\FleetBridge\Contract\KeySets;

/**
 * Key sets fetched over HTTP and cached.
 *
 * The cache TTL is the **revocation window**. Revoking a leaked key means the
 * publisher stops publishing it, and an install keeps accepting it until its
 * cache expires. That is the price of being able to rotate without shipping a
 * plugin release, and it is why the window is minutes rather than the day the
 * settings channel is cached for.
 *
 * Fetched lazily, only while a request is actually being verified. An install
 * nobody commands never asks — there is no cron here and no scheduled work.
 */
final class HttpKeySets implements KeySets
{
	/**
	 * How long a fetched set is reused, in seconds.
	 */
	public const CACHE_SECONDS = 600;

	/**
	 * How long a failure is remembered, in seconds.
	 *
	 * Without this, a publisher that is down turns every inbound request into
	 * an outbound one that will also fail, and a site under any load starts
	 * hammering them. Much shorter than the success TTL, because coming back
	 * should be noticed quickly.
	 */
	public const FAILURE_CACHE_SECONDS = 30;

	/**
	 * Hosts allowed over plain HTTP, and only these.
	 *
	 * A development environment has no certificate for a name that resolves
	 * nowhere. Named hosts rather than a "dev mode" flag, because a flag is one
	 * wrong environment variable away from doing this in production.
	 */
	private const LOCAL_HOSTS = [ 'localhost', '127.0.0.1', '::1', 'host.docker.internal' ];

	/**
	 * @var callable|null
	 */
	private $logger;

	/**
	 * @param callable|null $logger Receives a string when a set cannot be used.
	 *                              Optional: a host that does not want the
	 *                              noise passes nothing.
	 */
	public function __construct(?callable $logger = null)
	{
		$this->logger = $logger;
	}

	/**
	 * Every Ed25519 public key published at a URL, as raw 32-byte strings.
	 *
	 * @param string $url Where to look.
	 *
	 * @return string[] Empty when the set could not be had, or carried nothing
	 *                  usable — which callers must treat as "verify nothing".
	 */
	public function keys(string $url): array
	{
		if ('' === $url) {
			return [];
		}

		if (! self::isTrustworthy($url)) {
			$this->log('refusing to fetch a key set over an untrusted transport: ' . $url);

			return [];
		}

		$transient = 'fleet_bridge_jwks_' . md5($url);
		$cached    = get_transient($transient);

		if (is_array($cached)) {
			return $cached;
		}

		// A remembered failure. A string rather than an empty array, so it is
		// distinguishable from a successful fetch of an empty set.
		if ('failed' === $cached) {
			return [];
		}

		$keys = $this->fetch($url);

		if ([] === $keys) {
			set_transient($transient, 'failed', self::FAILURE_CACHE_SECONDS);

			return [];
		}

		set_transient($transient, $keys, self::CACHE_SECONDS);

		return $keys;
	}

	/**
	 * Is this a URL worth fetching key material from.
	 *
	 * HTTPS only. A key set is not ordinary data: every key it carries is tried
	 * against every inbound command, so one forged key in a substituted
	 * response is enough to forge commands outright. Over plain HTTP that
	 * substitution is available to anyone on the path or anyone who can answer
	 * a DNS query, which would make the whole signature check decorative.
	 *
	 * @param string $url Candidate URL.
	 *
	 * @return bool
	 */
	public static function isTrustworthy(string $url): bool
	{
		$parts = wp_parse_url($url);

		if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
			return false;
		}

		if ('https' === $parts['scheme']) {
			return true;
		}

		if ('http' !== $parts['scheme']) {
			return false;
		}

		$host = strtolower((string) $parts['host']);

		if (in_array($host, self::LOCAL_HOSTS, true)) {
			return true;
		}

		// Reserved development TLDs, which by definition resolve to nothing on
		// the public internet.
		return 1 === preg_match('#\.(test|localhost)$#', $host);
	}

	/**
	 * Ask the endpoint for its key set.
	 *
	 * @param string $url Where to look.
	 *
	 * @return string[]
	 */
	private function fetch(string $url): array
	{
		$response = wp_remote_get($url, [ 'timeout' => 5 ]);

		if (is_wp_error($response) || 200 !== wp_remote_retrieve_response_code($response)) {
			$this->log('could not fetch the key set from ' . $url);

			return [];
		}

		$body = json_decode(wp_remote_retrieve_body($response), true);

		if (! is_array($body) || ! isset($body['keys']) || ! is_array($body['keys'])) {
			$this->log('the key set at ' . $url . ' is not a JWKS');

			return [];
		}

		$keys = [];

		foreach ($body['keys'] as $key) {
			$decoded = self::decode($key);

			if ('' !== $decoded) {
				$keys[] = $decoded;
			}
		}

		return $keys;
	}

	/**
	 * One JWK, as raw key bytes.
	 *
	 * Anything that is not an Ed25519 signing key is skipped rather than
	 * refused: a set is allowed to carry keys for purposes we do not have, and
	 * failing the whole fetch over one of them would take verification down for
	 * a reason nobody could see.
	 *
	 * @param mixed $key One entry from the `keys` array.
	 *
	 * @return string Raw 32-byte key, or empty when unusable.
	 */
	private static function decode($key): string
	{
		if (! is_array($key)) {
			return '';
		}

		if ('OKP' !== ( $key['kty'] ?? '' ) || 'Ed25519' !== ( $key['crv'] ?? '' )) {
			return '';
		}

		// `use` is optional, but a key declaring itself for encryption must not
		// be used to check a signature.
		if (isset($key['use']) && 'sig' !== $key['use']) {
			return '';
		}

		if (! isset($key['x']) || ! is_string($key['x'])) {
			return '';
		}

		$raw = Base64Url::decode($key['x']);

		return SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES === strlen($raw) ? $raw : '';
	}

	/**
	 * @param string $message What happened.
	 *
	 * @return void
	 */
	private function log(string $message): void
	{
		if (null !== $this->logger) {
			( $this->logger )($message);
		}
	}
}
