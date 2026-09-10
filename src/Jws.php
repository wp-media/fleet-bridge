<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge;

use WPMedia\FleetBridge\Exception\NotAuthorised;

/**
 * A compact JWS, parsed and checked against a set of keys.
 *
 * Structure and signature only. What the claims *mean* is {@see Bridge}'s
 * business; this class refuses anything that is not a well formed, correctly
 * signed Ed25519 token and knows nothing about Fleet.
 */
final class Jws
{
	/**
	 * Only Ed25519.
	 *
	 * Compared by equality rather than checked against a blocklist, so `RS256`
	 * and `none` fail the same way and a future algorithm name cannot slip
	 * through by not being on a list. This is the classic JWS confusion
	 * attack: accepting `RS256` would let anyone who can read a public key
	 * sign their own tokens.
	 */
	public const ALGORITHM = 'EdDSA';

	/**
	 * @var array<string, mixed>
	 */
	private $header;

	/**
	 * @var array<string, mixed>
	 */
	private $payload;

	/**
	 * @var string
	 */
	private $signature;

	/**
	 * @var string
	 */
	private $signingInput;

	/**
	 * @param array<string, mixed> $header       Decoded header.
	 * @param array<string, mixed> $payload      Decoded payload.
	 * @param string               $signature    Raw signature bytes.
	 * @param string               $signingInput The two encoded segments, joined.
	 */
	private function __construct(array $header, array $payload, string $signature, string $signingInput)
	{
		$this->header       = $header;
		$this->payload      = $payload;
		$this->signature    = $signature;
		$this->signingInput = $signingInput;
	}

	/**
	 * Parse a token, refusing anything structurally wrong.
	 *
	 * Cheapest checks first: a length before a split, a split before a decode,
	 * a decode before a parse. A megabyte of base64 should cost a `strlen`.
	 *
	 * @param string $token    Compact serialisation.
	 * @param int    $maxBytes Longest token worth parsing.
	 *
	 * @return self
	 *
	 * @throws NotAuthorised When the token is not a usable EdDSA JWS.
	 */
	public static function parse(string $token, int $maxBytes): self
	{
		if ('' === $token) {
			throw new NotAuthorised('No token was presented.');
		}

		if (strlen($token) > $maxBytes) {
			throw new NotAuthorised('Token larger than ' . $maxBytes . ' bytes.');
		}

		$segments = explode('.', $token);

		if (3 !== count($segments)) {
			throw new NotAuthorised('Token does not have three segments.');
		}

		$header = self::decodeJson($segments[0], 'header');

		if (! isset($header['alg']) || self::ALGORITHM !== $header['alg']) {
			throw new NotAuthorised('Unsupported algorithm.');
		}

		$payload   = self::decodeJson($segments[1], 'payload');
		$signature = Base64Url::decode($segments[2]);

		if (SODIUM_CRYPTO_SIGN_BYTES !== strlen($signature)) {
			throw new NotAuthorised('Malformed signature.');
		}

		return new self($header, $payload, $signature, $segments[0] . '.' . $segments[1]);
	}

	/**
	 * Check the signature against every key a publisher offers.
	 *
	 * **Every** key, because a rotation publishes two at once and these tokens
	 * carry no `kid` to select on. An empty set refuses rather than passes:
	 * "we could not fetch the keys" must never read as "no key objected".
	 *
	 * @param string[] $keys Raw 32-byte Ed25519 public keys.
	 *
	 * @return void
	 *
	 * @throws NotAuthorised When no key verifies it.
	 */
	public function assertSignedByOneOf(array $keys): void
	{
		if ([] === $keys) {
			throw new NotAuthorised('No usable key was published, so no signature can be checked.');
		}

		foreach ($keys as $key) {
			if (SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen($key)) {
				continue;
			}

			if (sodium_crypto_sign_verify_detached($this->signature, $this->signingInput, $key)) {
				return;
			}
		}

		throw new NotAuthorised('Bad signature.');
	}

	/**
	 * The decoded payload. Meaningless until the signature has been checked.
	 *
	 * @return array<string, mixed>
	 */
	public function payload(): array
	{
		return $this->payload;
	}

	/**
	 * One base64url JSON segment, as an array.
	 *
	 * @param string $segment Encoded segment.
	 * @param string $what    Which segment, for the log.
	 *
	 * @return array<string, mixed>
	 *
	 * @throws NotAuthorised When it is not a JSON object.
	 */
	private static function decodeJson(string $segment, string $what): array
	{
		$decoded = json_decode(Base64Url::decode($segment), true);

		if (! is_array($decoded)) {
			throw new NotAuthorised('The ' . $what . ' is not a JSON object.');
		}

		return $decoded;
	}
}
