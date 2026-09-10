<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge;

/**
 * Base64url, which is what JOSE uses and PHP does not ship.
 *
 * Its own class because three separate places need it — a token's segments, the
 * keys in a JWKS, and a body digest — and a copy in each is three chances to
 * get the padding wrong in a way that only fails for some inputs.
 */
final class Base64Url
{
	/**
	 * Decode a base64url string.
	 *
	 * Strict, so a value carrying characters outside the alphabet is rejected
	 * rather than silently decoded into something else. A token segment that is
	 * not valid base64url is malformed, and treating it as data would mean
	 * verifying a signature over bytes the sender did not send.
	 *
	 * @param string $value Encoded value.
	 *
	 * @return string Raw bytes, or empty on anything unusable.
	 */
	public static function decode(string $value): string
	{
		if ('' === $value || 1 !== preg_match('#^[A-Za-z0-9_-]+$#', $value)) {
			return '';
		}

		$padded  = strtr($value, '-_', '+/');
		$padding = strlen($padded) % 4;

		if ($padding > 0) {
			$padded .= str_repeat('=', 4 - $padding);
		}

		$decoded = base64_decode($padded, true);

		return false === $decoded ? '' : $decoded;
	}

	/**
	 * Encode raw bytes as unpadded base64url.
	 *
	 * @param string $value Raw bytes.
	 *
	 * @return string
	 */
	public static function encode(string $value): string
	{
		return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
	}

	/**
	 * The digest of a request body, as the signer computed it.
	 *
	 * Unpadded base64url of the SHA-256, which is what JOSE uses everywhere
	 * else in this exchange.
	 *
	 * @param string $body Raw request body.
	 *
	 * @return string
	 */
	public static function digest(string $body): string
	{
		return self::encode(hash('sha256', $body, true));
	}
}
