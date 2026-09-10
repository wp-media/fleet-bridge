<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests\Double;

use WPMedia\FleetBridge\Base64Url;

/**
 * Mints real tokens with a real key.
 *
 * Tests sign for themselves rather than pasting fixtures, so the signature
 * being checked is one that was actually made — a hardcoded token proves the
 * string was copied correctly and nothing else.
 */
final class Signer
{
	/**
	 * @var string
	 */
	private $secret;

	/**
	 * @var string
	 */
	private $public;

	public function __construct()
	{
		$pair         = sodium_crypto_sign_keypair();
		$this->secret = sodium_crypto_sign_secretkey($pair);
		$this->public = sodium_crypto_sign_publickey($pair);
	}

	/**
	 * The public half, as a key set entry.
	 *
	 * @return string
	 */
	public function publicKey(): string
	{
		return $this->public;
	}

	/**
	 * Sign a payload, with an overridable header.
	 *
	 * @param array<string, mixed> $payload Claims.
	 * @param array<string, mixed> $header  Header overrides.
	 *
	 * @return string Compact serialisation.
	 */
	public function sign(array $payload, array $header = []): string
	{
		$header = array_merge(
			[
				'alg' => 'EdDSA',
				'typ' => 'JWT',
			],
			$header
		);

		$input = Base64Url::encode((string) json_encode($header))
			. '.'
			. Base64Url::encode((string) json_encode($payload));

		return $input . '.' . Base64Url::encode(sodium_crypto_sign_detached($input, $this->secret));
	}
}
