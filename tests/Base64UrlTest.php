<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests;

use PHPUnit\Framework\TestCase;
use WPMedia\FleetBridge\Base64Url;

/**
 * The encoding everything else rests on.
 *
 * Worth its own tests because the failure mode is subtle: a decoder that is
 * lenient about padding or alphabet will accept a token whose bytes are not the
 * bytes the sender signed, and the signature check would then be verifying
 * something else.
 */
final class Base64UrlTest extends TestCase
{
	public function testItRoundTripsArbitraryBytes(): void
	{
		$raw = random_bytes(64);

		self::assertSame($raw, Base64Url::decode(Base64Url::encode($raw)));
	}

	public function testItEncodesWithoutPadding(): void
	{
		/* JOSE is unpadded. Emitting `=` would produce a signing input the
		 * other side does not reproduce. */
		self::assertStringNotContainsString('=', Base64Url::encode('abcde'));
	}

	public function testItUsesTheUrlSafeAlphabet(): void
	{
		$encoded = Base64Url::encode(hex2bin('fbf0') ?: '');

		self::assertStringNotContainsString('+', $encoded);
		self::assertStringNotContainsString('/', $encoded);
	}

	/**
	 * @dataProvider rejected
	 */
	public function testItRefusesAnythingOutsideTheAlphabet(string $value): void
	{
		/* Returning empty rather than best-effort decoding: a segment that is
		 * not valid base64url is malformed, and guessing at it would mean
		 * checking a signature over bytes nobody sent. */
		self::assertSame('', Base64Url::decode($value));
	}

	/**
	 * @return array<string, array<int, string>>
	 */
	public function rejected(): array
	{
		return [
			'empty'            => [ '' ],
			'standard base64'  => [ 'ab+cd/ef' ],
			'padded'           => [ 'YWJj=' ],
			'whitespace'       => [ 'YWJ j' ],
			'newline'          => [ "YWJj\n" ],
			'non-alphabet'     => [ 'YWJj!' ],
		];
	}

	public function testTheDigestMatchesAKnownSha256(): void
	{
		/* Pinned against a value computed independently, so a change to the
		 * digest shape is caught here rather than as an unexplained refusal on
		 * a customer's site. */
		self::assertSame(
			'47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU',
			Base64Url::digest('')
		);
	}

	public function testTheDigestIsSensitiveToEveryByte(): void
	{
		self::assertNotSame(Base64Url::digest('{"a":1}'), Base64Url::digest('{"a":2}'));
	}
}
