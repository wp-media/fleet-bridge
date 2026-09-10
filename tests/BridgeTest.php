<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests;

use PHPUnit\Framework\TestCase;
use WPMedia\FleetBridge\Base64Url;
use WPMedia\FleetBridge\Bridge;
use WPMedia\FleetBridge\Config;
use WPMedia\FleetBridge\Contract\TrustStore;
use WPMedia\FleetBridge\Exception\NotAuthorised;
use WPMedia\FleetBridge\Tests\Double\ArrayKeySets;
use WPMedia\FleetBridge\Tests\Double\ArrayNonceStore;
use WPMedia\FleetBridge\Tests\Double\ArrayTrustStore;
use WPMedia\FleetBridge\Tests\Double\FixedClock;
use WPMedia\FleetBridge\Tests\Double\Signer;

/**
 * What this site will and will not accept.
 *
 * The refusals are the point. A test named for what it allows proves the happy
 * path; a test named for what it refuses proves the thing an attacker would
 * try, and each docstring here says what would happen **without** the check —
 * because in a year that is the only thing that makes the test worth keeping.
 *
 * Real keys, real signatures, real digests. Only the clock, the key transport
 * and the nonce store are doubles, and each of those is a seam the production
 * code was given deliberately.
 */
final class BridgeTest extends TestCase
{
	private const HOST = 'poc.fleet.test';
	private const SUBJECT = 'grn:2@g1:wprocket:site/poc.fleet.test';
	private const FLEET = 'grn:2@int:grn::environment/g1:wprocket:fleet.test-suite';
	private const VENDOR = 'grn:2@int:grn::environment/g1:wprocket:app.test-suite';
	private const FLEET_KEYS = 'https://fleet.test-suite/api/v1/grnd/jwks';
	private const VENDOR_KEYS = 'https://app.test-suite/wp-json/grnd/v1/jwks';

	/**
	 * @var Signer
	 */
	private $fleet;

	/**
	 * @var Signer
	 */
	private $vendor;

	/**
	 * @var ArrayTrustStore
	 */
	private $trust;

	/**
	 * @var ArrayKeySets
	 */
	private $keySets;

	/**
	 * @var ArrayNonceStore
	 */
	private $nonces;

	/**
	 * @var FixedClock
	 */
	private $clock;

	/**
	 * @var Bridge
	 */
	private $bridge;

	protected function setUp(): void
	{
		$this->fleet  = new Signer();
		$this->vendor = new Signer();

		$this->trust = new ArrayTrustStore();
		$this->trust->trust(TrustStore::COMMAND, self::FLEET, self::FLEET_KEYS);
		$this->trust->trust(TrustStore::CONSENT, self::VENDOR, self::VENDOR_KEYS);

		$this->keySets = new ArrayKeySets();
		$this->keySets->publish(self::FLEET_KEYS, [ $this->fleet->publicKey() ]);
		$this->keySets->publish(self::VENDOR_KEYS, [ $this->vendor->publicKey() ]);

		$this->nonces = new ArrayNonceStore();
		$this->clock  = new FixedClock();

		$this->bridge = new Bridge(
			$this->trust,
			$this->keySets,
			$this->nonces,
			new Config(self::HOST),
			$this->clock
		);
	}

	// --- what is accepted ---------------------------------------------------

	public function testAValidCommandIsAccepted(): void
	{
		$claims = $this->bridge->verifyCommand('Bearer ' . $this->command('{"a":1}'), '{"a":1}');

		self::assertSame(self::FLEET, $claims->get('iss'));
		self::assertSame(1, $this->nonces->count());
	}

	public function testAValidGrantCoveringTheScopeIsAccepted(): void
	{
		$claims = $this->bridge->verifyGrant($this->grant(), 'settings:write');

		self::assertSame([ 'settings:read', 'settings:write' ], $claims->scopes());
	}

	public function testAGrantIsNotBoundToABody(): void
	{
		/* A grant authorises a scope on a site, not one set of bytes. Requiring
		 * a digest of it would mean the vendor had to know what Fleet was about
		 * to send, which it does not and should not. */
		$this->bridge->verifyGrant($this->grant([ 'scope' => [ 'settings:read' ] ]), 'settings:read');

		self::assertSame(1, $this->nonces->count());
	}

	public function testEitherOfTwoPublishedKeysVerifies(): void
	{
		/* Without trying every key, a rotation would break every install
		 * between the moment the new key starts signing and the moment each
		 * site's cache expires. That is why a set is published, and why there
		 * is no `kid` to select on. */
		$rotated = new Signer();
		$this->keySets->publish(self::FLEET_KEYS, [ $rotated->publicKey(), $this->fleet->publicKey() ]);

		$this->bridge->verifyCommand('Bearer ' . $this->command(''), '');

		self::assertSame(1, $this->nonces->count());
	}

	// --- the credential itself ----------------------------------------------

	public function testNoAuthorizationHeaderIsRefused(): void
	{
		$this->expectRefusal('Missing Authorization');
		$this->bridge->verifyCommand('', '');
	}

	public function testAnAuthorizationHeaderThatIsNotABearerIsRefused(): void
	{
		$this->expectRefusal('not a Bearer');
		$this->bridge->verifyCommand('Basic ' . base64_encode('a:b'), '');
	}

	public function testTheBearerSchemeIsMatchedCaseInsensitively(): void
	{
		/* RFC 7235 says the scheme is case insensitive. Being stricter than the
		 * standard on our own inbound side is a compatibility problem nobody
		 * would think to look for. */
		$claims = $this->bridge->verifyCommand('bearer ' . $this->command(''), '');

		self::assertSame(self::FLEET, $claims->get('iss'));
	}

	public function testAnOversizeTokenIsRefusedBeforeParsing(): void
	{
		$this->expectRefusal('larger than');
		$this->bridge->verifyCommand('Bearer ' . str_repeat('a', Config::MAX_BYTES + 1), '');
	}

	public function testATokenWithoutThreeSegmentsIsRefused(): void
	{
		$this->expectRefusal('three segments');
		$this->bridge->verifyCommand('Bearer not.a.jws.at.all', '');
	}

	/**
	 * @dataProvider forgedAlgorithms
	 */
	public function testOnlyEdDSAIsAccepted(string $algorithm): void
	{
		/* Accepting RS256 would let anyone who can read the published public
		 * key sign their own commands — the classic JWS confusion attack.
		 * `none` would let anyone sign nothing at all. Compared by equality, so
		 * both fail the same way and a new algorithm name cannot slip past a
		 * blocklist. */
		$token = $this->fleet->sign($this->commandClaims(''), [ 'alg' => $algorithm ]);

		$this->expectRefusal('Unsupported algorithm');
		$this->bridge->verifyCommand('Bearer ' . $token, '');
	}

	/**
	 * @return array<int, array<int, string>>
	 */
	public function forgedAlgorithms(): array
	{
		return [ [ 'RS256' ], [ 'none' ], [ 'HS256' ], [ 'ES256' ] ];
	}

	/**
	 * @dataProvider requiredClaims
	 */
	public function testEveryRequiredClaimIsRequired(string $claim): void
	{
		$claims = $this->commandClaims('');
		unset($claims[ $claim ]);

		$this->expectRefusal('Missing claim: ' . $claim);
		$this->bridge->verifyCommand('Bearer ' . $this->fleet->sign($claims), '');
	}

	/**
	 * @return array<int, array<int, string>>
	 */
	public function requiredClaims(): array
	{
		return [['iss'], ['sub'], ['aud'], ['exp'], ['iat'], ['jti'], ['ver'], ['digest']];
	}

	public function testAGrantNeedsNoDigestClaim(): void
	{
		$claims = $this->grantClaims();
		unset($claims['digest']);

		$this->bridge->verifyGrant($this->vendor->sign($claims), 'settings:read');

		self::assertSame(1, $this->nonces->count());
	}

	// --- the contract version -----------------------------------------------

	public function testAnUnknownContractVersionIsRefused(): void
	{
		/* The single most important line in this package. Everything else here
		 * freezes on the first plugin release — old installs live for years and
		 * nobody can patch them — so a v2 signer talking to a v1 verifier has to
		 * be refused cleanly rather than read with v1 meanings. Without this,
		 * the claim names, the tags, the subject shape and the scope strings are
		 * settled forever by whatever shipped first. */
		$this->expectRefusal('Unsupported contract version: 2');
		$this->bridge->verifyCommand('Bearer ' . $this->command('', ['ver' => 2]), '');
	}

	public function testAVersionThatIsNotANumberIsRefused(): void
	{
		$this->expectRefusal('not a number');
		$this->bridge->verifyCommand('Bearer ' . $this->command('', ['ver' => 'v1']), '');
	}

	public function testTheVersionIsCheckedBeforeTheIssuer(): void
	{
		/* Order matters: nothing a token asserts should be interpreted before we
		 * know we speak its dialect, and that includes which issuer claim to
		 * compare. */
		$this->expectRefusal('Unsupported contract version');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->command('', ['ver' => 99, 'iss' => 'grn:2@int:grn::environment/g1:wprocket:stranger']),
			''
		);
	}

	public function testATransitionCanAcceptMoreThanOneVersion(): void
	{
		/* For a rollout where a newer signer is already talking to installs that
		 * have not updated. Widening it permanently would defeat the point. */
		$bridge = new Bridge(
			$this->trust,
			$this->keySets,
			$this->nonces,
			(new Config(self::HOST))->withAcceptedVersions([1, 2]),
			$this->clock
		);

		$claims = $bridge->verifyCommand('Bearer ' . $this->command('', ['ver' => 2]), '');

		self::assertSame(2, $claims->get('ver'));
	}

	// --- who signed it ------------------------------------------------------

	public function testAnUnknownIssuerIsRefused(): void
	{
		$this->expectRefusal('Unknown command issuer');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->fleet->sign(
				$this->commandClaims('', ['iss' => 'grn:2@int:grn::environment/g1:wprocket:stranger'])
			),
			''
		);
	}

	public function testAnInstallToldNothingTrustsNobody(): void
	{
		/* The state of a site that has never polled its vendor. Failing open
		 * here would mean every install accepted commands by default. */
		$bridge = new Bridge(
			new ArrayTrustStore(),
			$this->keySets,
			$this->nonces,
			new Config(self::HOST),
			$this->clock
		);

		$this->expectRefusal('No command issuer has been served');
		$bridge->verifyCommand('Bearer ' . $this->command(''), '');
	}

	public function testACommandSignedWithTheVendorsKeyIsRefused(): void
	{
		/* Claiming Fleet's issuer while signing with the vendor's key. It fails
		 * at the *signature*, not at the issuer — which is the property worth
		 * proving: the key is taken from the role's key set, never from
		 * anything the token says. Naming the right issuer buys an attacker
		 * nothing if they cannot sign as it. */
		$this->expectRefusal('Bad signature');
		$this->bridge->verifyCommand('Bearer ' . $this->vendor->sign($this->commandClaims('')), '');
	}

	public function testAGrantSignedWithFleetsKeyIsRefused(): void
	{
		/* The whole point of the second credential. Fleet is the party being
		 * granted the access; a grantee attesting its own grant proves nothing
		 * at all. Fleet's key is not in the consent role's key set, so this
		 * fails however the claims are dressed up. */
		$this->expectRefusal('Bad signature');
		$this->bridge->verifyGrant($this->fleet->sign($this->grantClaims()), 'settings:read');
	}

	public function testACommandClaimingTheConsentIssuerIsRefused(): void
	{
		/* Signed with the right key, but claiming the other role's identity.
		 * Refused at the issuer, before any key is fetched — so the two roles
		 * cannot be collapsed into one even by a party that holds both. */
		$this->expectRefusal('Unknown command issuer');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->fleet->sign($this->commandClaims('', [ 'iss' => self::VENDOR ])),
			''
		);
	}

	public function testAGrantClaimingTheCommandIssuerIsRefused(): void
	{
		$this->expectRefusal('Unknown consent issuer');
		$this->bridge->verifyGrant(
			$this->vendor->sign(array_merge($this->grantClaims(), [ 'iss' => self::FLEET ])),
			'settings:read'
		);
	}

	public function testASignatureFromAnUnpublishedKeyIsRefused(): void
	{
		$impostor = new Signer();

		$this->expectRefusal('Bad signature');
		$this->bridge->verifyCommand('Bearer ' . $impostor->sign($this->commandClaims('')), '');
	}

	public function testAnEmptyKeySetRefusesRatherThanPasses(): void
	{
		/* "We could not fetch the keys" must never read as "no key objected".
		 * A publisher being unreachable is the moment an attacker would choose. */
		$this->keySets->publish(self::FLEET_KEYS, []);

		$this->expectRefusal('No usable key was published');
		$this->bridge->verifyCommand('Bearer ' . $this->command(''), '');
	}

	// --- what it is about ---------------------------------------------------

	public function testATokenNamingAnotherSiteIsRefused(): void
	{
		/* The check that makes a token useless anywhere but here. A licence
		 * covers up to fifty sites; without this, a command minted for one of
		 * them would drive all fifty. */
		$this->expectRefusal('Wrong subject');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->command('', [ 'sub' => 'grn:2@g1:wprocket:site/someone-else.test' ]),
			''
		);
	}

	public function testATokenAddressedElsewhereIsRefused(): void
	{
		$this->expectRefusal('Wrong audience');
		$this->bridge->verifyCommand('Bearer ' . $this->command('', [ 'aud' => 'someone-else.test' ]), '');
	}

	public function testACommandCarryingTheConsentTagIsRefused(): void
	{
		/* A tag says what a token was minted for. Without it, a token the same
		 * issuer minted for another purpose — a login, a snapshot read — could
		 * be spent against a customer's settings on a perfectly good
		 * signature. */
		$this->expectRefusal('Wrong tag: fleet-consent');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->command('', [ 'jti' => 'grn:2@int:grnd::fleet-consent/' . uniqid('', true) ]),
			''
		);
	}

	public function testAMalformedIdentifierIsRefused(): void
	{
		$this->expectRefusal('not a GRND profile GRN');
		$this->bridge->verifyCommand('Bearer ' . $this->command('', [ 'jti' => 'just-a-string' ]), '');
	}

	// --- when it is valid ---------------------------------------------------

	public function testAnExpiredTokenIsRefused(): void
	{
		$token = $this->command('');
		$this->clock->advance(60 + Config::LEEWAY + 1);

		$this->expectRefusal('Expired');
		$this->bridge->verifyCommand('Bearer ' . $token, '');
	}

	public function testATokenFromTheFutureIsRefused(): void
	{
		$this->expectRefusal('Not valid yet');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->command('', [ 'iat' => $this->clock->now() + Config::LEEWAY + 10 ]),
			''
		);
	}

	public function testClockSkewInsideTheLeewayIsTolerated(): void
	{
		/* The signer's machine and this one are operated by different people.
		 * Refusing a token a few seconds out would make management fail on
		 * sites whose clock nobody has ever checked. */
		$claims = $this->bridge->verifyCommand(
			'Bearer ' . $this->command('', [ 'iat' => $this->clock->now() + 30 ]),
			''
		);

		self::assertSame(self::FLEET, $claims->get('iss'));
	}

	public function testATokenAskingForTooLongALifeIsRefused(): void
	{
		/* Capped here rather than trusted from the token: a signer asking for a
		 * year would otherwise get one, and the lifetime is exactly the window
		 * in which an intercepted token stays useful. */
		$now = $this->clock->now();

		$this->expectRefusal('Lifetime exceeds');
		$this->bridge->verifyCommand(
			'Bearer ' . $this->command(
				'',
				[
					'iat' => $now,
					'exp' => $now + Config::MAX_LIFETIME + 1,
				]
			),
			''
		);
	}

	// --- what it covers -----------------------------------------------------

	public function testASwappedBodyIsRefused(): void
	{
		/* Without the digest, a captured header could be replayed against any
		 * body — which on a write endpoint means setting a different option to
		 * a different value. */
		$token = $this->command('{"option_name":"minify_css","option_value":0}');

		$this->expectRefusal('does not match the signed digest');
		$this->bridge->verifyCommand('Bearer ' . $token, '{"option_name":"lazyload","option_value":0}');
	}

	public function testAnEmptyBodyIsStillCovered(): void
	{
		/* A read has no body, but its digest is still over the empty string
		 * rather than absent — so "no body" cannot be substituted for "some
		 * body" by dropping the claim. */
		$this->bridge->verifyCommand('Bearer ' . $this->command(''), '');

		self::assertSame(1, $this->nonces->count());
	}

	// --- scope --------------------------------------------------------------

	public function testAReadGrantDoesNotAuthoriseAWrite(): void
	{
		/* The separation a customer actually asked for: "show me my settings"
		 * without "change them". Without this the level would be decorative. */
		$this->expectRefusal('does not cover settings:write');
		$this->bridge->verifyGrant($this->grant([ 'scope' => [ 'settings:read' ] ]), 'settings:write');
	}

	public function testAGrantWithNoScopeClaimAuthorisesNothing(): void
	{
		$claims = $this->grantClaims();
		unset($claims['scope']);

		$this->expectRefusal('does not cover settings:read');
		$this->bridge->verifyGrant($this->vendor->sign($claims), 'settings:read');
	}

	public function testAMalformedScopeClaimAuthorisesNothing(): void
	{
		$this->expectRefusal('does not cover settings:read');
		$this->bridge->verifyGrant($this->grant([ 'scope' => 'settings:read' ]), 'settings:read');
	}

	// --- single use ---------------------------------------------------------

	public function testATokenIsAcceptedOnceOnly(): void
	{
		$token = 'Bearer ' . $this->command('');

		$this->bridge->verifyCommand($token, '');

		$this->expectRefusal('Already used');
		$this->bridge->verifyCommand($token, '');
	}

	public function testAGrantIsAcceptedOnceOnly(): void
	{
		$grant = $this->grant();

		$this->bridge->verifyGrant($grant, 'settings:read');

		$this->expectRefusal('Already used');
		$this->bridge->verifyGrant($grant, 'settings:read');
	}

	public function testATokenThatFailsACheckIsNotSpent(): void
	{
		/* The identifier is burned last, on purpose. Spending a token that was
		 * about to be refused would let one bad request permanently consume a
		 * good token — and would turn a wrong-scope retry into a dead end. */
		try {
			$this->bridge->verifyGrant($this->grant([ 'scope' => [ 'settings:read' ] ]), 'settings:write');
			self::fail('expected a refusal');
		} catch (NotAuthorised $expected) {
			self::assertSame(0, $this->nonces->count());
		}
	}

	// --- helpers ------------------------------------------------------------

	/**
	 * @param string               $body      Body the command covers.
	 * @param array<string, mixed> $overrides Claim overrides.
	 *
	 * @return string
	 */
	private function command(string $body, array $overrides = []): string
	{
		return $this->fleet->sign($this->commandClaims($body, $overrides));
	}

	/**
	 * @param array<string, mixed> $overrides Claim overrides.
	 *
	 * @return string
	 */
	private function grant(array $overrides = []): string
	{
		return $this->vendor->sign(array_merge($this->grantClaims(), $overrides));
	}

	/**
	 * @param string               $body      Body the command covers.
	 * @param array<string, mixed> $overrides Claim overrides.
	 *
	 * @return array<string, mixed>
	 */
	private function commandClaims(string $body, array $overrides = []): array
	{
		$now = $this->clock->now();

		return array_merge(
			[
				'iss'    => self::FLEET,
				'sub'    => self::SUBJECT,
				'aud'    => self::HOST,
				'iat'    => $now,
				'exp'    => $now + 60,
				'jti'    => 'grn:2@int:grnd::fleet-site/' . uniqid('', true),
				'ver'    => Config::VERSION,
				'digest' => Base64Url::digest($body),
			],
			$overrides
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function grantClaims(): array
	{
		$now = $this->clock->now();

		return [
			'iss'   => self::VENDOR,
			'sub'   => self::SUBJECT,
			'aud'   => self::HOST,
			'iat'   => $now,
			'exp'   => $now + 60,
			'jti'   => 'grn:2@int:grnd::fleet-consent/' . uniqid('', true),
			'ver'   => Config::VERSION,
			'scope' => [ 'settings:read', 'settings:write' ],
		];
	}

	/**
	 * @param string $fragment Expected in the log message, not in any response.
	 *
	 * @return void
	 */
	private function expectRefusal(string $fragment): void
	{
		$this->expectException(NotAuthorised::class);
		$this->expectExceptionMessageMatches('#' . preg_quote($fragment, '#') . '#');
	}
}
