<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Contract;

/**
 * Who this install trusts, and where their keys are published.
 *
 * The host implements this, because where trust comes from is the host's
 * business: WP Rocket reads it from the response its licence API already
 * returns, and another plugin will read it from wherever it already talks to
 * its own vendor.
 *
 * Two roles, and they must be **different issuers**. See
 * {@see \WPMedia\FleetBridge\Bridge} for why that is the whole point.
 *
 * Every method may return an empty string, and empty means **trust nobody** —
 * never "trust anybody". An install that has not yet polled its vendor, or
 * whose vendor has Fleet switched off, is expected to answer empty here and to
 * refuse everything as a result.
 */
interface TrustStore
{
	/**
	 * Fleet, the party that sends commands.
	 */
	public const COMMAND = 'command';

	/**
	 * The licence vendor, the party that vouches for the owner's consent.
	 */
	public const CONSENT = 'consent';

	/**
	 * The issuer GRN accepted for a role.
	 *
	 * Compared against a token's `iss`. The comparison is the only thing that
	 * `iss` is used for — it never selects a key.
	 *
	 * @param string $role One of the constants above.
	 *
	 * @return string Empty when this install has not been told.
	 */
	public function issuer(string $role): string;

	/**
	 * Where that issuer publishes its key set.
	 *
	 * Delivered to the install out of band — over a channel already
	 * authenticated by something other than the key being fetched — so that a
	 * forged `iss` cannot nominate the key that would verify it.
	 *
	 * @param string $role One of the constants above.
	 *
	 * @return string Empty when this install has not been told.
	 */
	public function keySetUrl(string $role): string;
}
