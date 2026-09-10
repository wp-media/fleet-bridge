<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Contract;

/**
 * What time it is, injectable.
 *
 * Exists so expiry and skew can be tested at a chosen instant rather than by
 * sleeping. Every freshness rule in this package reads the clock through here.
 */
interface Clock
{
	/**
	 * The current Unix timestamp.
	 *
	 * @return int
	 */
	public function now(): int;
}
