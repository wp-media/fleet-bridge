<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests\Double;

use WPMedia\FleetBridge\Contract\Clock;

/**
 * A clock that says whatever the test needs.
 *
 * Every freshness rule reads the clock, so expiry and skew are tested at a
 * chosen instant rather than by sleeping.
 */
final class FixedClock implements Clock
{
	/**
	 * @var int
	 */
	private $now;

	/**
	 * @param int $now Fixed timestamp.
	 */
	public function __construct(int $now = 1700000000)
	{
		$this->now = $now;
	}

	/**
	 * @return int
	 */
	public function now(): int
	{
		return $this->now;
	}

	/**
	 * @param int $seconds Move the clock forward.
	 *
	 * @return void
	 */
	public function advance(int $seconds): void
	{
		$this->now += $seconds;
	}
}
