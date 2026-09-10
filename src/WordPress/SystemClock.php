<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\WordPress;

use WPMedia\FleetBridge\Contract\Clock;

/**
 * The wall clock.
 *
 * `time()` rather than `current_time()`: every timestamp in this exchange is
 * UTC, and WordPress's site-timezone helpers are a way to get that wrong.
 */
final class SystemClock implements Clock
{
	/**
	 * @return int
	 */
	public function now(): int
	{
		return time();
	}
}
