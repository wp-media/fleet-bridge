<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests\Double;

use WPMedia\FleetBridge\Contract\NonceStore;

/**
 * Spent identifiers in memory.
 *
 * Records what was spent so a test can assert that a token which failed a check
 * was **not** spent — the difference between "refused and retryable" and
 * "refused and burned".
 */
final class ArrayNonceStore implements NonceStore
{
	/**
	 * @var array<string, int>
	 */
	private $spent = [];

	/**
	 * @param string $identifier The `jti`.
	 * @param int    $ttl        Ignored; nothing expires in memory.
	 *
	 * @return bool
	 */
	public function spend(string $identifier, int $ttl): bool
	{
		if (isset($this->spent[ $identifier ])) {
			return false;
		}

		$this->spent[ $identifier ] = $ttl;

		return true;
	}

	/**
	 * @return int
	 */
	public function count(): int
	{
		return count($this->spent);
	}
}
