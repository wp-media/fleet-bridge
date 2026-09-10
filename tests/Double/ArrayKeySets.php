<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests\Double;

use WPMedia\FleetBridge\Contract\KeySets;

/**
 * Key sets from a map, with no HTTP anywhere near a test.
 */
final class ArrayKeySets implements KeySets
{
	/**
	 * @var array<string, array<int, string>>
	 */
	private $sets = [];

	/**
	 * @param string             $url  Where the keys live.
	 * @param array<int, string> $keys Raw 32-byte public keys.
	 *
	 * @return void
	 */
	public function publish(string $url, array $keys): void
	{
		$this->sets[ $url ] = $keys;
	}

	/**
	 * @param string $url Where to look.
	 *
	 * @return array<int, string>
	 */
	public function keys(string $url): array
	{
		return $this->sets[ $url ] ?? [];
	}
}
