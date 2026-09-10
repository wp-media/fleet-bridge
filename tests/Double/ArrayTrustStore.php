<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Tests\Double;

use WPMedia\FleetBridge\Contract\TrustStore;

/**
 * Trust from a map.
 *
 * A role with nothing configured answers empty, which is how a test exercises
 * "this install has not been told anything yet".
 */
final class ArrayTrustStore implements TrustStore
{
	/**
	 * @var array<string, array<string, string>>
	 */
	private $roles = [];

	/**
	 * @param string $role   A role constant.
	 * @param string $issuer Issuer GRN.
	 * @param string $url    Key set URL.
	 *
	 * @return void
	 */
	public function trust(string $role, string $issuer, string $url): void
	{
		$this->roles[ $role ] = [
			'issuer' => $issuer,
			'url'    => $url,
		];
	}

	/**
	 * @param string $role A role constant.
	 *
	 * @return string
	 */
	public function issuer(string $role): string
	{
		return $this->roles[ $role ]['issuer'] ?? '';
	}

	/**
	 * @param string $role A role constant.
	 *
	 * @return string
	 */
	public function keySetUrl(string $role): string
	{
		return $this->roles[ $role ]['url'] ?? '';
	}
}
