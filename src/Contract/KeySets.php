<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Contract;

/**
 * Where a publisher's signing keys come from.
 *
 * Injected so this package holds no HTTP and no cache of its own: fetching is
 * the host's business, and a host that already has an HTTP layer with its own
 * timeouts, proxies and telemetry should use it.
 *
 * The one rule an implementation must keep is in the return value's docblock.
 */
interface KeySets
{
	/**
	 * Every Ed25519 public key published at a URL, as raw 32-byte strings.
	 *
	 * A list rather than one key, and that matters: a rotation publishes two at
	 * once so neither side has to be redeployed in step with the other, and
	 * assertions carry no `kid` to select on.
	 *
	 * **An empty list must mean "verify nothing", never "verify anything".** A
	 * failed fetch and a genuinely empty set are the same answer here, and both
	 * make every signature refuse. An implementation that cannot reach the URL
	 * returns an empty list; it must not throw, and it must not guess.
	 *
	 * @param string $url Where to look. Comes from the host's trust store,
	 *                    never from a token.
	 *
	 * @return string[]
	 */
	public function keys(string $url): array;
}
