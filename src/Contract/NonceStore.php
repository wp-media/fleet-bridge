<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Contract;

/**
 * Where a spent assertion identifier is remembered.
 *
 * Injected rather than assumed, because the store decides how strong single-use
 * actually is. A non-persistent object cache that gets flushed inside a token's
 * lifetime weakens replay protection, and a host that cares can supply
 * something durable instead.
 */
interface NonceStore
{
	/**
	 * Record an identifier as used, and say whether it was already.
	 *
	 * Must be atomic against a concurrent caller: two simultaneous requests
	 * carrying one identifier must not both be told it was unused. An
	 * implementation that cannot guarantee that has to say so, because this is
	 * the whole of the replay protection.
	 *
	 * @param string $identifier The `jti`.
	 * @param int    $ttl        Seconds to remember it — its remaining lifetime,
	 *                           after which it is refused on expiry anyway.
	 *
	 * @return bool True when this call is the first to spend it.
	 */
	public function spend(string $identifier, int $ttl): bool;
}
