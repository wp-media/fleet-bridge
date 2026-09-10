<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\WordPress;

use WPMedia\FleetBridge\Contract\NonceStore;

/**
 * Spent identifiers, in the options table, atomically.
 *
 * ## Why not a transient
 *
 * The obvious implementation is `get_transient()` then `set_transient()`, and
 * it is wrong twice over.
 *
 * It is not atomic: two requests carrying one identifier can both read "unused"
 * before either writes, and both are honoured. That is precisely the replay
 * this class exists to prevent, and it is reachable by anyone who can send two
 * requests at once.
 *
 * And on a site with a non-persistent object cache — the WordPress default —
 * transients live in this same table anyway, so the indirection buys nothing.
 *
 * A single `INSERT` relying on the unique index on `option_name` is atomic in
 * the database, which is the only place it can be. Whoever's insert lands is
 * the one caller told the identifier was unused.
 *
 * ## Growth
 *
 * A row per credential honoured — so two per request for a host that checks
 * both a command and a grant. It grows with real usage rather than with
 * traffic: a refused token is never recorded, and nothing is written unless a
 * request was believed.
 *
 * Rows are written with `autoload = 'no'`, so however many there are they
 * never reach an ordinary page load. **A host must schedule
 * {@see self::purge()}**, which deletes everything already expired; it is safe
 * to call at any interval and safe to call twice, and the expiry lives in the
 * row's value so no separate timeout row is needed. Nothing here depends on it
 * for correctness — an expired token is refused on its own `exp` whether or
 * not its row is still present — so a host that forgets pays in table size and
 * never in permission.
 */
final class WpdbNonceStore implements NonceStore
{
	/**
	 * Prefix for the option name. Long enough to be greppable in a table
	 * someone is debugging, short enough to leave room for a hash.
	 */
	public const PREFIX = 'fleet_bridge_jti_';

	/**
	 * Record an identifier as used, and say whether it was already.
	 *
	 * @param string $identifier The `jti`.
	 * @param int    $ttl        Seconds to remember it.
	 *
	 * @return bool True when this call is the first to spend it.
	 */
	public function spend(string $identifier, int $ttl): bool
	{
		global $wpdb;

		// Hashed rather than stored raw: an identifier is a GRN containing
		// slashes and colons, and `option_name` is only 191 bytes on a utf8mb4
		// index. A hash is fixed width and collision-free enough that two
		// distinct identifiers colliding is not a scenario worth designing for.
		$name    = self::PREFIX . hash('sha256', $identifier);
		$expires = time() + max($ttl, 1);

		// `INSERT IGNORE` rather than a read followed by a write: the unique
		// index on option_name is what makes this a single atomic decision.
		// `rows_affected` is 1 for the caller who won and 0 for everyone else.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} ( option_name, option_value, autoload ) VALUES ( %s, %s, 'no' )",
				$name,
				(string) $expires
			)
		);

		return 1 === (int) $wpdb->rows_affected;
	}

	/**
	 * Delete every identifier that has expired anyway.
	 *
	 * Safe to run at any interval and safe to run twice. Nothing depends on it
	 * for correctness — an expired token is refused on its `exp` whether or not
	 * its row is still here — so this is housekeeping, not enforcement.
	 *
	 * @return int Rows deleted.
	 */
	public static function purge(): int
	{
		global $wpdb;

		return (int) $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST( option_value AS UNSIGNED ) < %d",
				$wpdb->esc_like(self::PREFIX) . '%',
				time()
			)
		);
	}
}
