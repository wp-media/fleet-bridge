<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Exception;

use RuntimeException;

/**
 * A credential that was offered and must not be honoured.
 *
 * One exception type for every cause, and the message is for a log rather than
 * for a response. A caller is told one fixed thing whatever went wrong: this
 * route is reachable by anyone, so reflecting the reason turns it into an
 * oracle — "unknown issuer" against "bad signature" tells an attacker whether
 * their guessed issuer is the one this site trusts.
 *
 * Callers must catch this and answer with {@see \WPMedia\FleetBridge\Bridge::REFUSED}.
 */
final class NotAuthorised extends RuntimeException
{
}
