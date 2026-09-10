<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge\Contract;

use WPMedia\FleetBridge\Claims;
use WPMedia\FleetBridge\Exception\NotAuthorised;

/**
 * The two checks a host route performs before it believes a request.
 *
 * `Bridge` is the implementation and is deliberately `final`: verification is
 * security critical, and a subclass that overrides half a check is a hole that
 * looks like a customisation. But a host route that depends on the concrete
 * class cannot be tested — a final class cannot be doubled — and the only way
 * left to exercise a route's own refusals is to sign real tokens in the host's
 * test suite, which tests this package again instead of the route.
 *
 * So hosts depend on this interface. It also leaves room for a host with a
 * genuinely different source of proof to supply its own, without reaching
 * inside anything here.
 *
 * Both methods throw {@see NotAuthorised} and return `Claims` otherwise. There
 * is no boolean-returning variant on purpose: `if ( ! $verifier->check() )` is
 * one forgotten negation away from believing everything, whereas a forgotten
 * `try` fails closed with a 500.
 */
interface Verifier
{
	/**
	 * Verify a command, and that it covers exactly these body bytes.
	 *
	 * @param string $authorization The `Authorization` header, in full.
	 * @param string $body          The raw request body.
	 *
	 * @throws NotAuthorised When the command is not believed.
	 *
	 * @return Claims
	 */
	public function verifyCommand(string $authorization, string $body): Claims;

	/**
	 * Verify a consent grant, and that it carries the scope being used.
	 *
	 * @param string $grant         The grant token.
	 * @param string $requiredScope The scope this request needs.
	 *
	 * @throws NotAuthorised When the grant is not believed, or is too narrow.
	 *
	 * @return Claims
	 */
	public function verifyGrant(string $grant, string $requiredScope): Claims;
}
