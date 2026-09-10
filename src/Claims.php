<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge;

/**
 * The payload of a verified token.
 *
 * Only constructed by {@see Bridge} after verification, so holding one is proof
 * the signature held. A plain array would be indistinguishable from a decoded
 * but unchecked payload, which is the mistake this type exists to make
 * impossible.
 */
final class Claims
{
	/**
	 * @var array<string, mixed>
	 */
	private $claims;

	/**
	 * @param array<string, mixed> $claims Verified payload.
	 */
	public function __construct(array $claims)
	{
		$this->claims = $claims;
	}

	/**
	 * One claim, or a default.
	 *
	 * @param string $name    Claim name.
	 * @param mixed  $default Returned when absent.
	 *
	 * @return mixed
	 */
	public function get(string $name, $default = null)
	{
		return array_key_exists($name, $this->claims) ? $this->claims[ $name ] : $default;
	}

	/**
	 * The identifier this token was spent under.
	 *
	 * @return string
	 */
	public function identifier(): string
	{
		return (string) $this->get('jti', '');
	}

	/**
	 * The capabilities a consent grant carries. Empty for a command.
	 *
	 * @return string[]
	 */
	public function scopes(): array
	{
		$scopes = $this->get('scope', []);

		if (! is_array($scopes)) {
			return [];
		}

		return array_values(array_filter($scopes, 'is_string'));
	}

	/**
	 * Everything, for a log line.
	 *
	 * @return array<string, mixed>
	 */
	public function all(): array
	{
		return $this->claims;
	}
}
