<?php

declare(strict_types=1);

namespace WPMedia\FleetBridge;

/**
 * What this install considers a valid token, beyond the signature.
 *
 * Immutable and fluent rather than a long constructor: this package targets PHP
 * 7.4, so there are no named arguments, and a seven-argument constructor is a
 * seven-argument mistake waiting to happen.
 *
 * Every default is the protocol's own value. A host normally writes
 * `new Config( $host )` and nothing else; the setters exist for a brand whose
 * GRN namespace differs, and for tests.
 */
final class Config
{
	/**
	 * The GRND tag a command carries.
	 *
	 * A tag says what a token was minted for. Checking it stops a token the
	 * same issuer minted for another purpose — a login, a snapshot read — from
	 * being spent against a customer's site, even though its signature is
	 * perfectly good.
	 */
	public const COMMAND_TAG = 'fleet-site';

	/**
	 * The GRND tag a consent grant carries. Distinct from the command tag, so
	 * a command cannot be presented as its own consent.
	 */
	public const CONSENT_TAG = 'fleet-consent';

	/**
	 * The resource a token must claim control over, with this site's host in it.
	 */
	public const SUBJECT_TEMPLATE = 'grn:2@g1:wprocket:site/%s';

	/**
	 * Longest token worth parsing, in bytes. A structural check before any
	 * decoding, so a megabyte of base64 costs a strlen rather than a parse.
	 */
	/**
	 * The contract version this package speaks.
	 *
	 * Bumped when the *meaning* of the exchange changes — a new required claim,
	 * a renamed one, a different subject shape, a check that becomes stricter.
	 * Not bumped for anything a v1 verifier would still get right.
	 */
	public const VERSION = 1;

	public const MAX_BYTES = 8192;

	/**
	 * Longest lifetime accepted, in seconds. The window in which an intercepted
	 * token stays useful, so it is capped here rather than trusted from the
	 * token.
	 */
	public const MAX_LIFETIME = 300;

	/**
	 * Clock skew tolerated, in seconds. Generous, because the signer's machine
	 * and this one are operated by different people and an unsynchronised clock
	 * is common.
	 */
	public const LEEWAY = 60;

	/**
	 * @var string
	 */
	private $host;

	/**
	 * @var string
	 */
	private $commandTag = self::COMMAND_TAG;

	/**
	 * @var string
	 */
	private $consentTag = self::CONSENT_TAG;

	/**
	 * @var string
	 */
	private $subjectTemplate = self::SUBJECT_TEMPLATE;

	/**
	 * @var int
	 */
	private $maxLifetime = self::MAX_LIFETIME;

	/**
	 * @var int
	 */
	private $leeway = self::LEEWAY;

	/**
	 * @var array<int, int>
	 */
	private $acceptedVersions = [ self::VERSION ];

	/**
	 * @param string $host This site's identity: its host, **without a port**.
	 *                     Both sides derive the same string from it, which is
	 *                     what makes a mismatch a refusal rather than a
	 *                     silently wrong write.
	 */
	public function __construct(string $host)
	{
		$this->host = strtolower(trim($host));
	}

	/**
	 * @return string
	 */
	public function host(): string
	{
		return $this->host;
	}

	/**
	 * The subject a token must name to be about this site.
	 *
	 * @return string
	 */
	public function subject(): string
	{
		return sprintf($this->subjectTemplate, $this->host);
	}

	/**
	 * @return string
	 */
	public function commandTag(): string
	{
		return $this->commandTag;
	}

	/**
	 * @return string
	 */
	public function consentTag(): string
	{
		return $this->consentTag;
	}

	/**
	 * @return int
	 */
	public function maxLifetime(): int
	{
		return $this->maxLifetime;
	}

	/**
	 * @return int
	 */
	public function leeway(): int
	{
		return $this->leeway;
	}

	/**
	 * The contract versions this install will honour.
	 *
	 * @return array<int, int>
	 */
	public function acceptedVersions(): array
	{
		return $this->acceptedVersions;
	}

	/**
	 * Accept more than one contract version, during a transition.
	 *
	 * The only reason to call this is a rollout where a newer signer is talking
	 * to installs that have not updated yet. Widening it permanently defeats the
	 * point of having a version at all.
	 *
	 * @param array<int, int> $versions Versions to honour.
	 *
	 * @return self
	 */
	public function withAcceptedVersions(array $versions): self
	{
		$clone                   = clone $this;
		$clone->acceptedVersions = array_values(array_unique(array_map('intval', $versions)));

		return $clone;
	}

	/**
	 * @param string $template A `sprintf` template taking the host.
	 *
	 * @return self
	 */
	public function withSubjectTemplate(string $template): self
	{
		$clone                  = clone $this;
		$clone->subjectTemplate = $template;

		return $clone;
	}

	/**
	 * @param string $command Tag for a command.
	 * @param string $consent Tag for a consent grant.
	 *
	 * @return self
	 */
	public function withTags(string $command, string $consent): self
	{
		$clone             = clone $this;
		$clone->commandTag = $command;
		$clone->consentTag = $consent;

		return $clone;
	}

	/**
	 * @param int $maxLifetime Seconds.
	 * @param int $leeway      Seconds.
	 *
	 * @return self
	 */
	public function withWindow(int $maxLifetime, int $leeway): self
	{
		$clone              = clone $this;
		$clone->maxLifetime = $maxLifetime;
		$clone->leeway      = $leeway;

		return $clone;
	}
}
