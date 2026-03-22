<?php
declare(strict_types=1);

namespace Hardened\REST;

/**
 * Configuration for REST API scope enforcement.
 *
 * Pure PHP — no WordPress dependencies, fully unit testable.
 */
final class ScopeConfig
{
    /** @var string[] */
    private array $anonymousAllowlist;

    /** @var string[] */
    private array $authenticatedAllowlist;

    public function __construct(array $config)
    {
        $this->anonymousAllowlist = $config['anonymous_allowlist'] ?? [];
        $this->authenticatedAllowlist = $config['authenticated_allowlist'] ?? [];
    }

    /**
     * Check if a route is allowed for the given authentication state.
     *
     * @param string $route          The REST route (e.g., '/wp/v2/posts').
     * @param bool   $authenticated  Whether the requester is authenticated.
     */
    public function isAllowed(string $route, bool $authenticated): bool
    {
        $allowlist = $authenticated ? $this->authenticatedAllowlist : $this->anonymousAllowlist;

        // Wildcard allows everything.
        if (in_array('*', $allowlist, true)) {
            return true;
        }

        // Normalize: strip leading slash and /wp-json prefix.
        $route = ltrim($route, '/');
        $route = preg_replace('#^wp-json/#', '', $route);

        foreach ($allowlist as $pattern) {
            $pattern = ltrim($pattern, '/');

            // Exact namespace match (e.g., 'wp/v2/posts' matches '/wp/v2/posts' and '/wp/v2/posts/123').
            if (str_starts_with($route, $pattern)) {
                return true;
            }

            // Namespace-level match (e.g., 'oembed/1.0' matches '/oembed/1.0/embed').
            if (str_contains($pattern, '*')) {
                $regex = '#^' . str_replace('*', '.*', preg_quote($pattern, '#')) . '#';
                if (preg_match($regex, $route)) {
                    return true;
                }
            }
        }

        return false;
    }
}
