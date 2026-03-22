<?php
declare(strict_types=1);

namespace Hardened\REST;

use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

/**
 * Enforces the REST API allowlist via the rest_pre_dispatch filter.
 */
final class ScopeEnforcer
{
    public function __construct(
        private readonly ScopeConfig $config,
    ) {}

    /**
     * Filter: rest_pre_dispatch.
     *
     * @param mixed            $result
     * @param WP_REST_Server   $server
     * @param WP_REST_Request  $request
     * @return mixed|WP_Error
     */
    public function enforce(mixed $result, WP_REST_Server $server, WP_REST_Request $request): mixed
    {
        if ($result !== null) {
            return $result; // Already handled by another filter.
        }

        $route = $request->get_route();
        $authenticated = is_user_logged_in();

        // Always allow the hardened plugin's own endpoints.
        if (str_starts_with($route, '/hardened/')) {
            return $result;
        }

        if (!$this->config->isAllowed($route, $authenticated)) {
            /**
             * Fires when a REST request is blocked by scope enforcement.
             *
             * @param string $route         The blocked route.
             * @param bool   $authenticated Whether the requester was authenticated.
             */
            do_action('hardened_rest_blocked', $route, $authenticated);

            return new WP_Error(
                'rest_forbidden',
                __('This endpoint is not available.', 'hardened'),
                ['status' => 403]
            );
        }

        return $result;
    }
}
