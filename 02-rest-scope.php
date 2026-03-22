<?php
declare(strict_types=1);
/**
 * Plugin Name: Hardened: REST API Scope
 * Description: Allowlist-based REST API surface reduction with per-role controls.
 * Version:     1.0.0
 *
 * @package Hardened
 */

defined( 'ABSPATH' ) || exit;

$hardened_config = require __DIR__ . '/config/defaults.php';
$rest_config     = $hardened_config['rest'] ?? [];

if ( ! empty( $rest_config['enabled'] ) ) {
	$config   = new \Hardened\REST\ScopeConfig( $rest_config );
	$enforcer = new \Hardened\REST\ScopeEnforcer( $config );

	add_filter( 'rest_pre_dispatch', [ $enforcer, 'enforce' ], 10, 3 );

	// Remove user enumeration for anonymous requests.
	add_filter( 'rest_endpoints', static function ( array $endpoints ) use ( $rest_config ): array {
		if ( is_user_logged_in() || empty( $rest_config['block_user_enumeration'] ) ) {
			return $endpoints;
		}

		unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\\d]+)'] );
		return $endpoints;
	} );
}
