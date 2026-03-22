<?php
declare(strict_types=1);
/**
 * Plugin Name: Hardened: Login Fortress
 * Description: Brute force protection, device fingerprinting, login URL obfuscation, session management.
 * Version:     1.0.0
 *
 * @package Hardened
 */

defined( 'ABSPATH' ) || exit;

$hardened_config = require __DIR__ . '/config/defaults.php';
$login_config    = $hardened_config['login'] ?? [];

// Install schema on first load.
add_action( 'init', static function (): void {
	if ( get_option( 'hardened_schema_version' ) !== '1.0.0' ) {
		require_once __DIR__ . '/migrations/schema.php';
		\Hardened\Migrations\install_schema();
		update_option( 'hardened_schema_version', '1.0.0' );
	}
}, 1 );

// Brute force protection.
$guard = new \Hardened\Login\BruteForceGuard(
	(int) ( $login_config['max_attempts'] ?? 5 ),
	(int) ( $login_config['window_seconds'] ?? 900 ),
	(int) ( $login_config['lockout_seconds'] ?? 1800 )
);

add_filter( 'authenticate', [ $guard, 'check' ], 20, 2 );
add_action( 'wp_login_failed', [ $guard, 'recordFailure' ] );
add_action( 'wp_login', [ $guard, 'clearAttempts' ] );

// Device fingerprinting — new device triggers verification.
$tracker = new \Hardened\Login\DeviceTracker();
add_action( 'wp_login', [ $tracker, 'onLogin' ], 10, 2 );

// Login URL obfuscation.
$custom_slug = $login_config['custom_login_slug'] ?? '';
if ( ! empty( $custom_slug ) ) {
	$obfuscator = new \Hardened\Login\URLObfuscator( $custom_slug );
	add_action( 'init', [ $obfuscator, 'registerRewrite' ] );
	add_filter( 'login_url', [ $obfuscator, 'filterLoginUrl' ], 10, 2 );
	add_action( 'login_init', [ $obfuscator, 'blockDefault' ] );
}

// Session manager.
$session_mgr = new \Hardened\Login\SessionManager(
	(int) ( $login_config['max_sessions'] ?? 3 )
);
add_action( 'wp_login', [ $session_mgr, 'enforceLimit' ], 10, 2 );
