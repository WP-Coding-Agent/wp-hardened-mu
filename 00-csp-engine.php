<?php
declare(strict_types=1);
/**
 * Plugin Name: Hardened: CSP Engine
 * Description: Content Security Policy with automatic nonce injection and violation reporting.
 * Version:     1.0.0
 *
 * @package Hardened
 */

defined( 'ABSPATH' ) || exit;

// Shared autoloader for all hardened MU-plugins.
spl_autoload_register( static function ( string $class ): void {
	$prefix = 'Hardened\\';
	if ( strncmp( $class, $prefix, strlen( $prefix ) ) !== 0 ) {
		return;
	}

	$relative = substr( $class, strlen( $prefix ) );
	$file     = __DIR__ . '/src/' . str_replace( '\\', '/', $relative ) . '.php';

	if ( file_exists( $file ) ) {
		require_once $file;
	}
} );

// Load default configuration.
$hardened_config = require __DIR__ . '/config/defaults.php';

// Initialize CSP engine.
$csp_nonce = \Hardened\CSP\NonceInjector::generateNonce();

add_action( 'send_headers', static function () use ( $hardened_config, $csp_nonce ): void {
	$builder = new \Hardened\CSP\PolicyBuilder( $hardened_config['csp'] ?? [] );
	$builder->setNonce( $csp_nonce );

	$mode = $hardened_config['csp']['report_only'] ?? false;
	$header_name = $mode ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';

	header( "{$header_name}: {$builder->build()}" );
} );

// Output buffer for nonce injection into scripts/styles.
add_action( 'template_redirect', static function () use ( $csp_nonce ): void {
	ob_start( static function ( string $html ) use ( $csp_nonce ): string {
		return \Hardened\CSP\NonceInjector::inject( $html, $csp_nonce );
	} );
} );

// CSP violation report endpoint.
add_action( 'rest_api_init', static function (): void {
	( new \Hardened\CSP\ReportCollector() )->register_routes();
} );

// WP-CLI commands.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'hardened', \Hardened\CLI\HardenedCommand::class );
}
