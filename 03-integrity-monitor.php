<?php
declare(strict_types=1);
/**
 * Plugin Name: Hardened: Integrity Monitor
 * Description: Runtime file integrity monitoring with checksum manifests, diff detection, and email alerts.
 * Version:     1.0.0
 *
 * @package Hardened
 */

defined( 'ABSPATH' ) || exit;

$hardened_config = require __DIR__ . '/config/defaults.php';
$integrity_cfg   = $hardened_config['integrity'] ?? [];

// Build manifest on plugin/theme activation.
add_action( 'activated_plugin', static function ( string $plugin ) use ( $integrity_cfg ): void {
	$dir = WP_PLUGIN_DIR . '/' . dirname( $plugin );
	if ( is_dir( $dir ) ) {
		$scanner  = new \Hardened\Integrity\Scanner( $integrity_cfg['exclude_patterns'] ?? [] );
		$manifest = new \Hardened\Integrity\Manifest();
		$manifest->store( $dir, $scanner->scan( $dir ) );
	}
} );

add_action( 'switch_theme', static function () use ( $integrity_cfg ): void {
	$dir = get_template_directory();
	$scanner  = new \Hardened\Integrity\Scanner( $integrity_cfg['exclude_patterns'] ?? [] );
	$manifest = new \Hardened\Integrity\Manifest();
	$manifest->store( $dir, $scanner->scan( $dir ) );
} );

// Periodic integrity check via WP-Cron.
add_action( 'hardened_integrity_check', static function () use ( $integrity_cfg ): void {
	$monitor = new \Hardened\Integrity\Monitor(
		new \Hardened\Integrity\Scanner( $integrity_cfg['exclude_patterns'] ?? [] ),
		new \Hardened\Integrity\Manifest(),
		$integrity_cfg['alert_email'] ?? get_option( 'admin_email' )
	);
	$monitor->runCheck();
} );

if ( ! wp_next_scheduled( 'hardened_integrity_check' ) ) {
	wp_schedule_event( time(), 'twicedaily', 'hardened_integrity_check' );
}
