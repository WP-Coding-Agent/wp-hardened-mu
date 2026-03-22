<?php
declare(strict_types=1);

namespace Hardened\Migrations;

defined( 'ABSPATH' ) || exit;

function install_schema(): void {
	global $wpdb;
	$charset = $wpdb->get_charset_collate();

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	// CSP violation reports.
	dbDelta( "CREATE TABLE {$wpdb->prefix}hardened_csp_reports (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		directive VARCHAR(255) NOT NULL,
		blocked_uri VARCHAR(2048) NOT NULL DEFAULT '',
		document_uri VARCHAR(2048) NOT NULL DEFAULT '',
		hit_count INT UNSIGNED NOT NULL DEFAULT 1,
		first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		UNIQUE KEY idx_directive_blocked (directive(100), blocked_uri(200))
	) {$charset};" );

	// Login attempt tracking.
	dbDelta( "CREATE TABLE {$wpdb->prefix}hardened_login_attempts (
		ip_address VARCHAR(45) NOT NULL,
		attempts INT UNSIGNED NOT NULL DEFAULT 0,
		first_attempt DATETIME NOT NULL,
		last_attempt DATETIME NOT NULL,
		PRIMARY KEY (ip_address),
		KEY idx_last_attempt (last_attempt)
	) {$charset};" );

	// REST API blocked request log.
	dbDelta( "CREATE TABLE {$wpdb->prefix}hardened_rest_log (
		id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
		route VARCHAR(500) NOT NULL,
		ip_address VARCHAR(45) NOT NULL,
		authenticated TINYINT(1) NOT NULL DEFAULT 0,
		blocked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (id),
		KEY idx_blocked_at (blocked_at)
	) {$charset};" );
}
