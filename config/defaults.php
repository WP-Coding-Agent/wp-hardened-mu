<?php
declare(strict_types=1);

/**
 * Default configuration for all Hardened MU-plugins.
 *
 * Override via the 'hardened_config' filter:
 *   add_filter('hardened_config', function($config) { $config['csp']['report_only'] = false; return $config; });
 */

$defaults = [
	'csp' => [
		'report_only' => true,
		'report_uri'  => '/wp-json/hardened/v1/csp-reports',
		'directives'  => [
			'default-src' => ["'self'"],
			'script-src'  => ["'self'", "'nonce-{csp_nonce}'"],
			'style-src'   => ["'self'", "'nonce-{csp_nonce}'", "'unsafe-inline'"],
			'img-src'     => ["'self'", 'data:', 'https:'],
			'font-src'    => ["'self'", 'data:'],
			'connect-src' => ["'self'"],
			'frame-src'   => ["'none'"],
			'object-src'  => ["'none'"],
			'base-uri'    => ["'self'"],
			'form-action' => ["'self'"],
		],
	],

	'login' => [
		'max_attempts'       => 5,
		'window_seconds'     => 900,     // 15 minutes.
		'lockout_seconds'    => 1800,    // 30 minutes.
		'custom_login_slug'  => '',      // e.g. 'my-login' — empty = disabled.
		'max_sessions'       => 3,
	],

	'rest' => [
		'enabled'              => true,
		'block_user_enumeration' => true,
		'anonymous_allowlist'  => [
			'oembed/1.0',
			'wp/v2/posts',
			'wp/v2/pages',
			'wp/v2/categories',
			'wp/v2/tags',
			'wp/v2/media',
		],
		'authenticated_allowlist' => [
			'*', // Authenticated users get full access by default.
		],
	],

	'integrity' => [
		'exclude_patterns' => [
			'*/uploads/*',
			'*/cache/*',
			'*/upgrade/*',
			'*/.git/*',
			'*/node_modules/*',
		],
		'alert_email' => '', // Falls back to admin_email.
	],
];

return apply_filters( 'hardened_config', $defaults );
