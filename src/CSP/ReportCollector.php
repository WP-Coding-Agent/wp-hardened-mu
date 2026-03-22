<?php
declare(strict_types=1);

namespace Hardened\CSP;

use WP_REST_Controller;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

/**
 * REST endpoint that receives CSP violation reports from browsers.
 *
 * Stores reports in a DB table with deduplication: same directive + blocked URI
 * increments a counter rather than creating a new row.
 */
final class ReportCollector extends WP_REST_Controller
{
    protected $namespace = 'hardened/v1';
    protected $rest_base = 'csp-reports';

    public function register_routes(): void
    {
        register_rest_route($this->namespace, '/' . $this->rest_base, [
            [
                'methods'             => WP_REST_Server::CREATABLE,
                'callback'            => [$this, 'receive_report'],
                'permission_callback' => '__return_true', // Browsers send reports anonymously.
            ],
            [
                'methods'             => WP_REST_Server::READABLE,
                'callback'            => [$this, 'list_reports'],
                'permission_callback' => fn() => current_user_can('manage_options'),
                'args'                => [
                    'limit' => ['type' => 'integer', 'default' => 50, 'maximum' => 200],
                ],
            ],
        ]);
    }

    public function receive_report(WP_REST_Request $request): WP_REST_Response
    {
        global $wpdb;
        $table = $wpdb->prefix . 'hardened_csp_reports';

        $body = json_decode($request->get_body(), true);
        $report = $body['csp-report'] ?? $body;

        if (empty($report)) {
            return new WP_REST_Response(null, 204);
        }

        $directive  = sanitize_text_field($report['violated-directive'] ?? $report['effectiveDirective'] ?? '');
        $blocked    = esc_url_raw($report['blocked-uri'] ?? $report['blockedURL'] ?? '');
        $document   = esc_url_raw($report['document-uri'] ?? $report['documentURL'] ?? '');

        if (empty($directive)) {
            return new WP_REST_Response(null, 204);
        }

        // Upsert with deduplication — same directive+blocked_uri increments counter.
        $existing = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id FROM {$table} WHERE directive = %s AND blocked_uri = %s LIMIT 1",
                $directive,
                $blocked
            )
        );

        if ($existing) {
            $wpdb->query(
                $wpdb->prepare(
                    "UPDATE {$table} SET hit_count = hit_count + 1, last_seen = NOW() WHERE id = %d",
                    $existing
                )
            );
        } else {
            $wpdb->insert($table, [
                'directive'    => $directive,
                'blocked_uri'  => $blocked,
                'document_uri' => $document,
                'hit_count'    => 1,
            ], ['%s', '%s', '%s', '%d']);
        }

        return new WP_REST_Response(null, 204);
    }

    public function list_reports(WP_REST_Request $request): WP_REST_Response
    {
        global $wpdb;
        $table = $wpdb->prefix . 'hardened_csp_reports';
        $limit = $request->get_param('limit');

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT directive, blocked_uri, document_uri, hit_count, last_seen
                 FROM {$table} ORDER BY hit_count DESC LIMIT %d",
                $limit
            ),
            ARRAY_A
        );

        return new WP_REST_Response($rows ?: []);
    }
}
