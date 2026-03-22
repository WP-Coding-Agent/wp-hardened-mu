<?php
declare(strict_types=1);

namespace Hardened\CLI;

use Hardened\CSP\ReportCollector;
use Hardened\Integrity\Manifest;
use Hardened\Integrity\Monitor;
use Hardened\Integrity\Scanner;
use WP_CLI;

/**
 * Manage Hardened security modules.
 */
final class HardenedCommand
{
    /**
     * Show top CSP violations.
     *
     * ## OPTIONS
     *
     * [--limit=<limit>]
     * : Number of violations to show. Default: 20.
     *
     * ## EXAMPLES
     *
     *     wp hardened csp-violations
     */
    public function csp_violations(array $args, array $assoc_args): void // phpcs:ignore
    {
        global $wpdb;
        $table = $wpdb->prefix . 'hardened_csp_reports';
        $limit = (int) ($assoc_args['limit'] ?? 20);

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT directive, blocked_uri, hit_count, last_seen FROM {$table} ORDER BY hit_count DESC LIMIT %d",
                $limit
            ),
            ARRAY_A
        );

        if (empty($rows)) {
            WP_CLI::log('No CSP violations recorded.');
            return;
        }

        \WP_CLI\Utils\format_items('table', $rows, ['directive', 'blocked_uri', 'hit_count', 'last_seen']);
    }

    /**
     * Run a file integrity check against stored manifests.
     *
     * ## OPTIONS
     *
     * [<directory>]
     * : Specific directory to check. Default: all monitored directories.
     *
     * ## EXAMPLES
     *
     *     wp hardened integrity-check
     *     wp hardened integrity-check /var/www/html/wp-content/plugins/my-plugin
     */
    public function integrity_check(array $args): void // phpcs:ignore
    {
        $config = (require __DIR__ . '/../config/defaults.php')['integrity'] ?? [];
        $scanner = new Scanner($config['exclude_patterns'] ?? []);
        $manifest = new Manifest();

        if (!empty($args[0])) {
            $dir = rtrim($args[0], '/');
            if (!is_dir($dir)) {
                WP_CLI::error("Directory not found: {$dir}");
            }

            $current = $scanner->scan($dir);
            $diff = $manifest->diff($dir, $current);
            $this->printDiff(basename($dir), $diff);
            return;
        }

        $monitor = new Monitor(
            $scanner,
            $manifest,
            $config['alert_email'] ?? get_option('admin_email')
        );

        WP_CLI::log('Running integrity check on all monitored directories...');
        $monitor->runCheck();
        WP_CLI::success('Integrity check complete.');
    }

    /**
     * Rebuild the checksum manifest for a directory.
     *
     * ## OPTIONS
     *
     * <directory>
     * : Directory to scan and store a manifest for.
     *
     * ## EXAMPLES
     *
     *     wp hardened rebuild-manifest /var/www/html/wp-content/plugins/my-plugin
     */
    public function rebuild_manifest(array $args): void // phpcs:ignore
    {
        $dir = rtrim($args[0], '/');
        if (!is_dir($dir)) {
            WP_CLI::error("Directory not found: {$dir}");
        }

        $config = (require __DIR__ . '/../config/defaults.php')['integrity'] ?? [];
        $scanner = new Scanner($config['exclude_patterns'] ?? []);
        $manifest = new Manifest();

        $checksums = $scanner->scan($dir);
        $manifest->store($dir, $checksums);

        WP_CLI::success(sprintf('Manifest rebuilt: %d files checksummed in %s', count($checksums), basename($dir)));
    }

    private function printDiff(string $name, array $diff): void
    {
        $total = count($diff['added']) + count($diff['modified']) + count($diff['removed']);

        if ($total === 0) {
            WP_CLI::success("{$name}: No changes detected.");
            return;
        }

        WP_CLI::warning("{$name}: {$total} change(s) detected.");
        foreach ($diff['added'] as $f) {
            WP_CLI::log("  + ADDED: {$f}");
        }
        foreach ($diff['modified'] as $f) {
            WP_CLI::log("  ~ MODIFIED: {$f}");
        }
        foreach ($diff['removed'] as $f) {
            WP_CLI::log("  - REMOVED: {$f}");
        }
    }
}
