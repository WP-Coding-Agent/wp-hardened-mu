<?php
declare(strict_types=1);

namespace Hardened\Integrity;

/**
 * Compares current filesystem state against stored manifests
 * and sends email alerts when changes are detected.
 */
final class Monitor
{
    public function __construct(
        private readonly Scanner $scanner,
        private readonly Manifest $manifest,
        private readonly string $alertEmail,
    ) {}

    /**
     * Run an integrity check on all plugin and theme directories.
     */
    public function runCheck(): void
    {
        $directories = $this->getMonitoredDirectories();
        $allChanges = [];

        foreach ($directories as $dir) {
            $stored = $this->manifest->load($dir);
            if ($stored === null) {
                continue; // No baseline manifest — skip.
            }

            $current = $this->scanner->scan($dir);
            $diff = $this->manifest->diff($dir, $current);

            if (!empty($diff['added']) || !empty($diff['modified']) || !empty($diff['removed'])) {
                $allChanges[$dir] = $diff;
            }
        }

        if (!empty($allChanges)) {
            $this->sendAlert($allChanges);
        }
    }

    /**
     * Check a specific directory and return the diff.
     *
     * @return array{added: string[], modified: string[], removed: string[]}
     */
    public function checkDirectory(string $directory): array
    {
        $current = $this->scanner->scan($directory);
        return $this->manifest->diff($directory, $current);
    }

    /**
     * @return string[]
     */
    private function getMonitoredDirectories(): array
    {
        $dirs = [];

        // Active plugins.
        foreach (get_option('active_plugins', []) as $plugin) {
            $dir = WP_PLUGIN_DIR . '/' . dirname($plugin);
            if (is_dir($dir) && dirname($plugin) !== '.') {
                $dirs[] = $dir;
            }
        }

        // Active theme.
        $dirs[] = get_template_directory();

        if (get_template_directory() !== get_stylesheet_directory()) {
            $dirs[] = get_stylesheet_directory();
        }

        return array_unique($dirs);
    }

    /**
     * @param array<string, array{added: string[], modified: string[], removed: string[]}> $changes
     */
    private function sendAlert(array $changes): void
    {
        $site = get_bloginfo('name');
        $lines = ["File integrity changes detected on {$site}:\n"];

        foreach ($changes as $dir => $diff) {
            $name = basename($dir);
            $lines[] = "--- {$name} ({$dir}) ---";

            foreach ($diff['added'] as $f) {
                $lines[] = "  + ADDED: {$f}";
            }
            foreach ($diff['modified'] as $f) {
                $lines[] = "  ~ MODIFIED: {$f}";
            }
            foreach ($diff['removed'] as $f) {
                $lines[] = "  - REMOVED: {$f}";
            }

            $lines[] = '';
        }

        $lines[] = 'If these changes were not expected (e.g., not a plugin/theme update), investigate immediately.';

        wp_mail(
            $this->alertEmail,
            "[{$site}] File integrity alert — changes detected",
            implode("\n", $lines)
        );
    }
}
