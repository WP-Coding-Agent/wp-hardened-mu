<?php
declare(strict_types=1);

namespace Hardened\Integrity;

/**
 * Stores and retrieves file checksum manifests in the database.
 */
final class Manifest
{
    /**
     * Store a manifest for a directory.
     *
     * @param string                $directory  Absolute path.
     * @param array<string, string> $checksums  relative_path => sha256.
     */
    public function store(string $directory, array $checksums): void
    {
        $key = $this->optionKey($directory);
        update_option($key, [
            'checksums'  => $checksums,
            'created_at' => gmdate('c'),
            'file_count' => count($checksums),
        ], false);
    }

    /**
     * Retrieve a stored manifest.
     *
     * @return array{checksums: array<string, string>, created_at: string, file_count: int}|null
     */
    public function load(string $directory): ?array
    {
        $data = get_option($this->optionKey($directory), null);
        return is_array($data) ? $data : null;
    }

    /**
     * Diff current scan against stored manifest.
     *
     * @return array{added: string[], modified: string[], removed: string[]}
     */
    public function diff(string $directory, array $currentChecksums): array
    {
        $stored = $this->load($directory);

        if ($stored === null) {
            return ['added' => array_keys($currentChecksums), 'modified' => [], 'removed' => []];
        }

        $old = $stored['checksums'];

        $added    = array_keys(array_diff_key($currentChecksums, $old));
        $removed  = array_keys(array_diff_key($old, $currentChecksums));
        $modified = [];

        foreach ($currentChecksums as $file => $hash) {
            if (isset($old[$file]) && $old[$file] !== $hash) {
                $modified[] = $file;
            }
        }

        return ['added' => $added, 'modified' => $modified, 'removed' => $removed];
    }

    private function optionKey(string $directory): string
    {
        return 'hardened_manifest_' . md5($directory);
    }
}
