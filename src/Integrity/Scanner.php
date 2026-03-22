<?php
declare(strict_types=1);

namespace Hardened\Integrity;

/**
 * Recursively checksums all PHP files in a directory.
 */
final class Scanner
{
    /**
     * @param string[] $excludePatterns Glob patterns to exclude.
     */
    public function __construct(
        private readonly array $excludePatterns = [],
    ) {}

    /**
     * Scan a directory and return a map of relative_path => sha256_hash.
     *
     * @return array<string, string>
     */
    public function scan(string $directory): array
    {
        $directory = rtrim($directory, '/');
        $checksums = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        /** @var \SplFileInfo $file */
        foreach ($iterator as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }

            $path = $file->getPathname();
            $relative = substr($path, strlen($directory) + 1);

            if ($this->isExcluded($path)) {
                continue;
            }

            $checksums[$relative] = hash_file('sha256', $path);
        }

        ksort($checksums);
        return $checksums;
    }

    private function isExcluded(string $path): bool
    {
        foreach ($this->excludePatterns as $pattern) {
            if (fnmatch($pattern, $path)) {
                return true;
            }
        }
        return false;
    }
}
