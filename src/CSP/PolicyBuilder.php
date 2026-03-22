<?php
declare(strict_types=1);

namespace Hardened\CSP;

/**
 * Builds a Content-Security-Policy header string from a directive map.
 *
 * Pure PHP — no WordPress dependencies.
 */
final class PolicyBuilder
{
    private string $nonce = '';

    /**
     * @param array{directives?: array<string, string[]>, report_uri?: string} $config
     */
    public function __construct(
        private readonly array $config,
    ) {}

    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }

    /**
     * Build the full CSP header value.
     */
    public function build(): string
    {
        $directives = $this->config['directives'] ?? [];
        $parts = [];

        foreach ($directives as $directive => $sources) {
            $resolved = array_map(
                fn(string $src) => str_replace('{csp_nonce}', $this->nonce, $src),
                $sources
            );
            $parts[] = $directive . ' ' . implode(' ', $resolved);
        }

        $reportUri = $this->config['report_uri'] ?? '';
        if (!empty($reportUri)) {
            $parts[] = 'report-uri ' . $reportUri;
        }

        return implode('; ', $parts);
    }

    /**
     * Parse a CSP header string back into a directive map.
     * Useful for testing and validation.
     *
     * @return array<string, string[]>
     */
    public static function parse(string $header): array
    {
        $result = [];
        $directives = explode(';', $header);

        foreach ($directives as $directive) {
            $directive = trim($directive);
            if (empty($directive)) {
                continue;
            }

            $parts = preg_split('/\s+/', $directive);
            $name = array_shift($parts);
            $result[$name] = $parts;
        }

        return $result;
    }
}
