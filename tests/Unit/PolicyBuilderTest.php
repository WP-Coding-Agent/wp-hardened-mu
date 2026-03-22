<?php
declare(strict_types=1);

namespace Hardened\Tests\Unit;

use Hardened\CSP\PolicyBuilder;
use PHPUnit\Framework\TestCase;

final class PolicyBuilderTest extends TestCase
{
    public function test_builds_basic_policy(): void
    {
        $builder = new PolicyBuilder([
            'directives' => [
                'default-src' => ["'self'"],
                'script-src'  => ["'self'", 'https://cdn.example.com'],
            ],
        ]);

        $result = $builder->build();

        $this->assertStringContainsString("default-src 'self'", $result);
        $this->assertStringContainsString("script-src 'self' https://cdn.example.com", $result);
    }

    public function test_replaces_nonce_placeholder(): void
    {
        $builder = new PolicyBuilder([
            'directives' => [
                'script-src' => ["'self'", "'nonce-{csp_nonce}'"],
            ],
        ]);

        $builder->setNonce('abc123');
        $result = $builder->build();

        $this->assertStringContainsString("'nonce-abc123'", $result);
        $this->assertStringNotContainsString('{csp_nonce}', $result);
    }

    public function test_includes_report_uri(): void
    {
        $builder = new PolicyBuilder([
            'directives' => ['default-src' => ["'self'"]],
            'report_uri' => '/csp-reports',
        ]);

        $result = $builder->build();
        $this->assertStringContainsString('report-uri /csp-reports', $result);
    }

    public function test_parse_roundtrip(): void
    {
        $input = "default-src 'self'; script-src 'self' https://cdn.example.com; img-src *";
        $parsed = PolicyBuilder::parse($input);

        $this->assertSame(["'self'"], $parsed['default-src']);
        $this->assertSame(["'self'", 'https://cdn.example.com'], $parsed['script-src']);
        $this->assertSame(['*'], $parsed['img-src']);
    }
}
