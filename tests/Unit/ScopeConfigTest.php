<?php
declare(strict_types=1);

namespace Hardened\Tests\Unit;

use Hardened\REST\ScopeConfig;
use PHPUnit\Framework\TestCase;

final class ScopeConfigTest extends TestCase
{
    public function test_wildcard_allows_everything(): void
    {
        $config = new ScopeConfig(['authenticated_allowlist' => ['*']]);
        $this->assertTrue($config->isAllowed('/wp/v2/posts', true));
        $this->assertTrue($config->isAllowed('/custom/v1/anything', true));
    }

    public function test_anonymous_blocked_by_default(): void
    {
        $config = new ScopeConfig([
            'anonymous_allowlist' => ['wp/v2/posts'],
        ]);

        $this->assertTrue($config->isAllowed('/wp/v2/posts', false));
        $this->assertTrue($config->isAllowed('/wp/v2/posts/123', false));
        $this->assertFalse($config->isAllowed('/wp/v2/users', false));
    }

    public function test_namespace_prefix_matching(): void
    {
        $config = new ScopeConfig([
            'anonymous_allowlist' => ['oembed/1.0'],
        ]);

        $this->assertTrue($config->isAllowed('/oembed/1.0/embed', false));
        $this->assertFalse($config->isAllowed('/wp/v2/posts', false));
    }

    public function test_empty_allowlist_blocks_all(): void
    {
        $config = new ScopeConfig(['anonymous_allowlist' => []]);
        $this->assertFalse($config->isAllowed('/wp/v2/posts', false));
    }

    public function test_authenticated_vs_anonymous(): void
    {
        $config = new ScopeConfig([
            'anonymous_allowlist' => ['wp/v2/posts'],
            'authenticated_allowlist' => ['*'],
        ]);

        $this->assertFalse($config->isAllowed('/wp/v2/users', false));
        $this->assertTrue($config->isAllowed('/wp/v2/users', true));
    }
}
