<?php
declare(strict_types=1);

namespace Hardened\Login;

/**
 * Moves wp-login.php to a custom URL slug.
 * Requests to the default login URL return a 404.
 */
final class URLObfuscator
{
    public function __construct(
        private readonly string $customSlug,
    ) {}

    public function registerRewrite(): void
    {
        add_rewrite_rule(
            '^' . preg_quote($this->customSlug, '/') . '/?$',
            'wp-login.php',
            'top'
        );
    }

    /**
     * Filter the login URL to use the custom slug.
     */
    public function filterLoginUrl(string $login_url, string $redirect): string
    {
        return home_url($this->customSlug) . ($redirect ? '?redirect_to=' . urlencode($redirect) : '');
    }

    /**
     * Block direct access to wp-login.php unless coming via the custom slug.
     */
    public function blockDefault(): void
    {
        $request_uri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? ''));

        // Allow if the request came via the custom slug rewrite.
        if (strpos($request_uri, $this->customSlug) !== false) {
            return;
        }

        // Allow POST requests (form submissions already in progress).
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            return;
        }

        // Allow specific actions that need to work (logout, postpass).
        $allowed_actions = ['logout', 'postpass', 'rp', 'resetpass', 'confirmaction'];
        $action = sanitize_text_field($_GET['action'] ?? '');
        if (in_array($action, $allowed_actions, true)) {
            return;
        }

        // Block: return 404.
        status_header(404);
        nocache_headers();
        include get_404_template();
        exit;
    }
}
