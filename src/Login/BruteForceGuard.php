<?php
declare(strict_types=1);

namespace Hardened\Login;

/**
 * Brute force protection with a sliding window counter stored in a DB table.
 *
 * Uses INSERT ... ON DUPLICATE KEY UPDATE for atomic counter increments,
 * and periodic cleanup of expired rows.
 */
final class BruteForceGuard
{
    public function __construct(
        private readonly int $maxAttempts = 5,
        private readonly int $windowSeconds = 900,
        private readonly int $lockoutSeconds = 1800,
    ) {}

    /**
     * WordPress 'authenticate' filter — block if IP is locked out.
     *
     * @param mixed  $user
     * @param string $username
     * @return mixed|\WP_Error
     */
    public function check(mixed $user, string $username): mixed
    {
        if (empty($username)) {
            return $user;
        }

        $ip = $this->getClientIp();
        $attempts = $this->getAttempts($ip);

        if ($attempts >= $this->maxAttempts) {
            return new \WP_Error(
                'hardened_locked_out',
                sprintf(
                    __('Too many failed login attempts. Try again in %d minutes.', 'hardened'),
                    (int) ceil($this->lockoutSeconds / 60)
                )
            );
        }

        return $user;
    }

    public function recordFailure(): void
    {
        global $wpdb;
        $table = $wpdb->prefix . 'hardened_login_attempts';
        $ip = $this->getClientIp();
        $now = current_time('mysql', true);

        // Atomic upsert: increment if exists, insert if new.
        $wpdb->query(
            $wpdb->prepare(
                "INSERT INTO {$table} (ip_address, attempts, first_attempt, last_attempt)
                 VALUES (%s, 1, %s, %s)
                 ON DUPLICATE KEY UPDATE
                    attempts = IF(TIMESTAMPDIFF(SECOND, first_attempt, %s) > %d, 1, attempts + 1),
                    first_attempt = IF(TIMESTAMPDIFF(SECOND, first_attempt, %s) > %d, %s, first_attempt),
                    last_attempt = %s",
                $ip, $now, $now,
                $now, $this->windowSeconds,
                $now, $this->windowSeconds, $now,
                $now
            )
        );
    }

    public function clearAttempts(): void
    {
        global $wpdb;
        $table = $wpdb->prefix . 'hardened_login_attempts';
        $ip = $this->getClientIp();

        $wpdb->delete($table, ['ip_address' => $ip], ['%s']);
    }

    private function getAttempts(string $ip): int
    {
        global $wpdb;
        $table = $wpdb->prefix . 'hardened_login_attempts';
        $cutoff = gmdate('Y-m-d H:i:s', time() - $this->lockoutSeconds);

        $attempts = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT attempts FROM {$table} WHERE ip_address = %s AND last_attempt > %s",
                $ip,
                $cutoff
            )
        );

        return (int) ($attempts ?? 0);
    }

    private function getClientIp(): string
    {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));
        return filter_var($ip, FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }
}
