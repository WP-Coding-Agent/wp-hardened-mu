<?php
declare(strict_types=1);

namespace Hardened\Login;

/**
 * Enforces a maximum number of concurrent sessions per user.
 * When the limit is exceeded, the oldest session is destroyed.
 */
final class SessionManager
{
    public function __construct(
        private readonly int $maxSessions = 3,
    ) {}

    /**
     * Called on wp_login — enforce session limit.
     *
     * @param string   $user_login
     * @param \WP_User $user
     */
    public function enforceLimit(string $user_login, \WP_User $user): void
    {
        $manager = \WP_Session_Tokens::get_instance($user->ID);
        $sessions = $manager->get_all();

        if (count($sessions) <= $this->maxSessions) {
            return;
        }

        // Sort by login time (ascending) and destroy the oldest.
        uasort($sessions, static function (array $a, array $b): int {
            return ($a['login'] ?? 0) <=> ($b['login'] ?? 0);
        });

        $tokens = array_keys($sessions);
        $to_destroy = count($sessions) - $this->maxSessions;

        for ($i = 0; $i < $to_destroy; $i++) {
            $manager->destroy($tokens[$i]);
        }
    }
}
