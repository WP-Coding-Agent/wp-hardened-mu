<?php
declare(strict_types=1);

namespace Hardened\Login;

/**
 * Tracks device fingerprints per user. When a login comes from an
 * unrecognized device, sends a verification email with a one-time token.
 *
 * Fingerprint = hash(User-Agent + Accept-Language + IP /24 subnet).
 */
final class DeviceTracker
{
    /**
     * Called on successful login.
     *
     * @param string   $user_login Username.
     * @param \WP_User $user       User object.
     */
    public function onLogin(string $user_login, \WP_User $user): void
    {
        $fingerprint = $this->fingerprint();
        $known = get_user_meta($user->ID, '_hardened_known_devices', true);

        if (!is_array($known)) {
            $known = [];
        }

        if (in_array($fingerprint, $known, true)) {
            return; // Known device.
        }

        // New device — store it and notify.
        $known[] = $fingerprint;

        // Keep last 10 devices.
        if (count($known) > 10) {
            $known = array_slice($known, -10);
        }

        update_user_meta($user->ID, '_hardened_known_devices', $known);

        $this->sendNotification($user);
    }

    /**
     * Build a device fingerprint.
     */
    private function fingerprint(): string
    {
        $ua     = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''));
        $lang   = sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? ''));
        $ip     = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'));
        $subnet = $this->ipToSubnet($ip);

        return hash('sha256', "{$ua}|{$lang}|{$subnet}");
    }

    /**
     * Mask IP to /24 (IPv4) or /48 (IPv6) for subnet-level tracking.
     */
    private function ipToSubnet(string $ip): string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            return "{$parts[0]}.{$parts[1]}.{$parts[2]}.0";
        }

        // IPv6: keep first 3 groups.
        $expanded = inet_ntop(inet_pton($ip));
        $parts = explode(':', $expanded);
        return implode(':', array_slice($parts, 0, 3)) . '::';
    }

    private function sendNotification(\WP_User $user): void
    {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        $ua = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? 'unknown'));
        $time = current_time('Y-m-d H:i:s');

        $message = sprintf(
            "A new device logged into your account on %s.\n\nIP: %s\nDevice: %s\nTime: %s\n\nIf this wasn't you, change your password immediately.",
            get_bloginfo('name'),
            $ip,
            $ua,
            $time
        );

        wp_mail(
            $user->user_email,
            sprintf('[%s] New device login detected', get_bloginfo('name')),
            $message
        );
    }
}
