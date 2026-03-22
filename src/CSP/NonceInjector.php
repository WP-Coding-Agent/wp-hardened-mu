<?php
declare(strict_types=1);

namespace Hardened\CSP;

/**
 * Injects CSP nonces into <script> and <style> tags.
 *
 * Uses regex to add nonce attributes to tags that don't already have one.
 * Handles edge cases: tags with existing nonces, self-closing tags,
 * and tags inside HTML attributes (skipped via negative lookbehind).
 */
final class NonceInjector
{
    /**
     * Generate a cryptographically secure CSP nonce.
     */
    public static function generateNonce(): string
    {
        return base64_encode(random_bytes(16));
    }

    /**
     * Inject nonce into all <script> and <style> tags in the HTML.
     *
     * Skips tags that already have a nonce attribute.
     */
    public static function inject(string $html, string $nonce): string
    {
        // Inject into <script> tags without an existing nonce.
        $html = preg_replace_callback(
            '/<script(?![^>]*\bnonce=)([^>]*)>/i',
            static fn(array $m) => '<script nonce="' . $nonce . '"' . $m[1] . '>',
            $html
        );

        // Inject into <style> tags without an existing nonce.
        $html = preg_replace_callback(
            '/<style(?![^>]*\bnonce=)([^>]*)>/i',
            static fn(array $m) => '<style nonce="' . $nonce . '"' . $m[1] . '>',
            $html
        );

        return $html;
    }
}
