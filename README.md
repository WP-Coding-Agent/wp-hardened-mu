# WP Hardened MU

Battle-tested MU-plugin collection for WordPress security hardening. Four independent modules, each targeting a specific attack surface.

## Modules

### 00 — CSP Engine

**Threat:** Cross-site scripting (XSS), data injection, clickjacking.

- Generates a per-request CSP nonce and injects it into all `<script>` and `<style>` tags via output buffering
- Builds a complete Content-Security-Policy header from a configurable directive map
- Report-Only mode for safe rollout — violation reports are collected via a REST endpoint
- Deduplication: same directive + blocked URI increments a counter instead of creating duplicate rows
- WP-CLI: `wp hardened csp-violations` to view top violations

### 01 — Login Fortress

**Threat:** Brute force attacks, credential stuffing, session hijacking.

- **Brute force protection** — sliding window IP tracking in a DB table with atomic `INSERT ON DUPLICATE KEY UPDATE`. Auto-locks IPs after N failed attempts
- **Device fingerprinting** — hashes User-Agent + Accept-Language + IP /24 subnet. New devices trigger an email notification to the account owner
- **Login URL obfuscation** — moves `wp-login.php` to a custom slug; original URL returns 404
- **Session management** — enforces max concurrent sessions per user, destroys oldest on overflow

### 02 — REST API Scope

**Threat:** Information disclosure, user enumeration, unauthorized API access.

- Allowlist-based: blocks ALL REST endpoints except explicitly allowed ones
- Separate allowlists for anonymous and authenticated users
- Removes `/wp/v2/users` endpoint for unauthenticated requests (prevents user enumeration)
- Namespace-level and route-level matching with wildcard support

### 03 — Integrity Monitor

**Threat:** Backdoors, file tampering, supply chain compromise.

- Checksums all PHP files on plugin/theme activation, stores manifests in the database
- Periodic cron-based rescans detect: new files, modified files, deleted files
- Email alerts on any change detected outside of a legitimate update
- Configurable exclusion patterns (uploads, cache dirs, etc.)
- WP-CLI: `wp hardened integrity-check` and `wp hardened rebuild-manifest`

## Installation

```bash
# Copy all files to wp-content/mu-plugins/
cp -r wp-hardened-mu/* /path/to/wp-content/mu-plugins/
```

MU-plugins load automatically — no activation needed.

## Configuration

Override defaults via the `hardened_config` filter in a separate MU-plugin or `functions.php`:

```php
add_filter('hardened_config', function (array $config): array {
    // Switch CSP from report-only to enforce.
    $config['csp']['report_only'] = false;

    // Custom login URL.
    $config['login']['custom_login_slug'] = 'my-secret-login';
    $config['login']['max_attempts'] = 3;

    // Tighten anonymous REST access.
    $config['rest']['anonymous_allowlist'] = ['wp/v2/posts', 'wp/v2/pages'];

    return $config;
});
```

## WP-CLI

```bash
wp hardened csp-violations               # Top CSP violations
wp hardened integrity-check              # Run integrity scan
wp hardened integrity-check /path/to/dir # Check specific directory
wp hardened rebuild-manifest /path/to/dir # Rebuild checksum baseline
```

## License

GPL-2.0-or-later
