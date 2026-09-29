<?php

declare(strict_types=1);

/**
 * Gedeelde PHP-sessie-instellingen voor login en Asclepius.
 * Moet vóór session_start() worden aangeroepen.
 */
function configure_app_session(): void
{
    static $configured = false;
    if ($configured) {
        return;
    }

    $configured = true;

    // Cookie/ini-params kunnen niet meer als de sessie al loopt (bijv. app bootstrap
    // die session_start() vóór login/lib.php aanroept). Dan veilig no-op.
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    // Standaard 24 uur; overschrijf via env ASCLEPIUS_SESSION_LIFETIME (seconden).
    $lifetime = (int) (getenv('ASCLEPIUS_SESSION_LIFETIME') ?: 86400);
    if ($lifetime < 300) {
        $lifetime = 300;
    }
    if ($lifetime > 604800) {
        $lifetime = 604800;
    }

    ini_set('session.use_trans_sid', '0');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', (string) $lifetime);

    session_set_cookie_params([
        'lifetime' => $lifetime,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}
