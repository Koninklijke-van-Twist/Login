<?php

require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/remember.php';
configure_app_session();

login_start_session_for_request();

$cfg = require __DIR__ . '/cfg.php';

if (!ensure_session_user_from_remember()) {
    // Huidige URL (pad + query) bewaren
    $returnTo = $_SERVER['REQUEST_URI'] ?? '/';
    if (!is_string($returnTo) || $returnTo === '' || $returnTo[0] !== '/') {
        $returnTo = '/';
    }

    $_SESSION['return_to'] = $returnTo;
    set_return_to_cookie($returnTo);

    $loginStartUrl = (string) ($cfg['urls']['login_start'] ?? '/login/');
    header("Location: {$loginStartUrl}");
    exit;
}

session_write_close();

function set_return_to_cookie(string $returnTo): void
{
    setcookie('oauth_return_to', $returnTo, [
        'expires' => time() + 1800,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function user_is_allowed(string $email, array $whitelist, array $cfg): bool
{
    $email = strtolower(trim($email));
    if ($email === '') {
        return false;
    }

    $allow = array_map('strtolower', $whitelist['allow'] ?? []);
    $domains = array_values(array_filter(array_map(
        static fn($domain): string => strtolower(trim((string) $domain)),
        array_keys(is_array($cfg['domains'] ?? null) ? $cfg['domains'] : [])
    )));

    if (empty($domains)) {
        return false;
    }

    // domain check
    $domain = substr(strrchr($email, "@") ?: "", 1);
    if ($domain === '' || !in_array(strtolower($domain), $domains, true)) {
        return false;
    }

    return in_array($email, $allow, true);
}

/**
 * Start de sessie zo kort en stil mogelijk.
 *
 * - Bestaande sessie met geldige gebruiker: read_and_close, zodat het (Redis-)
 *   sessielock direct weer vrij is. Apps vinden de sessie daarna gesloten (zoals
 *   altijd na deze lib) en heropenen hem kort als ze iets willen opslaan.
 * - Geen gebruiker in de sessie (remember-herstel of return_to opslaan): gewoon
 *   schrijfbaar starten zoals voorheen.
 * - Waarschuwingen van session_start() (bijv. "Failed to acquire session lock"
 *   bij gelijktijdige verzoeken) worden gelogd maar nooit in de output getoond,
 *   zodat JSON-endpoints van apps geen HTML vóór hun JSON krijgen.
 */
function login_start_session_for_request(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $previousDisplay = ini_get('display_errors');
    ini_set('display_errors', '0');

    try {
        $hasCookie = isset($_COOKIE[session_name()]) && (string) $_COOKIE[session_name()] !== '';
        if ($hasCookie && session_start(['read_and_close' => true])) {
            $email = strtolower(trim((string) ($_SESSION['user']['email'] ?? '')));
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                return;
            }
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }
    } finally {
        ini_set('display_errors', $previousDisplay === false ? '' : (string) $previousDisplay);
    }
}
