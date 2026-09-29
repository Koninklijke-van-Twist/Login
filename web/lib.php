<?php

require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/remember.php';
configure_app_session();

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

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
