<?php

declare(strict_types=1);

/**
 * Serverside "blijf ingelogd" tokens (24 uur).
 * Geen MAC-adres: browsers geven dat niet door. Wel een httponly cookie + tokenbestand op de server.
 */

const REMEMBER_COOKIE_NAME = 'sleutels_remember';
const REMEMBER_LIFETIME_SECONDS = 86400; // 24 uur

function remember_tokens_directory(): string
{
    return __DIR__ . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'remember_tokens';
}

function ensure_remember_tokens_directory(): string
{
    $dir = remember_tokens_directory();
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }

    $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!is_file($htaccess)) {
        @file_put_contents($htaccess, "Require all denied\n");
    }

    return $dir;
}

/**
 * @param array{email: string, name?: string, oid?: string} $user
 */
function issue_remember_login(array $user): string
{
    $email = strtolower(trim((string) ($user['email'] ?? '')));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return '';
    }

    $dir = ensure_remember_tokens_directory();
    if (!is_dir($dir) || !is_writable($dir)) {
        return '';
    }

    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);
    $now = time();
    $expiresAt = $now + REMEMBER_LIFETIME_SECONDS;

    $payload = [
        'email' => $email,
        'name' => (string) ($user['name'] ?? ''),
        'oid' => strtolower(trim((string) ($user['oid'] ?? ''))),
        'created_at' => $now,
        'expires_at' => $expiresAt,
        'user_agent' => substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 300),
    ];

    $file = $dir . DIRECTORY_SEPARATOR . $tokenHash . '.json';
    $written = @file_put_contents(
        $file,
        json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        LOCK_EX
    );
    if ($written === false) {
        return '';
    }

    set_remember_cookie($token, $expiresAt);

    return $token;
}

function set_remember_cookie(string $token, int $expiresAt): void
{
    if (headers_sent()) {
        return;
    }

    setcookie(REMEMBER_COOKIE_NAME, $token, [
        'expires' => $expiresAt,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function clear_remember_cookie(): void
{
    if (headers_sent()) {
        $_COOKIE[REMEMBER_COOKIE_NAME] = '';

        return;
    }

    setcookie(REMEMBER_COOKIE_NAME, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

/**
 * @return array{email: string, name: string, oid: string}|null
 */
function load_remember_login_from_cookie(): ?array
{
    $token = trim((string) ($_COOKIE[REMEMBER_COOKIE_NAME] ?? ''));
    if ($token === '' || preg_match('/^[a-f0-9]{64}$/', $token) !== 1) {
        return null;
    }

    $dir = remember_tokens_directory();
    $file = $dir . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
    if (!is_file($file)) {
        clear_remember_cookie();

        return null;
    }

    $decoded = json_decode((string) file_get_contents($file), true);
    if (!is_array($decoded)) {
        @unlink($file);
        clear_remember_cookie();

        return null;
    }

    $expiresAt = (int) ($decoded['expires_at'] ?? 0);
    if ($expiresAt < time()) {
        @unlink($file);
        clear_remember_cookie();

        return null;
    }

    $email = strtolower(trim((string) ($decoded['email'] ?? '')));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        @unlink($file);
        clear_remember_cookie();

        return null;
    }

    return [
        'email' => $email,
        'name' => (string) ($decoded['name'] ?? ''),
        'oid' => strtolower(trim((string) ($decoded['oid'] ?? ''))),
    ];
}

/**
 * Herstel PHP-sessie vanuit remember-cookie indien nodig.
 * @return bool true als er nu een geldige $_SESSION['user'] is
 */
function ensure_session_user_from_remember(): bool
{
    $email = strtolower(trim((string) ($_SESSION['user']['email'] ?? '')));
    if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $oid = strtolower(trim((string) ($_SESSION['user']['oid'] ?? '')));
        if ($oid !== '') {
            require_once __DIR__ . '/session_user.php';
            $_SESSION['user']['api_key'] = build_rotating_api_key($oid);
        }

        return true;
    }

    $remembered = load_remember_login_from_cookie();
    if ($remembered === null) {
        return false;
    }

    require_once __DIR__ . '/session_user.php';
    $oid = $remembered['oid'];
    $_SESSION['user'] = [
        'email' => $remembered['email'],
        'name' => $remembered['name'],
        'oid' => $oid,
        'api_key' => $oid !== '' ? build_rotating_api_key($oid) : '',
        'restored_from_remember' => true,
    ];

    return true;
}

function revoke_remember_login_from_cookie(): void
{
    $token = trim((string) ($_COOKIE[REMEMBER_COOKIE_NAME] ?? ''));
    if ($token !== '' && preg_match('/^[a-f0-9]{64}$/', $token) === 1) {
        $file = remember_tokens_directory() . DIRECTORY_SEPARATOR . hash('sha256', $token) . '.json';
        if (is_file($file)) {
            @unlink($file);
        }
    }

    clear_remember_cookie();
}
