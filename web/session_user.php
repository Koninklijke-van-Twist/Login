<?php

declare(strict_types=1);

require_once __DIR__ . '/session_config.php';

function build_rotating_api_key(string $oid, ?string $dateKey = null): string
{
    $oid = strtolower(trim($oid));
    if ($oid === '') {
        return '';
    }

    $dateKey = $dateKey ?? gmdate('d-m-Y');

    return hash('sha256', $oid . '|' . $dateKey);
}

function verify_rotating_api_key(string $oid, string $apiKey): bool
{
    $apiKey = strtolower(trim($apiKey));
    if ($apiKey === '' || preg_match('/^[a-f0-9]{64}$/', $apiKey) !== 1) {
        return false;
    }

    $oid = strtolower(trim($oid));
    if ($oid === '' || preg_match('/^[a-z0-9-]{8,128}$/', $oid) !== 1) {
        return false;
    }

    $todayKey = build_rotating_api_key($oid);
    $yesterdayKey = build_rotating_api_key($oid, gmdate('d-m-Y', time() - 86400));

    return hash_equals($todayKey, $apiKey) || hash_equals($yesterdayKey, $apiKey);
}

/**
 * @return array{email: string, api_key: string, oid: string}|null
 */
function get_session_user_context(): ?array
{
    $email = strtolower(trim((string) ($_SESSION['user']['email'] ?? '')));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return null;
    }

    return [
        'email' => $email,
        'api_key' => trim((string) ($_SESSION['user']['api_key'] ?? '')),
        'oid' => strtolower(trim((string) ($_SESSION['user']['oid'] ?? ''))),
    ];
}

/**
 * @param array<string, mixed> $body
 * @return array{email: string, api_key: string, oid: string}|null
 */
function resolve_access_request_actor(array $body): ?array
{
    $sessionUser = get_session_user_context();
    if ($sessionUser !== null) {
        return $sessionUser;
    }

    $email = strtolower(trim((string) ($body['user_email'] ?? '')));
    $apiKey = strtolower(trim((string) ($body['api_key'] ?? ($_SERVER['HTTP_X_API_KEY'] ?? ''))));
    $oid = strtolower(trim((string) ($body['oid'] ?? '')));

    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return null;
    }

    if (!verify_rotating_api_key($oid, $apiKey)) {
        return null;
    }

    return [
        'email' => $email,
        'api_key' => $apiKey,
        'oid' => $oid,
    ];
}

function start_app_session_readonly(): void
{
    configure_app_session();

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start(['read_and_close' => true]);
    }
}

function start_app_session(): void
{
    configure_app_session();

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}
