<?php

declare(strict_types=1);

function get_asclepius_service_api_key(): string
{
    $cfg = require __DIR__ . '/cfg.php';

    return trim((string) ($cfg['asclepius_api_key'] ?? ''));
}

function resolve_asclepius_api_file(): ?string
{
    $candidates = [
        dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Asclepius' . DIRECTORY_SEPARATOR . 'web' . DIRECTORY_SEPARATOR . 'api.php',
        dirname(__DIR__) . DIRECTORY_SEPARATOR . 'asclepius' . DIRECTORY_SEPARATOR . 'api.php',
    ];

    $documentRoot = realpath((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''));
    if (is_string($documentRoot) && $documentRoot !== '') {
        $candidates[] = $documentRoot . DIRECTORY_SEPARATOR . 'asclepius' . DIRECTORY_SEPARATOR . 'api.php';
        $candidates[] = $documentRoot . DIRECTORY_SEPARATOR . 'Asclepius' . DIRECTORY_SEPARATOR . 'web' . DIRECTORY_SEPARATOR . 'api.php';
    }

    foreach ($candidates as $candidate) {
        if (is_file($candidate)) {
            return $candidate;
        }
    }

    return null;
}

function resolve_asclepius_api_url(): string
{
    $cfg = require __DIR__ . '/cfg.php';
    $configured = trim((string) ($cfg['urls']['asclepius_api'] ?? ''));
    if ($configured !== '') {
        return $configured;
    }

    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = trim((string) ($_SERVER['HTTP_HOST'] ?? 'localhost'));
    if ($host === '') {
        $host = 'localhost';
    }

    if (strtolower($host) === 'sleutels.kvt.nl') {
        return $scheme . '://' . $host . '/asclepius/api.php';
    }

    $apiFile = resolve_asclepius_api_file();
    if ($apiFile !== null) {
        $docRoot = realpath((string) ($_SERVER['DOCUMENT_ROOT'] ?? ''));
        $webDir = realpath(dirname($apiFile));
        if (
            is_string($docRoot) && $docRoot !== '' &&
            is_string($webDir) && $webDir !== '' &&
            str_starts_with(str_replace('\\', '/', $webDir), str_replace('\\', '/', $docRoot))
        ) {
            $relative = '/' . trim(substr(str_replace('\\', '/', $webDir), strlen(str_replace('\\', '/', $docRoot))), '/');

            return $scheme . '://' . $host . $relative . '/api.php';
        }
    }

    return $scheme . '://' . $host . '/asclepius/api.php';
}

/**
 * @return array<string, mixed>|null
 */
function invoke_asclepius_request_page_access(string $pageName, string $userEmail, string $apiKey): ?array
{
    $apiFile = resolve_asclepius_api_file();
    if ($apiFile === null) {
        return null;
    }

    if (!defined('ASCLEPIUS_API_SKIP_ROUTER')) {
        define('ASCLEPIUS_API_SKIP_ROUTER', true);
    }

    require_once $apiFile;

    if (!function_exists('handleRequestPageAccessApiAction')) {
        return null;
    }

    $apiClient = $apiKey !== '' ? loadApiClientByToken($apiKey) : null;
    if ($apiClient === null) {
        $apiClient = [
            'email' => $userEmail,
            'is_admin' => false,
            'oid' => '',
            'api_key' => $apiKey,
        ];
    }

    try {
        $store = new TicketStore(
            DATABASE_FILE,
            UPLOAD_DIRECTORY,
            $GLOBALS['ictUsers'] ?? [],
            TICKET_CATEGORIES
        );
    } catch (Throwable $exception) {
        return [
            'success' => false,
            'error' => 'database_error',
            'details' => $exception->getMessage(),
        ];
    }

    return handleRequestPageAccessApiAction($store, [
        'page_name' => $pageName,
        'viewer_email' => $userEmail,
    ], $apiClient);
}

/**
 * @return array<string, mixed>|null
 */
function invoke_asclepius_request_page_access_via_http(string $pageName, string $userEmail, string $apiKey): ?array
{
    $apiUrl = resolve_asclepius_api_url();
    $serviceApiKey = get_asclepius_service_api_key();
    $effectiveApiKey = $serviceApiKey !== '' ? $serviceApiKey : $apiKey;

    $requestFields = [
        'action' => 'request_page_access',
        'page_name' => $pageName,
        'viewer_email' => $userEmail,
    ];

    $requestUrl = $apiUrl . '?' . http_build_query($requestFields, '', '&', PHP_QUERY_RFC3986);
    $postBody = http_build_query($requestFields, '', '&', PHP_QUERY_RFC3986);

    $headers = [
        'Content-Type: application/x-www-form-urlencoded',
        'Accept: application/json',
    ];
    if ($effectiveApiKey !== '') {
        $headers[] = 'X-API-Key: ' . $effectiveApiKey;
    }

    $responseBody = null;

    if (function_exists('curl_init')) {
        $curl = curl_init($requestUrl);
        if ($curl !== false) {
            curl_setopt_array($curl, [
                CURLOPT_POST => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_POSTFIELDS => $postBody,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_FOLLOWLOCATION => true,
            ]);
            $responseBody = curl_exec($curl);
            curl_close($curl);
        }
    }

    if (!is_string($responseBody) || $responseBody === '') {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => implode("\r\n", $headers) . "\r\n",
                'content' => $postBody,
                'timeout' => 30,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $responseBody = @file_get_contents($requestUrl, false, $context);
    }

    if (!is_string($responseBody) || $responseBody === '') {
        return null;
    }

    $decoded = json_decode($responseBody, true);

    return is_array($decoded) ? $decoded : null;
}

/**
 * @return array<string, mixed>|null
 */
function request_page_access_for_user(string $pageName, string $userEmail, string $apiKey): ?array
{
    $result = invoke_asclepius_request_page_access($pageName, $userEmail, $apiKey);
    if ($result !== null) {
        return $result;
    }

    return invoke_asclepius_request_page_access_via_http($pageName, $userEmail, $apiKey);
}
