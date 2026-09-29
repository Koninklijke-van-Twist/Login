<?php

declare(strict_types=1);

function is_trusted_403_tester(): bool
{
    $remote = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    $server = trim((string) ($_SERVER['SERVER_ADDR'] ?? ''));

    if ($remote !== '' && $remote === $server) {
        return true;
    }

    return in_array($remote, ['127.0.0.1', '::1'], true);
}

function normalize_403_test_page(string $testPage): string
{
    $testPage = trim($testPage);
    if ($testPage === '') {
        return '';
    }

    if ($testPage[0] !== '/') {
        $testPage = '/' . $testPage;
    }

    if (!str_contains($testPage, '.') && !str_ends_with($testPage, '/')) {
        $testPage .= '/';
    }

    return $testPage;
}

function can_use_403_test_mode(bool $isLoggedIn): bool
{
    return is_trusted_403_tester() || $isLoggedIn;
}

/**
 * @return array{page_name: string, display_uri: string, is_test_mode: bool}
 */
function resolve_403_page_context(?string $requestUri, ?string $testPage, bool $allowTestMode): array
{
    $testPage = is_string($testPage) ? trim($testPage) : '';
    if ($allowTestMode && $testPage !== '') {
        $simulatedPath = normalize_403_test_page($testPage);

        return [
            'page_name' => $simulatedPath,
            'display_uri' => $simulatedPath,
            'is_test_mode' => true,
        ];
    }

    $requestPath = parse_url((string) ($requestUri ?? '/'), PHP_URL_PATH);
    $pageName = is_string($requestPath) && $requestPath !== '' ? $requestPath : '/';

    return [
        'page_name' => $pageName,
        'display_uri' => (string) ($requestUri ?? ''),
        'is_test_mode' => false,
    ];
}

function set_access_request_page_cookie(string $pagePath): void
{
    $pagePath = trim($pagePath);
    if ($pagePath === '') {
        return;
    }

    setcookie('access_request_page', $pagePath, [
        'expires' => time() + 600,
        'path' => '/login/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function extract_requested_path_from_request(): string
{
    $headerPath = trim((string) ($_SERVER['HTTP_X_REQUESTED_PATH'] ?? ''));
    if ($headerPath !== '') {
        return $headerPath;
    }

    $queryString = trim((string) ($_SERVER['QUERY_STRING'] ?? ''));
    if ($queryString !== '') {
        $queryParams = [];
        parse_str($queryString, $queryParams);
        $queryPath = trim((string) ($queryParams['requested_path'] ?? ''));
        if ($queryPath !== '') {
            return $queryPath;
        }
    }

    $redirectQuery = trim((string) ($_SERVER['REDIRECT_QUERY_STRING'] ?? ''));
    if ($redirectQuery !== '') {
        $redirectParams = [];
        parse_str($redirectQuery, $redirectParams);
        $redirectPath = trim((string) ($redirectParams['requested_path'] ?? ''));
        if ($redirectPath !== '') {
            return $redirectPath;
        }
    }

    $requestUri = (string) ($_SERVER['REQUEST_URI'] ?? '');
    if ($requestUri !== '') {
        $uriQuery = (string) parse_url($requestUri, PHP_URL_QUERY);
        if ($uriQuery !== '') {
            $uriParams = [];
            parse_str($uriQuery, $uriParams);
            $uriPath = trim((string) ($uriParams['requested_path'] ?? ''));
            if ($uriPath !== '') {
                return $uriPath;
            }
        }
    }

    return trim((string) ($_GET['requested_path'] ?? ''));
}

/**
 * @param array<string, mixed> $body
 */
function resolve_access_request_page_name(array $body): string
{
    $sessionPath = '';
    if (session_status() === PHP_SESSION_ACTIVE) {
        $sessionPath = trim((string) ($_SESSION['access_request_page'] ?? ''));
    }

    $candidates = [
        extract_requested_path_from_request(),
        $sessionPath !== '' ? $sessionPath : null,
        $body['page_name'] ?? null,
        $body['requested_path'] ?? null,
        $_POST['page_name'] ?? null,
        $_POST['requested_path'] ?? null,
        $_COOKIE['access_request_page'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        $pagePath = trim((string) $candidate);
        if ($pagePath !== '') {
            return $pagePath;
        }
    }

    $referer = trim((string) ($_SERVER['HTTP_REFERER'] ?? ''));
    if ($referer !== '') {
        $refererQuery = [];
        parse_str((string) parse_url($referer, PHP_URL_QUERY), $refererQuery);
        $testPage = trim((string) ($refererQuery['test_page'] ?? ''));
        if ($testPage !== '') {
            return normalize_403_test_page($testPage);
        }

        $refererPath = parse_url($referer, PHP_URL_PATH);
        if (is_string($refererPath) && $refererPath !== '' && !str_contains($refererPath, '/login/403.php')) {
            return $refererPath;
        }
    }

    return '';
}
