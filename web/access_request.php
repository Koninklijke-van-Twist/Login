<?php

declare(strict_types=1);

const ACCESS_REQUEST_VERSION = '2026-06-24-4';

require_once __DIR__ . '/session_user.php';
require_once __DIR__ . '/403_context.php';
start_app_session();

require_once __DIR__ . '/asclepius_access.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Access-Request-Version: ' . ACCESS_REQUEST_VERSION);

if (strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'method_not_allowed', 'source' => 'access_request'], JSON_UNESCAPED_UNICODE);
    exit;
}

$contentType = strtolower(trim((string) ($_SERVER['CONTENT_TYPE'] ?? '')));
$rawBody = file_get_contents('php://input');
$body = [];

if (str_contains($contentType, 'application/json') && is_string($rawBody) && trim($rawBody) !== '') {
    $decoded = json_decode($rawBody, true);
    if (is_array($decoded)) {
        $body = $decoded;
    }
}

if ($body === [] && $_POST !== []) {
    $body = $_POST;
}

$pageName = resolve_access_request_page_name($body);
if ($pageName === '') {
    http_response_code(422);
    echo json_encode([
        'success' => false,
        'error' => 'page_name_required',
        'source' => 'access_request',
        'version' => ACCESS_REQUEST_VERSION,
        'debug' => [
            'query_string' => (string) ($_SERVER['QUERY_STRING'] ?? ''),
            'request_uri' => (string) ($_SERVER['REQUEST_URI'] ?? ''),
            'x_requested_path' => (string) ($_SERVER['HTTP_X_REQUESTED_PATH'] ?? ''),
            'body_page_name' => (string) ($body['page_name'] ?? ''),
            'post_page_name' => (string) ($_POST['page_name'] ?? ''),
            'session_page_name' => (string) ($_SESSION['access_request_page'] ?? ''),
        ],
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$actor = resolve_access_request_actor($body);
if ($actor === null) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'not_logged_in', 'source' => 'access_request'], JSON_UNESCAPED_UNICODE);
    exit;
}

$_SESSION['access_request_page'] = $pageName;

$result = request_page_access_for_user($pageName, $actor['email'], $actor['api_key']);

if ($result === null) {
    http_response_code(502);
    echo json_encode([
        'success' => false,
        'error' => 'asclepius_unreachable',
        'source' => 'access_request',
        'version' => ACCESS_REQUEST_VERSION,
        'page_name' => $pageName,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

if (!empty($result['success'])) {
    $statusCode = !empty($result['created']) ? 201 : 200;
} else {
    $asclepiusError = trim((string) ($result['error'] ?? ''));
    $statusCode = match ($asclepiusError) {
        'page_name_required' => 422,
        'unauthorized', 'invalid_user', 'not_logged_in' => 401,
        default => 502,
    };
    $result['source'] = 'asclepius';
    $result['version'] = ACCESS_REQUEST_VERSION;
    $result['page_name'] = $pageName;
}

http_response_code($statusCode);
echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
