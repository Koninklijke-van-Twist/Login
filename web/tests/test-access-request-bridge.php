<?php

declare(strict_types=1);

$_SERVER['DOCUMENT_ROOT'] = dirname(__DIR__, 2);
$_SERVER['HTTP_HOST'] = '127.0.0.1';
$_SERVER['HTTPS'] = 'off';

require __DIR__ . '/../asclepius_access.php';

$result = invoke_asclepius_request_page_access('/finrap/', 'localtester@kvt.nl', '');
if (!is_array($result) || empty($result['success'])) {
    fwrite(STDERR, 'Directe Asclepius-aanroep mislukt: ' . json_encode($result) . PHP_EOL);
    exit(1);
}

echo 'Directe Asclepius-aanroep geslaagd, ticket #' . (int) ($result['ticket']['id'] ?? 0) . PHP_EOL;
