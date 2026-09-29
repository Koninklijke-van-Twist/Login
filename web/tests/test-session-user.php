<?php

declare(strict_types=1);

echo '=== TEST: session user auth ===' . PHP_EOL . PHP_EOL;

require __DIR__ . '/../session_user.php';

$passed = 0;
$failed = 0;

function assertTrue(string $label, bool $condition): void
{
    global $passed, $failed;
    if ($condition) {
        echo "  ✓ {$label}" . PHP_EOL;
        $passed++;
    } else {
        echo "  ✗ {$label}" . PHP_EOL;
        $failed++;
    }
}

function assertSame(string $label, mixed $expected, mixed $actual): void
{
    global $passed, $failed;
    if ($expected === $actual) {
        echo "  ✓ {$label}" . PHP_EOL;
        $passed++;
    } else {
        echo "  ✗ {$label}" . PHP_EOL;
        echo '      Verwacht : ' . var_export($expected, true) . PHP_EOL;
        echo '      Gekregen : ' . var_export($actual, true) . PHP_EOL;
        $failed++;
    }
}

$oid = '11111111-2222-3333-4444-555555555555';
$apiKey = build_rotating_api_key($oid);

echo 'verify_rotating_api_key' . PHP_EOL;
assertTrue('geldige key van vandaag', verify_rotating_api_key($oid, $apiKey));
assertTrue('ongeldige key', !verify_rotating_api_key($oid, str_repeat('a', 64)));

echo PHP_EOL . 'resolve_access_request_actor' . PHP_EOL;
$actor = resolve_access_request_actor([
    'user_email' => 'tester@kvt.nl',
    'api_key' => $apiKey,
    'oid' => $oid,
    'page_name' => '/finrap/',
]);
assertSame('e-mail uit body', 'tester@kvt.nl', $actor['email'] ?? null);
assertSame('api_key uit body', $apiKey, $actor['api_key'] ?? null);

$invalidActor = resolve_access_request_actor([
    'user_email' => 'tester@kvt.nl',
    'api_key' => str_repeat('b', 64),
    'oid' => $oid,
]);
assertSame('ongeldige body key geweigerd', null, $invalidActor);

echo PHP_EOL . str_repeat('-', 40) . PHP_EOL;
echo "Resultaat: {$passed} geslaagd, {$failed} gefaald" . PHP_EOL;

exit($failed > 0 ? 1 : 0);
