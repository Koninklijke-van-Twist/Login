<?php

declare(strict_types=1);

echo '=== TEST: 403 page context ===' . PHP_EOL . PHP_EOL;

$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['SERVER_ADDR'] = '127.0.0.1';

require __DIR__ . '/../403_context.php';

$passed = 0;
$failed = 0;

function assertSame(string $label, mixed $expected, mixed $actual): void
{
    global $passed, $failed;
    if ($expected === $actual) {
        echo "  ✓ {$label}" . PHP_EOL;
        $passed++;
    } else {
        $exp = var_export($expected, true);
        $act = var_export($actual, true);
        echo "  ✗ {$label}" . PHP_EOL;
        echo "      Verwacht : {$exp}" . PHP_EOL;
        echo "      Gekregen : {$act}" . PHP_EOL;
        $failed++;
    }
}

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

echo 'normalize_403_test_page' . PHP_EOL;
assertSame('finrap wordt /finrap/', '/finrap/', normalize_403_test_page('finrap'));
assertSame('/finrap/ blijft /finrap/', '/finrap/', normalize_403_test_page('/finrap/'));
assertSame('pad met bestand blijft zonder slash', '/finrap/web/index.php', normalize_403_test_page('finrap/web/index.php'));
assertSame('leeg blijft leeg', '', normalize_403_test_page(''));

echo PHP_EOL . 'resolve_403_page_context' . PHP_EOL;
$finrapContext = resolve_403_page_context('/login/403.php?test_page=finrap', 'finrap', true);
assertSame('test_page=finrap simuleert /finrap/', '/finrap/', $finrapContext['page_name']);
assertSame('display_uri is /finrap/', '/finrap/', $finrapContext['display_uri']);
assertSame('testmodus actief', true, $finrapContext['is_test_mode']);

$normalContext = resolve_403_page_context('/moirai/web/reports.php?foo=1', null, true);
assertSame('normale request path', '/moirai/web/reports.php', $normalContext['page_name']);
assertSame('normale display uri', '/moirai/web/reports.php?foo=1', $normalContext['display_uri']);
assertSame('geen testmodus', false, $normalContext['is_test_mode']);

$blockedContext = resolve_403_page_context('/login/403.php?test_page=finrap', 'finrap', false);
assertSame('test_page genegeerd zonder toegestane testmodus', '/login/403.php', $blockedContext['page_name']);
assertSame('testmodus uit zonder toegestane testmodus', false, $blockedContext['is_test_mode']);

$liveLoggedInContext = resolve_403_page_context('/login/403.php?test_page=finrap', 'finrap', can_use_403_test_mode(true));
assertSame('ingelogde gebruiker mag test_page op live', '/finrap/', $liveLoggedInContext['page_name']);

echo PHP_EOL . 'resolve_access_request_page_name' . PHP_EOL;
$_SERVER['QUERY_STRING'] = 'requested_path=%2Felpis%2F';
$_GET['requested_path'] = '/elpis/';
assertSame('query string requested_path', '/elpis/', resolve_access_request_page_name([]));
unset($_SERVER['QUERY_STRING'], $_GET['requested_path']);

$_SERVER['HTTP_X_REQUESTED_PATH'] = '/finrap/';
assertSame('header x-requested-path', '/finrap/', resolve_access_request_page_name([]));
unset($_SERVER['HTTP_X_REQUESTED_PATH']);

$_SERVER['REQUEST_URI'] = '/login/access_request.php?requested_path=%2FSluitDezeTicket%2F';
assertSame('request_uri query', '/SluitDezeTicket/', resolve_access_request_page_name([]));
unset($_SERVER['REQUEST_URI']);

$_POST['page_name'] = '/moirai/';
assertSame('post form page_name', '/moirai/', resolve_access_request_page_name([]));
unset($_POST['page_name']);

$_COOKIE['access_request_page'] = '/finrap/';
assertSame('cookie fallback', '/finrap/', resolve_access_request_page_name([]));
unset($_COOKIE['access_request_page']);

$_SERVER['HTTP_REFERER'] = 'https://sleutels.kvt.nl/login/403.php?test_page=SluitDezeTicket';
assertSame('referer test_page fallback', '/SluitDezeTicket/', resolve_access_request_page_name([]));
unset($_SERVER['HTTP_REFERER']);

echo PHP_EOL . 'can_use_403_test_mode' . PHP_EOL;
assertTrue('localhost zonder login', can_use_403_test_mode(false));
assertTrue('ingelogde gebruiker op live', can_use_403_test_mode(true));

echo PHP_EOL . str_repeat('-', 40) . PHP_EOL;
echo "Resultaat: {$passed} geslaagd, {$failed} gefaald" . PHP_EOL;

exit($failed > 0 ? 1 : 0);
