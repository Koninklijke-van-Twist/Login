<?php

declare(strict_types=1);

echo '=== TEST: remember login tokens ===' . PHP_EOL . PHP_EOL;

$_SERVER['HTTPS'] = 'off';
$_SERVER['HTTP_USER_AGENT'] = 'PHPUnit-Remember-Test';

require __DIR__ . '/../remember.php';

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

$dir = ensure_remember_tokens_directory();
assertTrue('tokenmap bestaat', is_dir($dir));
assertTrue('htaccess aanwezig', is_file($dir . DIRECTORY_SEPARATOR . '.htaccess'));

$token = issue_remember_login([
    'email' => 'remember-test@kvt.nl',
    'name' => 'Remember Tester',
    'oid' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
]);
assertTrue('token uitgegeven', $token !== '' && preg_match('/^[a-f0-9]{64}$/', $token) === 1);

$_COOKIE[REMEMBER_COOKIE_NAME] = $token;
$loaded = load_remember_login_from_cookie();
assertSame('e-mail hersteld', 'remember-test@kvt.nl', $loaded['email'] ?? null);
assertSame('oid hersteld', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', $loaded['oid'] ?? null);

$_SESSION = [];
assertTrue('sessie hersteld vanuit remember', ensure_session_user_from_remember());
assertSame('sessie e-mail', 'remember-test@kvt.nl', $_SESSION['user']['email'] ?? null);
assertTrue('api_key gezet', trim((string) ($_SESSION['user']['api_key'] ?? '')) !== '');

revoke_remember_login_from_cookie();
$_COOKIE = [];
$_SESSION = [];
assertTrue('na revoke geen restore', !ensure_session_user_from_remember());

echo PHP_EOL . str_repeat('-', 40) . PHP_EOL;
echo "Resultaat: {$passed} geslaagd, {$failed} gefaald" . PHP_EOL;

exit($failed > 0 ? 1 : 0);
