<?php
declare(strict_types=1);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/session_user.php';
require_once __DIR__ . '/remember.php';
configure_app_session();

session_start();

$cfg = require __DIR__ . '/cfg.php';

$returnTo = resolve_return_to(
    $_COOKIE['oauth_return_to'] ?? null,
    $_SESSION['return_to'] ?? null,
    $_SERVER['HTTP_REFERER'] ?? null,
    $_SERVER['HTTP_HOST'] ?? null
);
$loginStartUrl = build_login_start_url($cfg, $_SESSION['oauth_domain'] ?? null);

$configuredDomains = is_array($cfg['domains'] ?? null) ? $cfg['domains'] : [];
$defaultDomain = strtolower(trim((string) ($cfg['default_domain'] ?? '')));
$selectedDomain = strtolower(trim((string) ($_SESSION['oauth_domain'] ?? $defaultDomain)));

if ($selectedDomain === '' || !isset($configuredDomains[$selectedDomain]) || !is_array($configuredDomains[$selectedDomain])) {
    render_error_and_redirect('Domeinconfiguratie ontbreekt in cfg.php.', 500, $returnTo);
}

$domainOauth = $configuredDomains[$selectedDomain];

/** =========================
 *  1) CONFIG
 *  ========================= */
$TENANT_ID = (string) ($domainOauth['tenant_id'] ?? '');
$CLIENT_ID = (string) ($domainOauth['client_id'] ?? '');
$CLIENT_SECRET = (string) ($domainOauth['client_secret'] ?? '');
$REDIRECT_URI = (string) ($domainOauth['redirect_uri'] ?? '');

if ($TENANT_ID === '' || $CLIENT_ID === '' || $CLIENT_SECRET === '' || $REDIRECT_URI === '') {
    render_error_and_redirect('OAuth domeinconfiguratie ontbreekt in cfg.php.', 500, $returnTo);
}

if (!isset($_GET['code']) || !is_string($_GET['code']) || $_GET['code'] === '') {
    render_error_and_redirect('Geen authorisatiecode ontvangen.', 400, $returnTo);
}

$code = $_GET['code'];

/** =========================
 *  2) TOKEN EXCHANGE (uses client secret)
 *  ========================= */
$tokenUrl = "https://login.microsoftonline.com/{$TENANT_ID}/oauth2/v2.0/token";

$postBody = http_build_query([
    'client_id' => $CLIENT_ID,
    'client_secret' => $CLIENT_SECRET,
    'grant_type' => 'authorization_code',
    'code' => $code,
    'redirect_uri' => $REDIRECT_URI,
], '', '&', PHP_QUERY_RFC3986);

$ch = curl_init($tokenUrl);
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
    CURLOPT_POSTFIELDS => $postBody,
    CURLOPT_TIMEOUT => 20,
]);

$raw = curl_exec($ch);
$httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

if ($raw === false) {
    $err = curl_error($ch);
    curl_close($ch);
    render_error_and_redirect('Token request faalde (cURL): ' . $err, 500, $returnTo);
}
curl_close($ch);

$data = json_decode($raw, true);
if (!is_array($data)) {
    render_error_and_redirect('Token response is geen geldige JSON.', 500, $returnTo);
}

if ($httpCode < 200 || $httpCode >= 300) {
    $msg = $data['error_description'] ?? $data['error'] ?? 'Onbekende fout';
    render_error_and_redirect("Token request faalde ({$httpCode}): " . (string) $msg, 500, $returnTo);
}

$idToken = $data['id_token'] ?? null;
if (!is_string($idToken) || $idToken === '') {
    render_error_and_redirect('Geen id_token ontvangen.', 500, $returnTo);
}

/** =========================
 *  3) ID TOKEN CLAIMS uitlezen
 *  (Let op: dit decodeert alleen. Voor productie wil je ook JWT-signature valideren.)
 *  ========================= */
$claims = jwt_decode_without_verifying($idToken);
if (!is_array($claims)) {
    render_error_and_redirect('Kon claims niet uitlezen uit id_token.', 500, $returnTo);
}


/** =========================
 *  4) USER IDENTIFIER bepalen (email/upn)
 *  ========================= */
$email = strtolower(trim(
    (string) ($claims['preferred_username'] ?? $claims['email'] ?? $claims['upn'] ?? '')
));

if ($email === '' || strpos($email, '@') === false) {
    render_error_and_redirect('Geen geldig e-mailadres gevonden in token.', 403, $returnTo);
}

/** Domeincontrole op basis van cfg.php */
if (!email_domain_is_allowed($email, array_keys($configuredDomains))) {
    render_error_and_redirect('Uw domein is niet toegestaan.', 403, $returnTo);
}

/** =========================
 *  5) Sessieset + redirect terug
 *  ========================= */
$oid = strtolower(trim((string) ($claims['oid'] ?? '')));
$userRecord = [
    'email' => $email,
    'name' => (string) ($claims['name'] ?? ''),
    'oid' => $oid,
    'api_key' => build_rotating_api_key($oid),
];
$_SESSION['user'] = $userRecord;

issue_remember_login($userRecord);

unset($_SESSION['return_to'], $_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_domain']);
unset($_SESSION['oauth_state_retry']);
clear_return_to_cookie();
session_write_close();

/** Open-redirect protectie */
if (!is_string($returnTo) || $returnTo === '' || $returnTo[0] !== '/') {
    $returnTo = '/';
}

header("Location: {$returnTo}");
exit;


/** =========================
 *  Helpers
 *  ========================= */

/**
 * Decode JWT payload zonder signature verificatie.
 * Voor �echt netjes� wil je valideren met Microsoft JWKS (signing keys).
 */
function jwt_decode_without_verifying(string $jwt): ?array
{
    $parts = explode('.', $jwt);
    if (count($parts) !== 3)
        return null;

    [$headerB64, $payloadB64] = [$parts[0], $parts[1]];
    $payloadJson = base64url_decode($payloadB64);
    if ($payloadJson === null)
        return null;

    $payload = json_decode($payloadJson, true);
    return is_array($payload) ? $payload : null;
}

function base64url_decode(string $data): ?string
{
    $data = strtr($data, '-_', '+/');
    $pad = strlen($data) % 4;
    if ($pad)
        $data .= str_repeat('=', 4 - $pad);
    $decoded = base64_decode($data, true);
    return $decoded === false ? null : $decoded;
}

function email_domain_is_allowed(string $email, array $allowedDomains): bool
{
    $email = strtolower(trim($email));
    if ($email === '' || !str_contains($email, '@')) {
        return false;
    }

    $domain = strtolower((string) substr(strrchr($email, '@'), 1));
    if ($domain === '') {
        return false;
    }

    $normalizedAllowedDomains = array_values(array_filter(array_map(
        static fn($value): string => strtolower(trim((string) $value)),
        $allowedDomains
    )));

    return in_array($domain, $normalizedAllowedDomains, true);
}

function get_state_store(mixed $rawStore): array
{
    if (!is_array($rawStore)) {
        return [];
    }

    $now = time();
    $maxStateAgeSeconds = 900;
    $normalized = [];

    foreach ($rawStore as $state => $entry) {
        if (!is_string($state) || $state === '' || !is_array($entry)) {
            continue;
        }

        $nonce = $entry['nonce'] ?? null;
        $createdAt = $entry['created_at'] ?? null;

        if (!is_string($nonce) || $nonce === '' || !is_int($createdAt)) {
            continue;
        }

        if (($now - $createdAt) > $maxStateAgeSeconds) {
            continue;
        }

        $normalized[$state] = [
            'nonce' => $nonce,
            'created_at' => $createdAt,
        ];
    }

    return $normalized;
}

function resolve_return_to(mixed $cookieReturnTo, mixed $sessionReturnTo, mixed $referer, mixed $httpHost): string
{
    if (is_safe_return_path($cookieReturnTo)) {
        return $cookieReturnTo;
    }

    if (is_safe_return_path($sessionReturnTo)) {
        return $sessionReturnTo;
    }

    if (is_string($referer) && $referer !== '') {
        $refererHost = parse_url($referer, PHP_URL_HOST);
        $path = parse_url($referer, PHP_URL_PATH);
        $query = parse_url($referer, PHP_URL_QUERY);

        if (
            is_string($path) &&
            $path !== '' &&
            $path[0] === '/' &&
            is_string($httpHost) &&
            $httpHost !== '' &&
            is_string($refererHost) &&
            strcasecmp($refererHost, $httpHost) === 0
        ) {
            return $query ? $path . '?' . $query : $path;
        }
    }

    return '/';
}

function is_safe_return_path(mixed $value): bool
{
    return is_string($value) && $value !== '' && $value[0] === '/';
}

function clear_return_to_cookie(): void
{
    setcookie('oauth_return_to', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function build_login_start_url(array $cfg, mixed $domain): string
{
    $baseUrl = (string) ($cfg['urls']['login_start'] ?? '/login/');
    if ($baseUrl === '') {
        $baseUrl = '/login/';
    }

    $domain = is_string($domain) ? strtolower(trim($domain)) : '';
    if ($domain === '') {
        return $baseUrl;
    }

    $separator = str_contains($baseUrl, '?') ? '&' : '?';
    return $baseUrl . $separator . http_build_query(['domain' => $domain], '', '&', PHP_QUERY_RFC3986);
}

function log_oauth_issue(string $event, array $context = []): void
{
    $payload = [
        'event' => $event,
        'ts' => gmdate('c'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
        'ua' => $_SERVER['HTTP_USER_AGENT'] ?? null,
        'context' => $context,
    ];

    error_log('[oauth] ' . json_encode($payload, JSON_UNESCAPED_SLASHES));
}

function render_error_and_redirect(string $message, int $statusCode, string $returnTo): never
{
    http_response_code($statusCode);

    $safeMessage = htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $safeReturnTo = htmlspecialchars($returnTo, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    ?>
    <!DOCTYPE html>
    <html lang="nl">

    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="3;url=<?= $safeReturnTo ?>">
        <title>Inloggen tijdelijk mislukt</title>
        <style>
            :root {
                --bg-start: #f3f7fc;
                --bg-end: #eaf1f8;
                --panel: #ffffff;
                --text: #1f2d3d;
                --muted: #556372;
                --accent: #0a66c2;
                --danger: #b42318;
                --ring: rgba(10, 102, 194, 0.18);
            }

            * {
                box-sizing: border-box;
            }

            html,
            body {
                margin: 0;
                min-height: 100%;
                font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
                color: var(--text);
                background: radial-gradient(circle at top left, var(--bg-start) 0%, var(--bg-end) 70%);
            }

            body {
                display: grid;
                place-items: center;
                padding: 24px;
            }

            .card {
                width: min(640px, 100%);
                background: var(--panel);
                border-radius: 16px;
                padding: 28px;
                box-shadow: 0 14px 40px rgba(12, 33, 66, 0.12);
                border: 1px solid var(--ring);
                animation: fade-in 220ms ease-out;
            }

            .badge {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 6px 12px;
                border-radius: 999px;
                font-weight: 600;
                font-size: 0.9rem;
                color: var(--danger);
                background: #fee4e2;
                margin-bottom: 14px;
            }

            h1 {
                margin: 0 0 10px;
                font-size: clamp(1.35rem, 2.8vw, 1.9rem);
                line-height: 1.2;
            }

            p {
                margin: 0;
                color: var(--muted);
                line-height: 1.55;
            }

            .error {
                margin-top: 18px;
                padding: 12px 14px;
                border-left: 4px solid var(--danger);
                background: #fff4f2;
                border-radius: 8px;
                font-size: 0.95rem;
                color: #6b1f17;
                word-break: break-word;
            }

            .actions {
                margin-top: 24px;
                display: flex;
                gap: 12px;
                align-items: center;
                flex-wrap: wrap;
            }

            .btn {
                display: inline-block;
                padding: 10px 16px;
                border-radius: 10px;
                text-decoration: none;
                font-weight: 600;
                background: var(--accent);
                color: #ffffff;
            }

            .countdown {
                font-size: 0.9rem;
                color: var(--muted);
            }

            @keyframes fade-in {
                from {
                    opacity: 0;
                    transform: translateY(8px);
                }

                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
        </style>
    </head>

    <body>
        <main class="card" role="main" aria-live="polite">
            <div class="badge">Inlogfout</div>
            <h1>Inloggen is tijdelijk mislukt</h1>
            <p>Je wordt automatisch teruggestuurd zodat de loginflow opnieuw kan starten.</p>
            <div class="error"><?= $safeMessage ?></div>
            <div class="actions">
                <a class="btn" href="<?= $safeReturnTo ?>">Nu opnieuw proberen</a>
                <span class="countdown">Automatisch terug over <strong id="seconds">3</strong> seconden...</span>
            </div>
        </main>

        <script>
            (function ()
            {
                var seconds = 3;
                var target = document.getElementById('seconds');
                var timer = window.setInterval(function ()
                {
                    seconds -= 1;
                    if (target)
                    {
                        target.textContent = String(Math.max(0, seconds));
                    }
                    if (seconds <= 0)
                    {
                        window.clearInterval(timer);
                        window.location.replace('<?= $safeReturnTo ?>');
                    }
                }, 1000);
            })();
        </script>
    </body>

    </html>
    <?php
    exit;
}
