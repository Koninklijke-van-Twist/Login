<?php
require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/remember.php';
configure_app_session();

session_start();

$cfg = require __DIR__ . '/cfg.php';

// Al ingelogd (sessie of remember-cookie): niet opnieuw naar Microsoft.
if (ensure_session_user_from_remember()) {
    $returnTo = $_SESSION['return_to'] ?? ($_COOKIE['oauth_return_to'] ?? '/');
    if (!is_string($returnTo) || $returnTo === '' || $returnTo[0] !== '/') {
        $returnTo = '/';
    }
    unset($_SESSION['return_to']);
    session_write_close();
    header('Location: ' . $returnTo);
    exit;
}

$configuredDomains = is_array($cfg['domains'] ?? null) ? $cfg['domains'] : [];
$defaultDomain = strtolower(trim((string) ($cfg['default_domain'] ?? '')));

$requestedDomain = strtolower(trim((string) ($_GET['domain'] ?? '')));
$selectedDomain = $requestedDomain !== '' ? $requestedDomain : $defaultDomain;

if ($selectedDomain === '' || !isset($configuredDomains[$selectedDomain]) || !is_array($configuredDomains[$selectedDomain])) {
  http_response_code(500);
  exit('Domeinconfiguratie ontbreekt in cfg.php.');
}

$domainOauth = $configuredDomains[$selectedDomain];

$CLIENT_ID = (string) ($domainOauth['client_id'] ?? '');
$TENANT_ID = (string) ($domainOauth['tenant_id'] ?? '');
$REDIRECT_URI = (string) ($domainOauth['redirect_uri'] ?? '');

if ($CLIENT_ID === '' || $TENANT_ID === '' || $REDIRECT_URI === '') {
  http_response_code(500);
  exit('OAuth domeinconfiguratie ontbreekt in cfg.php.' . __DIR__);
}

$_SESSION['oauth_domain'] = $selectedDomain;

$oauthState = bin2hex(random_bytes(16));
$oauthNonce = bin2hex(random_bytes(16));

$stateStore = is_array($_SESSION['oauth_state_store'] ?? null) ? $_SESSION['oauth_state_store'] : [];
$now = time();
$maxStateAgeSeconds = 900;
$maxStateEntries = 10;

$stateStore = array_filter($stateStore, static function ($entry) use ($now, $maxStateAgeSeconds): bool {
  if (!is_array($entry)) {
    return false;
  }

  $createdAt = $entry['created_at'] ?? null;
  $nonce = $entry['nonce'] ?? null;
  if (!is_int($createdAt) || !is_string($nonce) || $nonce === '') {
    return false;
  }

  return ($now - $createdAt) <= $maxStateAgeSeconds;
});

$stateStore[$oauthState] = [
  'nonce' => $oauthNonce,
  'created_at' => $now,
];

if (count($stateStore) > $maxStateEntries) {
  uasort($stateStore, static function (array $a, array $b): int {
    return (int) ($a['created_at'] ?? 0) <=> (int) ($b['created_at'] ?? 0);
  });

  while (count($stateStore) > $maxStateEntries) {
    array_shift($stateStore);
  }
}

$_SESSION['oauth_state_store'] = $stateStore;
$_SESSION['oauth_state'] = $oauthState;
$_SESSION['oauth_nonce'] = $oauthNonce;

$authUrl = "https://login.microsoftonline.com/{$TENANT_ID}/oauth2/v2.0/authorize?" . http_build_query([
  'client_id' => $CLIENT_ID,
  'response_type' => 'code',
  'redirect_uri' => $REDIRECT_URI,
  'response_mode' => 'query',
  'scope' => 'openid profile email',
  'state' => $oauthState,
  'nonce' => $oauthNonce,
]);

header("Location: $authUrl");
session_write_close();
exit;
