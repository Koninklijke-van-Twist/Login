# Login (sleutels.kvt.nl)

Gedeelde Entra ID (Azure AD) SSO voor apps op [sleutels.kvt.nl](https://sleutels.kvt.nl/).
Live pad: `https://sleutels.kvt.nl/login/` ← `web/` → `/var/www/html/login/` via FTP op push naar `master`.

## Layout

- **Page root:** `web/` (zoals andere sleutels-apps)
- Apps doen `require __DIR__ . '/../login/lib.php'` (sibling van de app-map)
- Sessie: `session_config.php` → `configure_app_session()` **vóór** `session_start()` (zie Asclepius/Forum-Magnum). Als een app de sessie al startte, doet configure veilig een no-op (geen PHP-warnings).

## Secrets

`web/cfg.php` staat **niet** in git. Eenmalig op de server (en lokaal) zetten vanuit `web/cfg_TEMPLATE.php`:

```bash
cp web/cfg_TEMPLATE.php web/cfg.php
# vul client_secret + asclepius_api_key
```

FTP-deploy overschrijft `cfg.php` niet en raakt `data/` (map + inhoud) helemaal niet aan, zodat schrijfrechten op de server blijven.

## Deploy

Secrets op de GitHub-repo:

| Secret | Voorbeeld |
|--------|-----------|
| `FTP_HOST` | FTP-host |
| `FTP_USERNAME` | gebruiker |
| `FTP_PASSWORD` | wachtwoord |
| `FTP_REMOTE_DIR` | `/var/www/html/login` |

## Lokaal

```bash
cp web/cfg_TEMPLATE.php web/cfg.php
php -S localhost:8765 -t web
```

Tests: `php tests/run-tests.php` (vanaf repo-root; past paden aan indien nodig).
