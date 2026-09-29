<?php
// Zorg dat echt een 403 status wordt teruggegeven
http_response_code(403);

require_once __DIR__ . '/403_context.php';
require_once __DIR__ . '/session_user.php';

start_app_session();

$userContext = get_session_user_context();
$userEmail = (string) ($userContext['email'] ?? '');
$userApiKey = (string) ($userContext['api_key'] ?? '');
$userOid = (string) ($userContext['oid'] ?? '');
$isLoggedIn = $userContext !== null;

$pageContext = resolve_403_page_context(
    (string) ($_SERVER['REQUEST_URI'] ?? ''),
    isset($_GET['test_page']) ? (string) $_GET['test_page'] : null,
    can_use_403_test_mode($isLoggedIn)
);
$deniedPagePath = $pageContext['page_name'];
$displayUri = $pageContext['display_uri'];
$isTestMode = $pageContext['is_test_mode'];

if ($isLoggedIn && $deniedPagePath !== '') {
    $_SESSION['access_request_page'] = $deniedPagePath;
    set_access_request_page_cookie($deniedPagePath);
}

session_write_close();
?>
<!DOCTYPE html>
<html lang="nl">

<head>
    <meta charset="utf-8">
    <title>403 � Geen Toegang</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        html,
        body {
            margin: 0;
            padding: 0;
            min-height: 100%;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f4f6f8;
            color: #333;
        }

        .container {
            min-height: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 40px 20px;
        }

        .logo {
            max-width: 280px;
            margin-bottom: 40px;
        }

        h1 {
            font-size: 3rem;
            margin: 0 0 10px 0;
        }

        p {
            font-size: 1.1rem;
            margin: 0 0 30px 0;
            color: #555;
        }

        .url {
            font-family: monospace;
            background: #e9ecef;
            padding: 8px 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            display: inline-block;
            max-width: 100%;
            word-break: break-all;
        }

        .help-text {
            font-size: 0.95rem;
            color: #666;
            margin-bottom: 24px;
            max-width: 560px;
        }

        .button,
        button.button {
            display: inline-block;
            padding: 10px 18px;
            background: #005aa7;
            color: #fff;
            text-decoration: none;
            border-radius: 4px;
            transition: background 0.2s;
            border: 0;
            font: inherit;
            cursor: pointer;
        }

        .button:hover,
        button.button:hover {
            background: #004a8a;
        }

        button.button:disabled {
            background: #7a9fc4;
            cursor: wait;
        }

        .button-secondary {
            background: #fff;
            color: #005aa7;
            border: 1px solid #005aa7;
        }

        .button-secondary:hover {
            background: #eef4fa;
        }

        .access-panel {
            display: none;
            width: min(720px, 100%);
            margin-top: 8px;
            text-align: left;
            background: #fff;
            border: 1px solid #d8dee4;
            border-radius: 8px;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
            overflow: hidden;
        }

        .access-panel.visible {
            display: block;
        }

        .access-panel-header {
            padding: 18px 20px;
            border-bottom: 1px solid #e9ecef;
            background: #f8fafc;
        }

        .access-panel-header h2 {
            margin: 0 0 8px 0;
            font-size: 1.15rem;
            color: #1f2937;
        }

        .access-status {
            margin: 0;
            color: #166534;
            font-size: 0.95rem;
        }

        .access-status.error {
            color: #b91c1c;
        }

        .ticket-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px 16px;
            margin-top: 12px;
            font-size: 0.9rem;
            color: #4b5563;
        }

        .ticket-meta strong {
            color: #111827;
        }

        .ticket-messages {
            padding: 16px 20px 8px;
        }

        .ticket-messages h3 {
            margin: 0 0 12px 0;
            font-size: 0.95rem;
            color: #374151;
        }

        .message-item {
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 12px 14px;
            margin-bottom: 10px;
            background: #fff;
        }

        .message-item.admin {
            border-left: 4px solid #005aa7;
        }

        .message-item.user {
            border-left: 4px solid #6b7280;
        }

        .message-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 8px;
            font-size: 0.82rem;
            color: #6b7280;
        }

        .message-meta strong {
            color: #111827;
        }

        .message-text {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.5;
        }

        .access-panel-footer {
            padding: 16px 20px 20px;
            border-top: 1px solid #e9ecef;
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            align-items: center;
            justify-content: space-between;
        }

        .read-only-note {
            margin: 0;
            font-size: 0.85rem;
            color: #6b7280;
        }

        footer {
            margin-top: 50px;
            font-size: 0.9rem;
            color: #888;
        }
    </style>
</head>

<body>
    <div class="container">

        <img class="logo" src="https://sleutels.kvt.nl/kvt_logo.png" alt="KVT logo">

        <h1>403</h1>
        <p>U heeft geen toegang tot de opgevraagde pagina.</p>

        <div class="url">
            <?= htmlspecialchars($displayUri) ?>
        </div>

        <?php if ($isTestMode): ?>
            <p class="help-text" style="color: #92400e; background: #fffbeb; padding: 8px 12px; border-radius: 4px;">
                Testmodus: deze pagina simuleert geen toegang tot <?= htmlspecialchars($displayUri) ?>.
            </p>
        <?php endif; ?>

        <?php if ($isLoggedIn): ?>
            <button type="button" class="button" id="request-access-btn"
                data-requested-path="<?= htmlspecialchars($deniedPagePath, ENT_QUOTES) ?>">Toegang aanvragen</button>

            <div class="access-panel" id="access-panel" aria-live="polite">
                <div class="access-panel-header">
                    <h2 id="ticket-title"></h2>
                    <p class="access-status" id="access-status"></p>
                    <div class="ticket-meta" id="ticket-meta"></div>
                </div>
                <div class="ticket-messages" id="ticket-messages-wrap" hidden>
                    <h3>Berichten</h3>
                    <div id="ticket-messages"></div>
                </div>
                <div class="access-panel-footer">
                    <p class="read-only-note">Dit is een alleen-lezen voorbeeld. Om te reageren op uw ticket, open Asclepius.</p>
                    <a class="button button-secondary" id="ticket-link" href="#" target="_blank" rel="noopener">Bekijk uw ticket op Asclepius</a>
                </div>
            </div>
        <?php else: ?>
            <p class="help-text">
                Als dit niet juist is, maak dan een ticket aan op Asclepius onder de categorie
                &quot;sleutels.kvt.nl web-applicatieproblemen&quot;.
            </p>
        <?php endif; ?>

        <footer>
            Koninklijke van Twist
        </footer>

    </div>

    <?php if ($isLoggedIn): ?>
        <script>
            (function () {
                const requestButton = document.getElementById('request-access-btn');
                const requestedPagePath = <?= json_encode($deniedPagePath, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>
                    || (requestButton ? (requestButton.dataset.requestedPath || '') : '');
                const userEmail = <?= json_encode($userEmail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
                const userApiKey = <?= json_encode($userApiKey, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
                const userOid = <?= json_encode($userOid, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) ?>;
                const accessPanel = document.getElementById('access-panel');
                const accessStatus = document.getElementById('access-status');
                const ticketTitle = document.getElementById('ticket-title');
                const ticketMeta = document.getElementById('ticket-meta');
                const ticketMessagesWrap = document.getElementById('ticket-messages-wrap');
                const ticketMessages = document.getElementById('ticket-messages');
                const ticketLink = document.getElementById('ticket-link');

                function escapeHtml(value) {
                    return String(value)
                        .replace(/&/g, '&amp;')
                        .replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;')
                        .replace(/"/g, '&quot;')
                        .replace(/'/g, '&#39;');
                }

                function renderMetaItem(label, value) {
                    return '<span><strong>' + escapeHtml(label) + ':</strong> ' + escapeHtml(value) + '</span>';
                }

                function renderTicket(data) {
                    const ticket = data.ticket || {};
                    const messages = Array.isArray(data.messages) ? data.messages : [];

                    ticketTitle.textContent = ticket.title || 'Toegangsaanvraag';
                    accessStatus.textContent = data.message || '';
                    accessStatus.classList.remove('error');

                    ticketMeta.innerHTML = [
                        renderMetaItem('Ticket', '#' + (ticket.id || '')),
                        renderMetaItem('Status', ticket.status_label || ticket.status || ''),
                        renderMetaItem('Categorie', ticket.category_label || ticket.category || ''),
                        renderMetaItem('Aangemaakt', ticket.created_at || ''),
                        renderMetaItem('Laatst bijgewerkt', ticket.updated_at || ''),
                    ].join('');

                    if (messages.length > 0) {
                        ticketMessagesWrap.hidden = false;
                        ticketMessages.innerHTML = messages.map(function (message) {
                            const roleClass = message.sender_role === 'admin' ? 'admin' : 'user';
                            const roleLabel = message.sender_role === 'admin' ? 'ICT' : 'Gebruiker';
                            return (
                                '<article class="message-item ' + roleClass + '">' +
                                    '<div class="message-meta">' +
                                        '<strong>' + escapeHtml(message.sender_label || message.sender_email || 'Onbekend') + '</strong>' +
                                        '<span>' + escapeHtml(roleLabel) + '</span>' +
                                        '<span>' + escapeHtml(message.created_at || '') + '</span>' +
                                    '</div>' +
                                    '<p class="message-text">' + escapeHtml(message.message_text || '') + '</p>' +
                                '</article>'
                            );
                        }).join('');
                    } else {
                        ticketMessagesWrap.hidden = true;
                        ticketMessages.innerHTML = '';
                    }

                    if (data.ticket_url) {
                        ticketLink.href = data.ticket_url;
                    }

                    accessPanel.classList.add('visible');
                    requestButton.hidden = true;
                }

                function showError(message) {
                    accessStatus.textContent = message;
                    accessStatus.classList.add('error');
                    accessPanel.classList.add('visible');
                }

                requestButton.addEventListener('click', function () {
                    if (!requestedPagePath) {
                        showError('De pagina kon niet worden bepaald.');
                        return;
                    }

                    requestButton.disabled = true;
                    requestButton.textContent = 'Bezig met aanvragen...';

                    const requestUrl = '/login/access_request.php?requested_path='
                        + encodeURIComponent(requestedPagePath);
                    const requestParams = new URLSearchParams();
                    requestParams.set('page_name', requestedPagePath);
                    requestParams.set('requested_path', requestedPagePath);
                    requestParams.set('user_email', userEmail);
                    requestParams.set('api_key', userApiKey);
                    requestParams.set('oid', userOid);

                    fetch(requestUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Accept': 'application/json',
                            'X-API-Key': userApiKey,
                            'X-Requested-Path': requestedPagePath,
                        },
                        credentials: 'same-origin',
                        body: requestParams.toString(),
                    })
                        .then(function (response) {
                            return response.json().then(function (data) {
                                return { ok: response.ok, data: data };
                            });
                        })
                        .then(function (result) {
                            if (!result.ok || !result.data || !result.data.success) {
                                const errorCode = result.data && result.data.error ? String(result.data.error) : '';
                                const errorSource = result.data && result.data.source ? String(result.data.source) : '';
                                const errorMessages = {
                                    not_logged_in: 'U bent niet ingelogd.',
                                    page_name_required: errorSource === 'asclepius'
                                        ? 'Asclepius ontving geen paginanaam. Staat de nieuwste api.php al live?'
                                        : 'De pagina kon niet worden bepaald.',
                                    asclepius_unreachable: 'Asclepius is tijdelijk niet bereikbaar.',
                                    invalid_asclepius_response: 'Asclepius gaf een ongeldig antwoord.',
                                    unauthorized: 'U bent niet gemachtigd om deze aanvraag te doen.',
                                    invalid_user: 'Uw e-mailadres kon niet worden bepaald.',
                                };
                                let errorMessage = errorMessages[errorCode]
                                    || (result.data && result.data.message ? String(result.data.message) : '');
                                if (!errorMessage && result.data && Array.isArray(result.data.errors) && result.data.errors.length > 0) {
                                    errorMessage = 'Asclepius-api nog niet bijgewerkt: ' + result.data.errors.join(' ');
                                }
                                if (!errorMessage) {
                                    errorMessage = 'De aanvraag kon niet worden verwerkt.';
                                }
                                throw new Error(errorMessage);
                            }

                            renderTicket(result.data);
                        })
                        .catch(function (error) {
                            requestButton.hidden = true;
                            showError(error && error.message ? error.message : 'Er is een onverwachte fout opgetreden.');
                        });
                });
            })();
        </script>
    <?php endif; ?>
</body>

</html>
