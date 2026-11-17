<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/app.php';

$username = strtolower(trim($argv[1] ?? ''));
if ($argc !== 2 || !preg_match('/\A[a-z0-9_]{3,32}\z/', $username)) {
    fwrite(STDERR, "Usage: php promote-admin.php <registered-username>\n");
    exit(1);
}

try {
    $db = connectDatabase();
    $changed = query('UPDATE users SET admin = 1, session_version = session_version + 1
                      WHERE username = ? AND admin = 0', [$username])->rowCount();
    if ($changed) {
        fwrite(STDOUT, "Administrator access granted to $username. Log in again to use Manage users.\n");
    } elseif (query('SELECT admin FROM users WHERE username = ?', [$username])->fetchColumn()) {
        fwrite(STDOUT, "$username already has administrator access.\n");
    } else {
        fwrite(STDERR, "Account not found. Register $username before granting administrator access.\n");
        exit(1);
    }
} catch (PDOException $error) {
    fwrite(STDERR, "Could not update the account. Check the database connection and schema.\n");
    exit(1);
}
