<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require __DIR__ . '/app.php';

$usage = "Usage: php seed-demo.php [--with-photos | <nice-cat> <standard-cat> <premium-cat>]\n"
    . "Use this script only with a local or test database. Configure DB_DSN, DB_USER and DB_PASSWORD as for the app.\n"
    . "With no arguments, the script creates only the demo accounts. Use --with-photos to import the bundled photos.\n"
    . "Initial passwords are listed in README.md and printed when accounts are created.\n";
if ($argc === 2 && $argv[1] === '--help') {
    fwrite(STDOUT, $usage);
    exit;
}
$useBundledPhotos = $argc === 2 && $argv[1] === '--with-photos';
if ($argc !== 1 && !$useBundledPhotos && $argc !== 4) {
    fwrite(STDERR, $usage);
    exit(1);
}

$accounts = [
    'admin' => [0, 1, 'Admin2026!@#'],
    'alice' => [1, 0, 'AlicePassword2026!'],
    'bob' => [0, 0, 'BobPassword2026!'],
];
$photos = [
    ['admin', 'nice cat', 0, 'nice-cat.jpg'],
    ['bob', 'standard cat', 0, 'standard-cat.jpg'],
    ['alice', 'premium cat', 1, 'premium-cat.jpg'],
];
$created = [];
$accountIds = [];
$preparedPhotos = [];
$addedPhotos = 0;
$db = null;

try {
    if ($useBundledPhotos || $argc === 4) {
        if (!extension_loaded('gd')) {
            throw new RuntimeException('Enable the PHP GD extension to import photos.');
        }
        foreach ($photos as $index => [$owner, $description, $premium, $filename]) {
            $path = $useBundledPhotos ? __DIR__ . '/demo/photos/' . $filename : $argv[$index + 1];
            $bytes = is_file($path) ? @file_get_contents($path, false, null, 0, UPLOAD_LIMIT + 1) : false;
            if ($bytes === false) {
                throw new RuntimeException("Cannot read the photo for \"$description\": $path");
            }
            if (strlen($bytes) > UPLOAD_LIMIT) {
                throw new RuntimeException("The photo for \"$description\" exceeds " . UPLOAD_LIMIT_MB . " MB.");
            }
            $image = prepareImage($bytes, 'original');
            if (is_string($image)) {
                throw new RuntimeException("Cannot import the photo for \"$description\" ($image). Use JPEG, PNG or BMP within the upload limits.");
            }
            $preparedPhotos[] = [$owner, $description, $premium, ...$image];
        }
    }

    $db = connectDatabase();
    $db->beginTransaction();
    foreach ($accounts as $username => [$premium, $admin, $password]) {
        $email = "$username@example.test";
        $account = query('SELECT id, email, premium, admin FROM users WHERE username = ? FOR UPDATE',
            [$username])->fetch();
        if ($account) {
            if ($account['email'] !== $email || (int) $account['premium'] !== $premium
                || (int) $account['admin'] !== $admin) {
                throw new RuntimeException("The existing account \"$username\" does not match the demo account.");
            }
            $accountIds[$username] = (int) $account['id'];
            continue;
        }

        if (!validPassword($password)) {
            throw new RuntimeException("The demo password for \"$username\" does not meet the app password policy.");
        }
        query('INSERT INTO users (username, email, password_hash, premium, admin) VALUES (?, ?, ?, ?, ?)',
            [$username, $email, passwordHash($password), $premium, $admin]);
        $accountIds[$username] = (int) $db->lastInsertId();
        $created[$username] = $password;
    }

    foreach ($preparedPhotos as [$owner, $description, $premium, $mime, $bytes]) {
        $userId = $accountIds[$owner];
        $exists = query('SELECT id FROM photos WHERE user_id = ? AND description = ? AND premium = ?
                         AND mime = ? AND image = CAST(? AS BINARY) LIMIT 1',
            [$userId, $description, $premium, $mime, $bytes])->fetchColumn();
        if ($exists === false) {
            query('INSERT INTO photos (user_id, description, premium, mime, image) VALUES (?, ?, ?, ?, ?)',
                [$userId, $description, $premium, $mime, $bytes]);
            $addedPhotos++;
        }
    }
    $db->commit();
} catch (Throwable $error) {
    if ($db?->inTransaction()) {
        $db->rollBack();
    }
    $message = $error instanceof PDOException
        ? 'Check the database connection, schema and whether the demo usernames or emails are already in use.'
        : $error->getMessage();
    fwrite(STDERR, "Demo seed failed. $message\n");
    exit(1);
}

foreach ($accounts as $username => [$premium, $admin]) {
    $role = $admin ? 'Administrator' : ($premium ? 'Premium' : 'Standard');
    $status = isset($created[$username]) ? 'created' : 'already present';
    fwrite(STDOUT, "$username ($role): $status\n");
    if (isset($created[$username])) {
        fwrite(STDOUT, "  Password: $created[$username]\n");
    }
}
fwrite(STDOUT, "Photos added: $addedPhotos\n");
