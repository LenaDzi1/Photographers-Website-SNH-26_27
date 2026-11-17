<?php
require dirname(__DIR__) . '/app.php';

ini_set('display_errors', '0');
date_default_timezone_set('UTC');
header("Content-Security-Policy: default-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header('Content-Type: text/html; charset=utf-8');

$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path !== '/' && $path !== '/index.php') {
    deny(404, 'Page unavailable.');
}

session_start([
    'use_strict_mode' => true,
    'use_only_cookies' => true,
    'cookie_httponly' => true,
    'cookie_secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'cookie_samesite' => 'Lax',
]);
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

try {
    $db = connectDatabase();
    $db->exec("SET time_zone = '+00:00'");

    $user = null;
    if (isset($_SESSION['user_id'])) {
        if (time() - $_SESSION['last_seen'] < 1800) {
            $user = query('SELECT * FROM users WHERE id = ? AND session_version = ?',
                [$_SESSION['user_id'], $_SESSION['version']])->fetch() ?: null;
        } else {
            audit('session_expired', $_SESSION['user_id']);
        }
        if (!$user) {
            $_SESSION = ['csrf' => bin2hex(random_bytes(32))];
            session_regenerate_id(true);
        } else {
            $_SESSION['last_seen'] = time();
        }
    }
    $userId = $user['id'] ?? null;
    $canViewPremium = !empty($user['premium']) || !empty($user['admin']);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!hash_equals($_SESSION['csrf'], post('csrf'))) {
            audit('csrf_rejected', $userId);
            deny(403, 'Invalid form. Reload the page and try again.');
        }

        $action = post('action');
        $password = post('password');
        $username = strtolower(trim(post('username')));
        $validUsername = preg_match('/\A[a-z0-9_]{3,32}\z/', $username) === 1;
        $email = strtolower(trim(post('email')));
        $validEmail = strlen($email) <= 254 && filter_var($email, FILTER_VALIDATE_EMAIL);

        if (in_array($action, ['upload', 'logout', 'change_password', 'request_premium', 'premium',
                'decline_premium', 'revoke_sessions', 'start_delete_user', 'delete_user'], true) && !$user) {
            audit('login_required', null, $action);
            deny(403, 'Log in first.');
        }

        switch ($action) {
            case 'register':
                $registered = 'If the username and email were available, you can now log in.';
                limitAttempts($action, 10, $userId);
                if (!$validUsername || !$validEmail || !validPassword($password)) {
                    audit('registration_rejected', $userId);
                    redirect('Use a valid email, a username with 3–32 letters, digits or underscores, and a password of 12–72 bytes.', 'index.php?view=signup');
                }
                $hash = passwordHash($password);
                $db->beginTransaction();
                try {
                    query('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                        [$username, $email, $hash]);
                } catch (PDOException $error) {
                    if (($error->errorInfo[1] ?? null) !== 1062) {
                        throw $error;
                    }
                    $db->rollBack();
                    audit('registration_rejected', $userId, $username);
                    redirect($registered);
                }
                audit('registered', (int) $db->lastInsertId());
                $db->commit();
                redirect($registered);

            case 'login':
                limitAttempts($action, 20, $userId);
                if ($validUsername) {
                    limitAttempts($action, 10, $userId, $username);
                }
                $account = $validUsername
                    ? query('SELECT * FROM users WHERE username = ?', [$username])->fetch()
                    : false;
                if (!$account && validPassword($password)) {
                    passwordHash($password);
                }
                if (!$account || !validPassword($password) || !password_verify($password, $account['password_hash'])) {
                    audit('login_failed', $account['id'] ?? null, $validUsername ? $username : '');
                    redirect('Invalid username or password.');
                }
                audit('login_succeeded', $account['id']);
                session_regenerate_id(true);
                $_SESSION = [
                    'user_id' => $account['id'],
                    'version' => $account['session_version'],
                    'last_seen' => time(),
                    'csrf' => bin2hex(random_bytes(32)),
                ];
                redirect('Logged in.');

            case 'logout':
                audit('logout', $userId);
                $_SESSION = [];
                session_regenerate_id(true);
                redirect('Logged out.');

            case 'change_password':
                limitAttempts($action, 10, $userId);
                $current = post('current_password');
                if (!validPassword($current) || !password_verify($current, $user['password_hash'])) {
                    audit('password_change_rejected', $userId);
                    redirect('Current password is incorrect.', 'index.php?view=account');
                }
                if (!validPassword($password)) {
                    redirect('Use a new password of 12–72 bytes.', 'index.php?view=account');
                }
                $db->beginTransaction();
                $updated = query('UPDATE users SET password_hash = ?, session_version = session_version + 1,
                                  reset_hash = NULL, reset_expires = NULL WHERE id = ? AND session_version = ?',
                    [passwordHash($password), $userId, $user['session_version']])->rowCount();
                if (!$updated) {
                    $db->rollBack();
                    redirect('Your account changed. Log in again.');
                }
                audit('password_changed', $userId);
                $db->commit();
                session_regenerate_id(true);
                $_SESSION['version'] = $user['session_version'] + 1;
                $_SESSION['csrf'] = bin2hex(random_bytes(32));
                redirect('Password changed.', 'index.php?view=account');

            case 'request_premium':
                $db->beginTransaction();
                $changed = query('UPDATE users SET premium_requested = 1
                                  WHERE id = ? AND premium = 0 AND admin = 0 AND premium_requested = 0',
                    [$userId])->rowCount();
                if ($changed) {
                    audit('premium_requested', $userId);
                }
                $db->commit();
                redirect($changed ? 'Premium request submitted.' : 'No new Premium request was needed.', 'index.php?view=account');

            case 'recover':
                limitAttempts($action, 5, $userId);
                $accountId = $validEmail
                    ? query('SELECT id FROM users WHERE email = ?', [$email])->fetchColumn()
                    : false;
                if ($accountId) {
                    $token = bin2hex(random_bytes(32));
                    $db->beginTransaction();
                    query('UPDATE users SET reset_hash = ?, reset_expires = UTC_TIMESTAMP() + INTERVAL 30 MINUTE
                           WHERE id = ?', [hash('sha256', $token), $accountId]);
                    writeRecoveryEmail($accountId, $email, $token);
                    audit('reset_requested', $accountId);
                    $db->commit();
                } else {
                    audit('reset_requested');
                }
                redirect('If the email belongs to an account, a reset link has been sent.');

            case 'reset':
                limitAttempts($action, 10, $userId);
                $token = post('token');
                if (!preg_match('/\A[a-f0-9]{64}\z/', $token) || !validPassword($password)) {
                    audit('reset_rejected', $userId);
                    redirect('Use a valid reset link and a new password of 12–72 bytes.');
                }
                $hash = hash('sha256', $token);
                $db->beginTransaction();
                $accountId = query('SELECT id FROM users WHERE reset_hash = ? AND reset_expires > UTC_TIMESTAMP()
                                    FOR UPDATE', [$hash])->fetchColumn();
                if (!$accountId) {
                    $db->rollBack();
                    audit('reset_rejected', $userId);
                    redirect('This reset link is invalid or has expired.');
                }
                query('UPDATE users SET password_hash = ?, reset_hash = NULL, reset_expires = NULL,
                       session_version = session_version + 1 WHERE id = ?', [passwordHash($password), $accountId]);
                audit('password_reset', $accountId);
                $db->commit();
                redirect('Password reset. Log in with your new password.');

            case 'upload':
                $premium = post('premium') === '1' ? 1 : 0;
                if ($premium && !$canViewPremium) {
                    deny(403, 'Premium access is required to upload Premium photos.');
                }
                $description = trim(post('description'));
                if (!preg_match('/\A.{1,1000}\z/us', $description)) {
                    audit('upload_rejected', $userId, 'description');
                    redirect('Enter a description between 1 and 1,000 characters.', 'index.php?view=upload');
                }
                $orientation = post('orientation') ?: 'original';
                if (!in_array($orientation, ['original', 'portrait', 'landscape'], true)) {
                    redirect('Choose an available photo orientation.', 'index.php?view=upload');
                }
                $image = uploadedImage($orientation);
                if (is_string($image)) {
                    audit('upload_rejected', $userId, $image);
                    $message = match ($image) {
                        'missing' => 'Choose a photo to upload.',
                        'too_large' => 'The file is larger than ' . UPLOAD_LIMIT_MB . ' MB.',
                        'format' => 'Choose a JPEG, PNG or BMP image.',
                        'dimensions' => 'The image exceeds ' . UPLOAD_LIMIT_MEGAPIXELS . ' megapixels. Resize it and try again.',
                        'decode' => 'The image could not be opened. Export it again and retry.',
                        'stored_size' => 'The processed image is too large to save. Resize it and try again.',
                        'encode' => 'The image could not be processed. Try another file.',
                        default => 'The file did not upload completely. Try again.',
                    };
                    redirect($message, 'index.php?view=upload');
                }
                [$mime, $bytes] = $image;
                $db->beginTransaction();
                $saved = query('INSERT INTO photos (user_id, description, premium, mime, image)
                                SELECT id, ?, ?, ?, ? FROM users
                                WHERE id = ? AND (? = 0 OR premium = 1 OR admin = 1)',
                    [$description, $premium, $mime, $bytes, $userId, $premium])->rowCount();
                if (!$saved) {
                    $db->rollBack();
                    deny(403, 'Your account no longer has access to upload this photo.');
                }
                audit('photo_uploaded', $userId, $db->lastInsertId());
                $db->commit();
                redirect('Photo uploaded.', 'index.php?view=gallery');

            case 'premium':
            case 'decline_premium':
            case 'revoke_sessions':
            case 'start_delete_user':
            case 'delete_user':
                if (!$user['admin']) {
                    audit('admin_denied', $userId);
                    deny(403, 'Administrator access required.');
                }
                $accountId = filter_input(INPUT_POST, 'account_id', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
                if (!$accountId) {
                    deny(400, 'Invalid account.');
                }
                if ($action === 'start_delete_user' || $action === 'delete_user') {
                    if ($accountId === (int) $userId) {
                        deny(400, 'You cannot delete your own account.');
                    }
                    if ($action === 'start_delete_user') {
                        $accountName = query('SELECT username FROM users WHERE id = ?', [$accountId])->fetchColumn();
                        if ($accountName === false) {
                            redirect('Account unavailable.', 'index.php?admin=1');
                        }
                        $_SESSION['delete_user'] = [
                            'id' => $accountId,
                            'username' => $accountName,
                            'token' => bin2hex(random_bytes(16)),
                            'expires' => time() + 300,
                        ];
                        redirect('Review the account before deleting it.', 'index.php?admin=1&confirm_delete=1');
                    }
                    $confirmation = $_SESSION['delete_user'] ?? null;
                    if (!$confirmation || $confirmation['expires'] < time() || $confirmation['id'] !== $accountId
                        || !hash_equals($confirmation['token'], post('delete_token'))) {
                        redirect('Start a new deletion confirmation.', 'index.php?admin=1');
                    }
                    if (post('confirm_username') !== $confirmation['username']) {
                        redirect('Enter the username shown to confirm deletion.', 'index.php?admin=1&confirm_delete=1');
                    }
                    $db->beginTransaction();
                    $roles = query('SELECT id, admin FROM users WHERE id IN (?, ?) ORDER BY id FOR UPDATE',
                        [$userId, $accountId])->fetchAll(PDO::FETCH_KEY_PAIR);
                    if (empty($roles[$userId]) || !isset($roles[$accountId])) {
                        $db->rollBack();
                        unset($_SESSION['delete_user']);
                        redirect('The account could not be deleted.', 'index.php?admin=1');
                    }
                    query('DELETE FROM photos WHERE user_id = ?', [$accountId]);
                    query('DELETE FROM users WHERE id = ?', [$accountId]);
                    audit('user_deleted', $userId, (string) $accountId);
                    $db->commit();
                    unset($_SESSION['delete_user']);
                    redirect('User and uploaded photos deleted.', 'index.php?admin=1');
                }
                if ($action === 'revoke_sessions') {
                    if ($accountId === (int) $userId) {
                        deny(400, 'Use Log out to end your own session.');
                    }
                    $db->beginTransaction();
                    $changed = query('UPDATE users SET session_version = session_version + 1 WHERE id = ?',
                        [$accountId])->rowCount();
                    if ($changed) {
                        audit('sessions_revoked', $userId, (string) $accountId);
                    }
                    $db->commit();
                    redirect($changed ? 'User sessions ended.' : 'Account unavailable.', 'index.php?admin=1');
                }
                if ($action === 'decline_premium') {
                    $db->beginTransaction();
                    $changed = query('UPDATE users SET premium_requested = 0 WHERE id = ? AND premium_requested = 1',
                        [$accountId])->rowCount();
                    if ($changed) {
                        audit('premium_declined', $userId, (string) $accountId);
                    }
                    $db->commit();
                    redirect($changed ? 'Premium request declined.' : 'No pending Premium request.', 'index.php?admin=1');
                }
                $premium = post('premium');
                if (!in_array($premium, ['0', '1'], true)) {
                    deny(400, 'Invalid access level.');
                }
                $db->beginTransaction();
                $changed = query('UPDATE users SET premium = ?, premium_requested = IF(? = 1, 0, premium_requested)
                                  WHERE id = ? AND admin = 0', [$premium, $premium, $accountId])->rowCount();
                if ($changed) {
                    audit($premium === '1' ? 'premium_granted' : 'premium_revoked', $userId, (string) $accountId);
                }
                $db->commit();
                redirect($changed ? 'Premium access updated.' : 'No access change was made.', 'index.php?admin=1');

            default:
                deny(400, 'Unknown form action.');
        }
    }

    if (isset($_GET['photo'])) {
        $id = filter_input(INPUT_GET, 'photo', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        if (!$user) {
            audit('photo_denied', null, (string) $id);
            deny(403, 'Log in first.');
        }
        $photo = $id
            ? query('SELECT mime, image FROM photos WHERE id = ? AND (premium = 0 OR ? = 1)',
                [$id, (int) $canViewPremium])->fetch()
            : false;
        if (!$photo) {
            audit('photo_unavailable', $userId, (string) $id);
            deny(404, 'Photo unavailable.');
        }
        $download = isset($_GET['download']);
        $extensions = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/bmp' => 'bmp'];
        $name = 'photo-' . $id . '.' . $extensions[$photo['mime']];
        audit($download ? 'photo_downloaded' : 'photo_viewed', $userId, (string) $id);
        header('Content-Type: ' . $photo['mime']);
        header('Content-Length: ' . strlen($photo['image']));
        header('Content-Disposition: ' . ($download ? 'attachment' : 'inline') . '; filename="' . $name . '"');
        exit($photo['image']);
    }

    $view = $_GET['view'] ?? ($user ? 'gallery' : 'login');
    if (!in_array($view, ['gallery', 'login', 'signup', 'account', 'upload'], true)) {
        deny(404, 'Page unavailable.');
    }
    if (isset($_GET['reset'])) {
        $view = 'reset';
    } elseif (isset($_GET['admin'])) {
        $view = 'admin';
    }
    if ($view === 'admin' && empty($user['admin'])) {
        audit('admin_denied', $userId, 'view_users');
        deny(403, 'Administrator access required.');
    }
    if (!$user && in_array($view, ['gallery', 'account', 'upload'], true)) {
        redirect('Log in to continue.', 'index.php?view=login');
    }
    if ($user && in_array($view, ['login', 'signup'], true)) {
        header('Location: index.php?view=gallery', true, 303);
        exit;
    }
    $photos = $view === 'gallery'
        ? query('SELECT photos.id, CASE WHEN photos.premium = 0 OR ? = 1 THEN description END AS description,
                        photos.premium, username
                 FROM photos JOIN users ON users.id = photos.user_id ORDER BY photos.id DESC',
            [(int) $canViewPremium])->fetchAll()
        : [];
    $deleteConfirmation = $view === 'admin' && isset($_GET['confirm_delete']) ? ($_SESSION['delete_user'] ?? null) : null;
    if ($view === 'admin' && !$deleteConfirmation) {
        unset($_SESSION['delete_user']);
    }
    if ($deleteConfirmation && $deleteConfirmation['expires'] < time()) {
        unset($_SESSION['delete_user']);
        redirect('The deletion confirmation expired.', 'index.php?admin=1');
    }
    $accounts = $view === 'admin' && !$deleteConfirmation
        ? query('SELECT id, username, email, premium, admin, premium_requested
                 FROM users ORDER BY premium_requested DESC, username')->fetchAll()
        : [];
} catch (Throwable $error) {
    if (isset($db) && $db->inTransaction()) {
        $db->rollBack();
    }
    error_log('Photographers application error: ' . get_class($error) . ' (' . $error->getCode() . ')');
    deny(500, 'The site could not complete the request. Check the server configuration and logs.');
}

$message = $_SESSION['message'] ?? '';
unset($_SESSION['message']);
$csrf = escape($_SESSION['csrf']);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Photographers</title>
    <link rel="stylesheet" href="upload.css">
    <script src="app.js" defer></script>
</head>
<body>
<main>
    <h1 class="site-title">
        Photographers
        <?php if ($canViewPremium && $view !== 'reset'): ?>
            <span class="premium-badge">Premium</span>
        <?php endif; ?>
    </h1>
    <?php if ($user && $view !== 'reset'): ?>
        <nav aria-label="Main">
            <a href="index.php?view=gallery"<?= $view === 'gallery' ? ' aria-current="page"' : '' ?>>Gallery</a> |
            <a href="index.php?view=account"<?= $view === 'account' ? ' aria-current="page"' : '' ?>>Account settings</a> |
            <a href="index.php?view=upload"<?= $view === 'upload' ? ' aria-current="page"' : '' ?>>Upload a photo</a>
        </nav>
    <?php endif; ?>
    <?php if ($message !== ''): ?>
        <p role="status"><?= escape($message) ?></p>
    <?php endif; ?>

    <?php if ($view === 'reset'): ?>
        <h2>Reset password</h2>
        <form method="post" action="index.php">
            <input type="hidden" name="action" value="reset">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <input type="hidden" name="token" id="reset-token">
            <label>New password <input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="72" required></label>
            <button id="reset-button" disabled>Reset password</button>
            <p id="reset-error" hidden>This reset link is incomplete. Request a new one.</p>
            <noscript><p>Enable JavaScript and reopen the reset link.</p></noscript>
        </form>
        <p><a href="index.php">Back to Photographers</a></p>
    <?php elseif ($deleteConfirmation): ?>
        <h2>Confirm account deletion</h2>
        <form method="post" action="index.php?admin=1">
            <input type="hidden" name="action" value="delete_user">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <input type="hidden" name="account_id" value="<?= (int) $deleteConfirmation['id'] ?>">
            <input type="hidden" name="delete_token" value="<?= escape($deleteConfirmation['token']) ?>">
            <p>Deleting this account also permanently deletes all photos it uploaded.</p>
            <label>Type <strong><?= escape($deleteConfirmation['username']) ?></strong> to confirm
                <input name="confirm_username" maxlength="32" autocomplete="off" required>
            </label>
            <button class="danger-button">Permanently delete account</button>
            <p><a href="index.php?admin=1">Cancel</a></p>
        </form>
    <?php elseif ($view === 'admin'): ?>
        <h2>Manage users</h2>
        <table>
            <thead>
                <tr><th scope="col">Username</th><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Access</th><th scope="col">Premium request</th><th scope="col">Sessions</th><th scope="col">Account</th></tr>
            </thead>
            <tbody>
                <?php foreach ($accounts as $account): ?>
                    <tr>
                        <th scope="row"><?= escape($account['username']) ?></th>
                        <td><?= escape($account['email']) ?></td>
                        <td><?= $account['admin'] ? 'Administrator' : 'User' ?></td>
                        <td>
                            <?php if ($account['admin']): ?>
                                <span class="premium-badge">Premium</span>
                            <?php else: ?>
                            <form method="post" action="index.php?admin=1">
                                <input type="hidden" name="action" value="premium">
                                <input type="hidden" name="csrf" value="<?= $csrf ?>">
                                <input type="hidden" name="account_id" value="<?= (int) $account['id'] ?>">
                                <select name="premium" aria-label="Access for <?= escape($account['username']) ?>">
                                    <option value="0" <?= $account['premium'] ? '' : 'selected' ?>>Standard</option>
                                    <option value="1" <?= $account['premium'] ? 'selected' : '' ?>>Premium</option>
                                </select>
                                <button>Save</button>
                            </form>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($account['premium_requested'] && !$account['admin']): ?>
                                <form method="post" action="index.php?admin=1">
                                    <input type="hidden" name="csrf" value="<?= $csrf ?>">
                                    <input type="hidden" name="account_id" value="<?= (int) $account['id'] ?>">
                                    <input type="hidden" name="premium" value="1">
                                    <button name="action" value="premium">Approve</button>
                                    <button name="action" value="decline_premium">Decline</button>
                                </form>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ((int) $account['id'] !== (int) $userId): ?>
                                <form method="post" action="index.php?admin=1">
                                    <input type="hidden" name="action" value="revoke_sessions">
                                    <input type="hidden" name="csrf" value="<?= $csrf ?>">
                                    <input type="hidden" name="account_id" value="<?= (int) $account['id'] ?>">
                                    <button>Sign out everywhere</button>
                                </form>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ((int) $account['id'] !== (int) $userId): ?>
                                <form method="post" action="index.php?admin=1">
                                    <input type="hidden" name="action" value="start_delete_user">
                                    <input type="hidden" name="csrf" value="<?= $csrf ?>">
                                    <input type="hidden" name="account_id" value="<?= (int) $account['id'] ?>">
                                    <button class="danger-button">Delete user</button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php elseif ($view === 'login'): ?>
        <h2>Log in</h2>
        <form method="post">
            <input type="hidden" name="action" value="login">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <label>Username <input name="username" autocomplete="username" maxlength="32" required></label>
            <label>Password <input type="password" name="password" autocomplete="current-password" maxlength="72" required></label>
            <button>Log in</button>
        </form>

        <p>Need an account? <a href="index.php?view=signup">Sign up</a></p>

        <h2>Forgot password</h2>
        <form method="post">
            <input type="hidden" name="action" value="recover">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <label>Email <input type="email" name="email" autocomplete="email" maxlength="254" required></label>
            <button>Send reset link</button>
        </form>
    <?php elseif ($view === 'signup'): ?>
        <h2>Sign up</h2>
        <form method="post">
            <input type="hidden" name="action" value="register">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <p><label>Username <input name="username" autocomplete="username" pattern="[A-Za-z0-9_]{3,32}" minlength="3" maxlength="32" required></label> (3–32 letters, digits or underscores)</p>
            <p><label>Email <input type="email" name="email" autocomplete="email" maxlength="254" required></label></p>
            <p><label>Password <input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="72" required></label> (12–72 bytes)</p>
            <button>Sign up</button>
        </form>
        <p>Already registered? <a href="index.php?view=login">Log in</a></p>
    <?php elseif ($view === 'upload'): ?>
        <h2>Upload a photo</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="action" value="upload">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <p><label>Photo <input id="photo" type="file" name="photo" accept=".jpg,.jpeg,.png,.bmp" data-max-mb="<?= UPLOAD_LIMIT_MB ?>" aria-describedby="photo-limits" required></label></p>
            <p id="photo-limits">JPEG, PNG or BMP up to <?= UPLOAD_LIMIT_MB ?> MB and <?= UPLOAD_LIMIT_MEGAPIXELS ?> megapixels. High-resolution photos are resized on upload.</p>
            <p><label>Orientation
                <select id="photo-orientation" name="orientation" aria-describedby="orientation-help">
                    <option value="original">Original</option>
                    <option value="portrait">Portrait (3:4)</option>
                    <option value="landscape">Landscape (4:3)</option>
                </select>
            </label></p>
            <p id="orientation-help">Portrait and landscape crop the photo from the center before saving.</p>
            <img id="photo-preview" alt="Preview of the selected crop" hidden>
            <p><label>Description<br><textarea name="description" maxlength="1000" rows="3" cols="40" required></textarea></label></p>
            <?php if ($canViewPremium): ?>
                <p><label><input type="checkbox" name="premium" value="1"> Premium members and administrators only</label></p>
            <?php endif; ?>
            <button>Upload</button>
        </form>

    <?php elseif ($view === 'gallery'): ?>
        <h2>Gallery</h2>
        <?php if (!$photos): ?><p>No photos available.</p><?php endif; ?>
        <?php foreach ($photos as $photo): ?>
            <article>
                <h3 class="photo-title">
                    <span><?= escape($photo['username']) ?></span>
                    <?php if ($photo['premium']): ?>
                        <span class="premium-badge">Premium</span>
                    <?php endif; ?>
                </h3>
                <?php if ($photo['premium'] && !$canViewPremium): ?>
                    <div class="locked-photo">
                        <p>This picture is for Premium members only.</p>
                        <?php if ($user['premium_requested']): ?>
                            <p>Premium request pending</p>
                        <?php else: ?>
                            <form method="post">
                                <input type="hidden" name="action" value="request_premium">
                                <input type="hidden" name="csrf" value="<?= $csrf ?>">
                                <button>Get Premium</button>
                            </form>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <p><img src="?photo=<?= (int) $photo['id'] ?>" alt="Photo by <?= escape($photo['username']) ?>" width="320" loading="lazy"></p>
                    <p><?= nl2br(escape($photo['description'])) ?></p>
                    <p><a href="?photo=<?= (int) $photo['id'] ?>&amp;download=1">Download photo</a></p>
                <?php endif; ?>
            </article>
        <?php endforeach; ?>

    <?php elseif ($view === 'account'): ?>
        <h2>Account settings</h2>
        <p>Signed in as <?= escape($user['username']) ?><?= $user['admin'] ? ' (Administrator)' : ($canViewPremium ? '' : ' (Standard)') ?></p>
        <?php if ($user['admin']): ?>
            <p><a href="index.php?admin=1">Manage users</a></p>
        <?php elseif (!$user['premium']): ?>
            <?php if ($user['premium_requested']): ?>
                <p>Your Premium request is pending.</p>
            <?php else: ?>
                <form method="post">
                    <input type="hidden" name="action" value="request_premium">
                    <input type="hidden" name="csrf" value="<?= $csrf ?>">
                    <button>Request Premium</button>
                </form>
            <?php endif; ?>
        <?php endif; ?>

        <h3>Change password</h3>
        <form method="post">
            <input type="hidden" name="action" value="change_password">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <p><label>Current password <input type="password" name="current_password" autocomplete="current-password" maxlength="72" required></label></p>
            <p><label>New password <input type="password" name="password" autocomplete="new-password" minlength="12" maxlength="72" required></label></p>
            <button>Change password</button>
        </form>
        <form method="post">
            <input type="hidden" name="action" value="logout">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <button>Log out</button>
        </form>
    <?php endif; ?>
</main>
</body>
</html>

