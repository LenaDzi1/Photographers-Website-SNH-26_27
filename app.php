<?php

const UPLOAD_LIMIT_MB = 4;
const UPLOAD_LIMIT = UPLOAD_LIMIT_MB * 1024 * 1024;
const UPLOAD_LIMIT_MEGAPIXELS = 25;
const RESIZE_ABOVE_PIXELS = 8_000_000;
const RESIZED_IMAGE_MAX_EDGE = 2_000;
const STORED_IMAGE_LIMIT = 16 * 1024 * 1024 - 1; // MySQL MEDIUMBLOB capacity.

function connectDatabase(): PDO
{
    return new PDO(
        getenv('DB_DSN') ?: 'mysql:host=127.0.0.1;dbname=photographers;charset=utf8mb4',
        getenv('DB_USER') ?: 'photographers',
        getenv('DB_PASSWORD') ?: '',
        [PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
    );
}

function query(string $sql, array $params = []): PDOStatement
{
    global $db;
    $statement = $db->prepare($sql);
    $statement->execute($params);
    return $statement;
}

function audit(string $event, ?int $userId = null, string $detail = ''): void
{
    query('INSERT INTO audit_log (ip, user_id, event, detail) VALUES (?, ?, ?, ?)',
        [$_SERVER['REMOTE_ADDR'], $userId, $event, $detail]);
}

function post(string $name): string
{
    $value = $_POST[$name] ?? '';
    return is_string($value) ? $value : '';
}

function escape(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $message, string $location = 'index.php'): never
{
    $_SESSION['message'] = $message;
    header('Location: ' . $location, true, 303);
    exit;
}

function deny(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    exit($message);
}

function validPassword(string $password): bool
{
    return strlen($password) >= 12 && strlen($password) <= 72 && !str_contains($password, "\0");
}

function passwordHash(string $password): string
{
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

function limitAttempts(string $action, int $limit, ?int $userId, string $username = ''): void
{
    $subject = $username === '' ? 'ip:' . $_SERVER['REMOTE_ADDR'] : 'user:' . $username;
    $key = [$subject, $action];
    $window = intdiv(time(), 900);
    query('INSERT INTO auth_limits (subject, action, time_window, attempts) VALUES (?, ?, ?, 1)
           ON DUPLICATE KEY UPDATE attempts = IF(time_window = ?, attempts + 1, 1), time_window = ?',
        [...$key, $window, $window, $window]);
    $attempts = (int) query('SELECT attempts FROM auth_limits WHERE subject = ? AND action = ?', $key)->fetchColumn();

    if ($attempts > $limit) {
        if ($attempts === $limit + 1) {
            audit('throttled', $userId, $action);
        }
        header('Retry-After: ' . (900 - time() % 900));
        deny(429, 'Too many attempts. Try again later.');
    }
}

function uploadedImage(string $orientation): array|string
{
    $file = $_FILES['photo'] ?? null;
    $error = $file['error'] ?? UPLOAD_ERR_NO_FILE;
    if ($error !== UPLOAD_ERR_OK) {
        return match ($error) {
            UPLOAD_ERR_NO_FILE => 'missing',
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'too_large',
            default => 'transfer',
        };
    }
    if ($file['size'] > UPLOAD_LIMIT) {
        return 'too_large';
    }
    if (!is_uploaded_file($file['tmp_name'])) {
        return 'transfer';
    }

    $input = file_get_contents($file['tmp_name']);
    if ($input === false) {
        return 'transfer';
    }

    return prepareImage($input, $orientation);
}

function prepareImage(string $input, string $orientation): array|string
{
    $info = @getimagesizefromstring($input);
    if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_BMP], true)) {
        return 'format';
    }
    [$width, $height] = $info;
    $pixels = $width * $height;
    if ($pixels > UPLOAD_LIMIT_MEGAPIXELS * 1_000_000) {
        return 'dimensions';
    }

    $resize = $pixels > RESIZE_ABOVE_PIXELS;
    if ($resize) {
        // GD may hold several decoded buffers before the image can be resized.
        ini_set('memory_limit', '384M');
    }
    $image = @imagecreatefromstring($input);
    unset($input);
    if (!$image) {
        return 'decode';
    }

    if ($resize || $orientation !== 'original') {
        $ratio = match ($orientation) {
            'portrait' => 3 / 4,
            'landscape' => 4 / 3,
            default => $width / $height,
        };
        $cropWidth = max(1, min($width, (int) round($height * $ratio)));
        $cropHeight = max(1, min($height, (int) round($width / $ratio)));
        $scale = $resize ? min(1, RESIZED_IMAGE_MAX_EDGE / max($cropWidth, $cropHeight)) : 1;
        $targetWidth = max(1, (int) round($cropWidth * $scale));
        $targetHeight = max(1, (int) round($cropHeight * $scale));
        $resized = imagecreatetruecolor($targetWidth, $targetHeight);
        if (!$resized) {
            return 'encode';
        }
        imagealphablending($resized, false);
        if (!imagecopyresampled(
            $resized, $image, 0, 0, intdiv($width - $cropWidth, 2), intdiv($height - $cropHeight, 2),
            $targetWidth, $targetHeight, $cropWidth, $cropHeight
        )) {
            return 'encode';
        }
        $image = $resized;
    }

    ob_start();
    if ($info[2] === IMAGETYPE_JPEG) {
        $saved = imagejpeg($image);
    } elseif ($info[2] === IMAGETYPE_PNG) {
        imagesavealpha($image, true);
        $saved = imagepng($image);
    } else {
        $saved = imagebmp($image);
    }
    $bytes = ob_get_clean();

    if (!$saved || $bytes === '') {
        return 'encode';
    }
    if (strlen($bytes) > STORED_IMAGE_LIMIT) {
        return 'stored_size';
    }

    return [$info['mime'], $bytes];
}

function writeRecoveryEmail(int $userId, string $email, string $token): void
{
    $directory = __DIR__ . '/outbox';
    if (!is_dir($directory) && !@mkdir($directory, 0700) && !is_dir($directory)) {
        throw new RuntimeException('Cannot create recovery outbox');
    }

    $baseUrl = rtrim(getenv('APP_URL') ?: 'http://127.0.0.1:8000', '/');
    $filename = $directory . '/' . $userId . '-' . substr(hash('sha256', $token), 0, 16) . '.txt';
    $message = "To: $email\nSubject: Password reset\n\n"
        . "$baseUrl/index.php?reset=1#$token\n\nThis link expires in 30 minutes.\n";

    if (file_put_contents($filename, $message, LOCK_EX) !== strlen($message)) {
        throw new RuntimeException('Cannot write recovery email');
    }
    @chmod($filename, 0600);
}

