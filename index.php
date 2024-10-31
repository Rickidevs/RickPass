<?php

$allowed_files = [
    '*********.txt',
    '********.zip',
    '******.html'
];

$db = new SQLite3('**********.db');
$db->exec('CREATE TABLE IF NOT EXISTS passwords (*** INTEGER PRIMARY KEY, ***** TEXT UNIQUE NOT NULL)');

function rate_limit($user_ip) {
    $rate_limit_file = 'rate_limit.txt';
    $rate_limits = json_decode(file_get_contents($rate_limit_file), true) ?? [];
    $current_time = time();

    if (!isset($rate_limits[$user_ip])) {
        $rate_limits[$user_ip] = ['count' => 0, 'timestamp' => $current_time];
    }

    if ($current_time - $rate_limits[$user_ip]['timestamp'] < 5) {
        $rate_limits[$user_ip]['count']++;
        if ($rate_limits[$user_ip]['count'] > 3) {
            return false;
        }
    } else {
        $rate_limits[$user_ip]['count'] = 1;
        $rate_limits[$user_ip]['timestamp'] = $current_time;
    }

    file_put_contents($rate_limit_file, json_encode($rate_limits));
    return true;
}

function check_password($password) {
    global $db;
    $stmt = $db->prepare('SELECT 1 FROM passwords WHERE password = :password LIMIT 1');
    $stmt->bindValue(':password', $password, SQLITE3_TEXT);
    $result = $stmt->execute();

    if ($result === false) {
        return ["result" => "error", "message" => "Xəta baş verdi."];
    }

    $row = $result->fetchArray();
    if ($row) {
        return ["result" => "exists"];
    } else {
        return ["result" => "not found"];
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $requested_file = $_GET['file'] ?? 'index.html';
    $requested_file = basename($requested_file);

    if (in_array($requested_file, $allowed_files, true)) {
        $file_path = __DIR__ . '/' . $requested_file;
        if (file_exists($file_path)) {
            header('Content-Type: ' . mime_content_type($file_path));
            readfile($file_path);
            exit;
        } else {
            http_response_code(404);
            echo "fayl tapılmadı.";
            exit;
        }
    } else {
        http_response_code(403);
        echo "Bu fayla giriş icazəniz yoxdur.";
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($_SERVER['REQUEST_URI'], '/check_password') !== false) {
    $input = json_decode(file_get_contents('php://input'), true);
    $password = htmlspecialchars(trim($input['password'] ?? ''));
    $user_ip = $_SERVER['REMOTE_ADDR'];

    if ($password === '') {
        echo json_encode(["result" => "error", "message" => "Boş şifrə."]);
        exit;
    }

    if (!rate_limit($user_ip)) {
        echo json_encode(["result" => "error", "message" => "Çox sürətli cəhd etmisiniz. Zəhmət olmasa, bir az gözləyin."]);
        exit;
    }

    $response = check_password($password);
    echo json_encode($response);
    exit;
}

header('Location: index.html');
exit;
?>
