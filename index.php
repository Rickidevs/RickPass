<?php
$db = new SQLite3('*****.db');

function check_password($password) {
    global $db;
    $stmt = $db->prepare('SELECT 1 FROM ******* WHERE password_hash = :password LIMIT 1');
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $password = htmlspecialchars(trim($input['password'] ?? ''));
    if ($password === '') {
        echo json_encode(["result" => "error", "message" => "Boş şifrə."]);
        exit;
    }
    $response = check_password($password);
    echo json_encode($response);
    exit;
}
?>
