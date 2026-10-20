<?php
function store($pdo, $user, $password) {
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $token = bin2hex(random_bytes(32));
    $pdo->prepare('UPDATE users SET pw=?, reset=? WHERE name=?')->execute([$hash, $token, $user]);
}
