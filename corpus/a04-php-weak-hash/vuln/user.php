<?php
function store($pdo, $user, $password) {
    $hash = md5($password);
    $token = mt_rand();
    $pdo->prepare('UPDATE users SET pw=?, reset=? WHERE name=?')->execute([$hash, $token, $user]);
}
