<?php
$stmt = $pdo->prepare('SELECT * FROM items WHERE id = ?');
$stmt->execute([$_GET['id'] ?? '']);
