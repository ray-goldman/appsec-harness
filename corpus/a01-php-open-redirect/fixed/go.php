<?php
$ALLOWED = ['home' => '/home', 'account' => '/account'];
header('Location: ' . ($ALLOWED[$_GET['to'] ?? 'home'] ?? '/home'));
