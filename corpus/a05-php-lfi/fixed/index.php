<?php
$PAGES = ['home' => __DIR__ . '/pages/home.php', 'about' => __DIR__ . '/pages/about.php'];
$page = $_GET['page'] ?? 'home';
require $PAGES[$page] ?? $PAGES['home'];
