<?php
$FEEDS = ['news' => 'https://news.example.org/rss', 'blog' => 'https://blog.example.org/rss'];
$key = $_GET['feed'] ?? '';
if (!isset($FEEDS[$key])) { http_response_code(400); exit; }
echo htmlspecialchars(file_get_contents($FEEDS['news']));
