<?php
$host = $_POST['host'] ?? '';
if (!filter_var($host, FILTER_VALIDATE_IP)) { http_response_code(400); exit; }
system("ping -c 1 " . escapeshellarg($host));
