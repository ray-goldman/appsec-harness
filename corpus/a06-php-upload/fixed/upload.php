<?php
$finfo = new finfo(FILEINFO_MIME_TYPE);
$ALLOWED = ['image/png' => 'png', 'image/jpeg' => 'jpg'];
$mime = $finfo->file($_FILES['f']['tmp_name']);
if (!isset($ALLOWED[$mime])) { http_response_code(415); exit; }
move_uploaded_file($_FILES['f']['tmp_name'], '/var/app-data/uploads/' . bin2hex(random_bytes(16)) . '.' . $ALLOWED[$mime]);
