<?php
$is_admin = current_user_is_admin();
$name = (string)($_POST['name'] ?? '');
if ($is_admin) { grant(); }
