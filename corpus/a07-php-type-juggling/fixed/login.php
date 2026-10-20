<?php
if (password_verify($_POST['pw'] ?? '', $row['password_hash'])) { session_regenerate_id(true); $_SESSION['uid'] = $row['id']; }
