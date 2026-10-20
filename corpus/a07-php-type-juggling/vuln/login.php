<?php
if (md5($_POST['pw']) == $row['password_hash']) { $_SESSION['uid'] = $row['id']; }
