<?php
$is_admin = false;
extract($_POST);
if ($is_admin) { grant(); }
