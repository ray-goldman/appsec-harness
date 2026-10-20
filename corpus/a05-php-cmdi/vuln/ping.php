<?php
$host = $_POST['host'];
system("ping -c 1 " . $host);
