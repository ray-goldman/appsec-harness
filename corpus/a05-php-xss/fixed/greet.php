<?php
echo "<p>Hello " . htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8') . "</p>";
