<?php
$cart = json_decode($_COOKIE['cart'] ?? '[]', true, 8, JSON_THROW_ON_ERROR);
