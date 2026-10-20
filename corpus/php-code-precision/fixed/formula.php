<?php
$operation = $_POST['operation'];
$left = (float) $_POST['left'];
$right = (float) $_POST['right'];
switch ($operation) {
    case 'sum':
        echo $left + $right;
        break;
    case 'product':
        echo $left * $right;
        break;
    default:
        throw new InvalidArgumentException('Unsupported operation');
}
