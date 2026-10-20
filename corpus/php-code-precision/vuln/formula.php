<?php
$formula = $_POST['formula'];
$expression = $formula;
eval(
    trim($expression)
);
