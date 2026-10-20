<?php
$id = $_GET['id'];
$res = mysqli_query($conn, "SELECT * FROM items WHERE id = '$id'");
