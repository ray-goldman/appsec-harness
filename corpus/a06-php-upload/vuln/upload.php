<?php
move_uploaded_file($_FILES['f']['tmp_name'], __DIR__ . '/uploads/' . $_FILES['f']['name']);
