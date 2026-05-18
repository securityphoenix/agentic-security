<?php
// Safe: parameterized PDO query.
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET["id"]]);
$row = $stmt->fetch();

// Safe: password_hash with argon2id.
$hash = password_hash($_POST["password"], PASSWORD_ARGON2ID);

// Safe: include from a whitelisted dispatch table.
$pages = ["home" => "home.php", "about" => "about.php"];
include $pages[$_GET["page"]] ?? "404.php";
