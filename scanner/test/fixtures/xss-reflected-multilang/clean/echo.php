<?php
echo "<div>Hi " . htmlspecialchars($_GET["name"], ENT_QUOTES) . "</div>";
