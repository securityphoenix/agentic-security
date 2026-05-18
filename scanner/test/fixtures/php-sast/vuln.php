<?php
eval($_REQUEST["expr"]);                             // dangerous call
$cmd = `echo $_GET[input]`;                           // backtick command interp
$obj = unserialize($_POST["state"]);                 // unsafe deserialization
include $_GET["page"];                                // LFI/RFI
mysql_query("SELECT * FROM u WHERE id=" . $_GET["id"]);   // SQLi
extract($_REQUEST);                                  // variable injection
$h = md5($_POST["password"]);                        // weak password hash
phpinfo();                                            // info disclosure
