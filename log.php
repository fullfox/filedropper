<?php
include 'vars.php';
header("Content-Type: text/plain");
$log = file_get_contents($logfile);

$bdd = json_decode($log, true);
foreach ($bdd as $randomname => $elem) {
  if($elem['link_private'] == 'false'){
    echo '<span class="item">' . $elem['ip'] . " uploaded <a href=\"download.php?d=" . $randomname . "\">"
    . "<span class='filename'>" . $elem['filename'] . "</span></a> (" . formatSizeUnits($elem['size']) . ") on "
    . $elem['date'] . "</span>\n\n";
  }
}

?>
