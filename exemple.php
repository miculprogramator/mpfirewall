<?php

include_once('firewall.php');

$protection = array(
	'_ENTITIES' => TRUE,
	'_XSS' => TRUE,
	'_RFI' => TRUE,
	'_SQLI' => FALSE,
);
$detection = array(
	'XSS' => TRUE,
	'RFI' => TRUE,
	'SQLI' => TRUE
);

$obj = new Firewall($protection,$detection);
$obj->enableDetection();
$obj->enableProtection();


?>

<html>
	<head>
		<title>Micul-Programator.ro firewall</title>
	</head>
	<body>
		<?=$_GET['test'];?>
	</body>
</html>