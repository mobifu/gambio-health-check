<?php
header('Content-Type: application/json');
$res = ['php' => phpversion(), 'db' => ['type' => null, 'version_full' => null, 'version_number' => null]];

// Try to get DB connection details from includes/configure.php
$db_host = null;
$db_user = null;
$db_pass = null;
$db_name = null;

if (file_exists('includes/configure.php')) {
    $conf = file_get_contents('includes/configure.php');
    preg_match('/DB_SERVER[\'"], [\'"]([^\'"]+)[\'"]/', $conf, $hs);
    preg_match('/DB_SERVER_USERNAME[\'"], [\'"]([^\'"]+)[\'"]/', $conf, $us);
    preg_match('/DB_SERVER_PASSWORD[\'"], [\'"]([^\'"]+)[\'"]/', $conf, $ps);
    preg_match('/DB_DATABASE[\'"], [\'"]([^\'"]+)[\'"]/', $conf, $ds);

    if (isset($hs[1])) $db_host = $hs[1];
    if (isset($us[1])) $db_user = $us[1];
    if (isset($ps[1])) $db_pass = $ps[1];
    if (isset($ds[1])) $db_name = $ds[1];
}

if ($db_host && $db_user && $db_name) {
    $link = @mysqli_connect($db_host, $db_user, $db_pass, $db_name);
    if ($link) {
        $server_info = mysqli_get_server_info($link);
        $res['db']['version_full'] = $server_info;

        if (strpos($server_info, 'MariaDB') !== false) {
            $res['db']['type'] = 'MariaDB';
            preg_match('/^(\\d+\\.\\d+\\.\\d+)/', $server_info, $matches);
            if (isset($matches[1])) { $res['db']['version_number'] = $matches[1]; }
        } else {
            $res['db']['type'] = 'MySQL';
            preg_match('/^(\\d+\\.\\d+\\.\\d+)/', $server_info, $matches);
            if (isset($matches[1])) { $res['db']['version_number'] = $matches[1]; }
        }
        mysqli_close($link);
    }
}

// Fallback if DB connection failed or configure.php not found
if (!$res['db']['version_full'] && function_exists('mysqli_get_client_info')) {
    $client_info = mysqli_get_client_info();
    $res['db']['type'] = 'Client';
    $res['db']['version_full'] = 'Client: ' . $client_info;
    preg_match('/^(\\d+\\.\\d+\\.\\d+)/', $client_info, $matches);
    if (isset($matches[1])) { $res['db']['version_number'] = $matches[1]; }
}

$res['security'] = [
    'installer_exists' => file_exists('gambio_installer') && is_dir('gambio_installer'),
    'config_writable' => file_exists('includes/configure.php') && is_writable('includes/configure.php'),
    'admin_config_writable' => file_exists('admin/includes/configure.php') && is_writable('admin/includes/configure.php'),
    'htaccess_admin_backups' => file_exists('admin/backups/.htaccess'),
    'htaccess_log' => file_exists('logfiles/.htaccess')
];

$res['env'] = [
    'session_auto_start' => ini_get('session.auto_start') == '1',
    'soap_loaded' => extension_loaded('soap'),
    'intl_loaded' => extension_loaded('intl')
];

echo json_encode($res);
