<?php
/**
 * Login Success Page
 * Demonstrates successful credential capture in MITM attack
 */

session_start();

$username = $_SESSION['user'] ?? 'Guest';
$protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'HTTPS' : 'HTTP';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login Successful</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 50px auto;
            padding: 30px;
            background: white;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #28a745;
            text-align: center;
        }
        .info {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .danger {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .detail {
            margin: 10px 0;
        }
        .label {
            font-weight: bold;
            color: #333;
        }
        .value {
            color: #666;
            margin-left: 10px;
        }
        .logout-btn {
            display: block;
            width: 100%;
            padding: 10px;
            background: #dc3545;
            color: white;
            text-align: center;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 20px;
        }
        .logout-btn:hover {
            background: #c82333;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>Login Successful</h1>
    
    <div class="info">
        <strong>Welcome, <?php echo htmlspecialchars($username); ?>!</strong>
        <p>You have successfully logged in to the system.</p>
    </div>
    
    <?php if ($protocol === 'HTTP'): ?>
    <div class="danger">
        <strong>SECURITY WARNING</strong>
        <p>Your connection is NOT SECURE. This page was accessed via HTTP.</p>
        <p>Your credentials and session data were transmitted in plain text!</p>
        <p><strong>This demonstrates a successful SSL stripping attack.</strong></p>
    </div>
    <?php else: ?>
    <div class="info">
        <strong>Secure Connection</strong>
        <p>Your connection is protected by HTTPS encryption.</p>
    </div>
    <?php endif; ?>
    
    <div class="warning">
        <h3>Session Information</h3>
        <div class="detail">
            <span class="label">Username:</span>
            <span class="value"><?php echo htmlspecialchars($username); ?></span>
        </div>
        <div class="detail">
            <span class="label">Protocol:</span>
            <span class="value"><?php echo $protocol; ?></span>
        </div>
        <div class="detail">
            <span class="label">Session ID:</span>
            <span class="value"><?php echo session_id(); ?></span>
        </div>
        <div class="detail">
            <span class="label">Client IP:</span>
            <span class="value"><?php echo $_SERVER['REMOTE_ADDR']; ?></span>
        </div>
        <?php if (!empty($_COOKIE)): ?>
        <div class="detail">
            <span class="label">Cookies Set:</span>
            <span class="value"><?php echo count($_COOKIE); ?> cookie(s)</span>
        </div>
        <?php endif; ?>
    </div>
    
    <a href="/logout.php" class="logout-btn">Logout</a>
</div>

</body>
</html>
