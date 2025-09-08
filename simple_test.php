<?php
// Simple MySQL test
try {
    // Connect to MySQL
    $dsn = "mysql:unix_socket=/tmp/mysql.sock;dbname=auth_db;charset=utf8mb4";
    $pdo = new PDO($dsn, 'root', '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::MYSQL_ATTR_USE_BUFFERED_QUERY => true
    ]);
    
    echo "Connected successfully!\n";
    
    // Test simple query
    $stmt = $pdo->prepare("SELECT COUNT(*) as count FROM users");
    $stmt->execute();
    $result = $stmt->fetchAll();
    echo "Users table has " . $result[0]['count'] . " records\n";
    
    // Test second query
    $stmt2 = $pdo->prepare("SELECT COUNT(*) as count FROM otp_codes");
    $stmt2->execute();
    $result2 = $stmt2->fetchAll();
    echo "OTP codes table has " . $result2[0]['count'] . " records\n";
    
    echo "Test completed successfully!\n";
    
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
?>