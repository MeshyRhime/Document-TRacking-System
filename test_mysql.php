<?php
// Test MySQL connection
try {
    $dsn = "mysql:host=localhost;port=8000;dbname=auth_db;charset=utf8mb4";
    echo "Attempting to connect with DSN: $dsn\n";
    
    $pdo = new PDO($dsn, 'root', '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 10
    ]);
    
    echo "Connected successfully!\n";
    
    // Test database queries
    $result = $pdo->query("SHOW TABLES");
    $tables = $result->fetchAll();
    
    echo "Tables in database:\n";
    foreach ($tables as $table) {
        print_r($table);
    }
    
} catch (PDOException $e) {
    echo "Connection failed: " . $e->getMessage() . "\n";
    echo "Error code: " . $e->getCode() . "\n";
}
?>