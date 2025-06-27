<?php
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
$servername = "localhost"; 
$username = "root";        
$password = "";            
$dbname = "sacco_db";
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error);
    die("Connection to database failed. Please try again later or contact support.");
}
$conn->set_charset("utf8mb4");
?>
