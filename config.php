<?php
 config.php - Database connection and session start

 Start the session at the very beginning of the script
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Database connection details
$servername = "localhost"; // Your database server name (usually localhost)
$username = "root";        // Your database username (e.g., root)
$password = "";            // Your database password (leave empty if no password)
$dbname = "sacco_db";      // The name of the database you created in db_setup.php

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    // Log the error for debugging, but show a generic message to the user
    error_log("Database connection failed: " . $conn->connect_error);
    die("Connection to database failed. Please try again later or contact support.");
}

// Set character set to UTF-8 for proper handling of various characters
$conn->set_charset("utf8mb4");

?>
