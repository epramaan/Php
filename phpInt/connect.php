<?php
$servername = "localhost:3306"; // Change this if your database server is on a different host
$username = "root"; // Change this if you have a different MySQL username
$password = "root"; // Change this if you have set a password for MySQL
$database = "testing"; // Change this to your actual database name

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

echo "Connected successfully";
?>
