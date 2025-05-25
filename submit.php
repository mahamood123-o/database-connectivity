<?php
// Database configuration - update these as per your XAMPP setup
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "testdb";  // Change to your database name

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = htmlspecialchars($_POST['name']);

    // Create connection
    $conn = new mysqli($servername, $username, $password, $dbname);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Prepare and bind
    $stmt = $conn->prepare("INSERT INTO names (name) VALUES (?)");
    $stmt->bind_param("s", $name);

    if ($stmt->execute()) {
        echo "Hello, " . $name . "! Your form has been submitted and stored successfully.";
    } else {
        echo "Error: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();
} else {
    echo "Invalid request method.";
}
?>