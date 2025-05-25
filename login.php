<?php
session_start();

// Database connection parameters
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "testdb";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Function to sanitize input data
function sanitize_input($data) {
    return htmlspecialchars(stripslashes(trim($data)));
}

$message = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = sanitize_input($_POST['username']);
    $password = $_POST['password'];

    if (empty($username) || empty($password)) {
        $message = "Username and password are required.";
    } else {
        // Check if user exists and get failed_attempts and lockout_time
        $stmt = $conn->prepare("SELECT id, username, email, password, failed_attempts, lockout_time FROM users1 WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows == 1) {
            $stmt->bind_result($id, $db_username, $db_email, $db_password_hash, $failed_attempts, $lockout_time);
            $stmt->fetch();

            // Check if user is locked out
            if ($lockout_time !== null) {
                $lockout_timestamp = strtotime($lockout_time);
                $current_timestamp = time();
                $lockout_duration = 4 * 60 * 60; // 4 hours in seconds

                if (($current_timestamp - $lockout_timestamp) < $lockout_duration) {
                    $remaining = $lockout_duration - ($current_timestamp - $lockout_timestamp);
                    $hours = floor($remaining / 3600);
                    $minutes = floor(($remaining % 3600) / 60);
                    $message = "Account locked due to multiple failed login attempts. Please try again after {$hours} hour(s) and {$minutes} minute(s).";
                } else {
                    // Lockout expired, reset failed_attempts and lockout_time
                    $reset_stmt = $conn->prepare("UPDATE users1 SET failed_attempts = 0, lockout_time = NULL WHERE id = ?");
                    $reset_stmt->bind_param("i", $id);
                    $reset_stmt->execute();
                    $reset_stmt->close();
                    $failed_attempts = 0;
                    $lockout_time = null;
                }
            }

            if (empty($message)) {
                if (password_verify($password, $db_password_hash)) {
                    // Password is correct, reset failed_attempts and lockout_time
                    $reset_stmt = $conn->prepare("UPDATE users1 SET failed_attempts = 0, lockout_time = NULL WHERE id = ?");
                    $reset_stmt->bind_param("i", $id);
                    $reset_stmt->execute();
                    $reset_stmt->close();

                    // Start session
                    $_SESSION['user_id'] = $id;
                    $_SESSION['username'] = $db_username;
                    $message = "Login successful. Welcome, " . htmlspecialchars($db_username) . "!";
                    // Redirect or further processing can be done here
                } else {
                    // Password incorrect, increment failed_attempts
                    $failed_attempts++;
                    if ($failed_attempts >= 3) {
                        $lockout_time = date("Y-m-d H:i:s");
                        $update_stmt = $conn->prepare("UPDATE users1 SET failed_attempts = ?, lockout_time = ? WHERE id = ?");
                        $update_stmt->bind_param("isi", $failed_attempts, $lockout_time, $id);
                        $update_stmt->execute();
                        $update_stmt->close();
                        $message = "Account locked due to multiple failed login attempts. Please try again after 4 hours.";
                    } else {
                        $update_stmt = $conn->prepare("UPDATE users1 SET failed_attempts = ? WHERE id = ?");
                        $update_stmt->bind_param("ii", $failed_attempts, $id);
                        $update_stmt->execute();
                        $update_stmt->close();
                        $message = "Invalid password.";
                    }
                }
            }
        } else {
            $message = "User not found.";
        }

        $stmt->close();
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #2196F3, #64B5F6);
            color: #333;
            padding: 40px;
        }
        h2 {
            color: #fff;
            text-align: center;
            margin-bottom: 30px;
            text-shadow: 1px 1px 2px #000;
        }
        form {
            background: #fff;
            max-width: 400px;
            margin: 0 auto;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 15px rgba(0,0,0,0.3);
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #555;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border: 2px solid #2196F3;
            border-radius: 5px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: #64B5F6;
            outline: none;
        }
        input[type="submit"] {
            background: #2196F3;
            color: white;
            border: none;
            padding: 12px 20px;
            font-size: 18px;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            transition: background 0.3s ease;
        }
        input[type="submit"]:hover {
            background: #64B5F6;
        }
        .message {
            max-width: 400px;
            margin: 0 auto 20px auto;
            padding: 15px;
            border-radius: 5px;
            font-weight: bold;
            text-align: center;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
    </style>
</head>
<body>
    <h2>Login</h2>
    <?php if (!empty($message)): ?>
        <?php
            $class = strpos($message, 'successful') !== false ? 'success' : 'error';
        ?>
        <div class="message <?php echo $class; ?>">
            <?php echo htmlspecialchars($message); ?>
        </div>
    <?php endif; ?>
    <form action="login.php" method="post">
        <label for="username">Username or Email:</label>
        <input type="text" id="username" name="username" required />
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required />
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <input type="submit" value="Login" style="width: 48%;" />
            <a href="signup.php" style="display: inline-block; width: 48%; background: #4CAF50; color: white; padding: 12px 0; border-radius: 5px; text-align: center; text-decoration: none; font-size: 18px; transition: background 0.3s ease;">Sign Up</a>
        </div>
    </form>
</body>
</html>
