<?php
$host = 'localhost';
$username = 'root';
$password = '123456';
$database = 'automation';

// Create a new MySQL connection
$conn = new mysqli($host, $username, $password, $database);

// Check for connection errors pain
if ($conn->connect_error) {
    die('Connection failed: ' . $conn->connect_error);
    writeLog('Connection to database failed');

}


/////////////////////////////////////////////////////////////////////////////////////
     ////////////////////   REMOVE LATER        //////////////////// 
/////////////////////////////////////////////////////////////////////////////////////


//     DELIMITER //
//     CREATE EVENT IF NOT EXISTS delete_expired_tokens
//     ON SCHEDULE EVERY 1 HOUR
//     DO
//     BEGIN
//         DELETE FROM user_tokens WHERE expiration <= NOW();
//     END;
//     //
//     DELIMITER ;

// CREATE EVENT CheckExpectedTime
// ON SCHEDULE EVERY 1 MINUTE
// DO
//   UPDATE automated_garage_info
//   SET state = 'E',
//       carNum = NULL,
//       expected = NULL
//   WHERE state = 'B' AND expected <= NOW() - INTERVAL 30 MINUTE;

// CREATE EVENT CheckExpectedTime2
// ON SCHEDULE EVERY 1 MINUTE
// DO
//   UPDATE standard_garage_info
//   SET state = 'E',
//       carNum = NULL,
//       expected = NULL
//   WHERE state = 'B' AND expected <= NOW() - INTERVAL 30 MINUTE;
/////////////////////////////////////////////////////////////////////////////////////
     ////////////////////   REMOVE LATER        //////////////////// 
/////////////////////////////////////////////////////////////////////////////////////



$logFile = fopen('log.txt', 'a');
$logFile = 'log.txt';
/////////////////////////////////////////////////////////////////////////////////////

// Define the API endpoints
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    // Check Authentication
    authenticateToken();
    if (isset($_GET['action'])) {
        switch ($_GET['action']) {
            case 'get_locations':               //to do: add log data to this part
                // Handle the 'get_users' action
                $sql = 'SELECT * FROM locations';
                $result = $conn->query($sql);

                // Check for query errors // tried doing this in a better way lmao
                if (!$result) {
                    die('Query failed: ' . $conn->error);
                    print("fail");
                }
                // Convert the query result to an array of associative arrays
                $locations = array();
                while ($row = $result->fetch_assoc()) {
                    $locations[] = $row;
                }
                // Return the locations as a JSON response
                header('Content-Type: application/json');
                echo json_encode($locations);
                break;
            // Add more actions here...
        }
    }
//////////////////////////////////////////////////////////////////////////////////////

} elseif ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check Authentication
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'add_user':
                // Inside the 'add_user' action
                if (empty($_POST['name']) || empty($_POST['phoneNum']) || empty($_POST['email']) || empty($_POST['password']) || empty($_POST['carNum'])) {
                    writeLog("Missing one or more parameters. User: $name, Phone Number: $phoneNum");
                    header('Content-Type: application/json');
                    echo json_encode(array('error' => 'Missing one or more parameters'));
                    exit();
                }

                $name = $_POST['name'];
                $phoneNum = $_POST['phoneNum'];
                $email = $_POST['email'];
                $password = $_POST['password'];
                $carNum = $_POST['carNum'];

                // Check if the email or phone number already exists in the database
                $duplicateQuery = "SELECT * FROM users WHERE email = '$email' OR phoneNum = '$phoneNum'";
                $duplicateResult = $conn->query($duplicateQuery);

                if ($duplicateResult->num_rows > 0) {
                    writeLog("Number or email already exists in the database. User: $name, Phone Number: $phoneNum");
                    echo "Error: number or email already exists in the database.";
                } else {
                    // Hash the password
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                    
                    // Insert the user with the hashed password
                    $insertUserQuery = "INSERT INTO users (name, phoneNum, email, password) VALUES ('$name', '$phoneNum', '$email', '$hashedPassword')";
                    $insertUserResult = $conn->query($insertUserQuery);
                    
                    if (!$insertUserResult) {
                        writeLog("Failed to add user to the database. User: $name, Phone Number: $phoneNum");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Database query failed'));
                        exit();
                    }
                    
                    // Get the users_id of the inserted user
                    $userId = $conn->insert_id;
                
                    // Insert car information into the cars table
                    $carNumbers = $_POST['carNum'];
                    $carCount = min(count($carNumbers), 3); // Limit to 3 cars
                    
                    for ($i = 0; $i < $carCount; $i++) {
                        $carNum = $carNumbers[$i];
                        $insertCarQuery = "INSERT INTO cars (carNum, users_users_id) VALUES ('$carNum', '$userId')";
                        $insertCarResult = $conn->query($insertCarQuery);
                        
                        if (!$insertCarResult) {
                            // If failed to insert car information, rollback user insertion and return error
                            $rollbackQuery = "DELETE FROM users WHERE users_id = '$userId'";
                            $rollbackResult = $conn->query($rollbackQuery);
                    
                            if (!$rollbackResult) {
                                // If rollback failed, log and return error
                                writeLog("Failed to rollback user insertion. User: $name, Phone Number: $phoneNum");
                                header('Content-Type: application/json');
                                echo json_encode(array('error' => 'Failed to add user and rollback failed'));
                                exit();
                            }
                    
                            // Rollback successful, return error
                            writeLog("Failed to add car information to the database. User: $name, Phone Number: $phoneNum, Car Number: $carNum");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Failed to add car information'));
                            exit();
                        }
                    }
                
                    // Both user and car insertion successful
                    writeLog("User and cars added successfully. Name: $name, Phone Number: $phoneNum, Email: $email, Car Numbers: " . implode(', ', $carNumbers));
                    header('Content-Type: application/json');
                    echo json_encode(array('message' => 'User and cars added successfully'));
                }
                break;
                case 'update_user':
                    authenticateToken();
                    // Inside the 'update_user' action
                    if (empty($_POST['name']) || empty($_POST['phoneNum']) || empty($_POST['email']) || empty($_POST['password']) || empty($_POST['carNum']) || empty($_POST['users_id'])) {
                        writeLog("Missing one or more parameters. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Missing one or more parameters'));
                        exit();
                    }
                
                    $name = $_POST['name'];
                    $phoneNum = $_POST['phoneNum'];
                    $email = $_POST['email'];
                    $password = $_POST['password'];
                    $carNum = $_POST['carNum'];
                    $users_id = $_POST['users_id'];
                
                    // Check if the user exists in the database
                    $checkQuery = "SELECT * FROM users WHERE users_id = '$users_id'";
                    $checkResult = $conn->query($checkQuery);
                
                    if ($checkResult->num_rows == 0) {
                        writeLog("User not found. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'User not found'));
                        exit();
                    }
                
                    // Check if the new email or phone number already exists in the database
                    $duplicateQuery = "SELECT * FROM users WHERE (email = '$email' OR phoneNum = '$phoneNum') AND users_id != '$users_id'";
                    $duplicateResult = $conn->query($duplicateQuery);
                
                    if ($duplicateResult->num_rows > 0) {
                        writeLog("Number or email already exists in the database. User ID: $users_id");
                        echo "Error: number or email already exists in the database.";
                        exit();
                    }
                
                    // Hash the password
                    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                
                    // Update the user's information in the database
                    $updateQuery = "UPDATE users SET name = '$name', phoneNum = '$phoneNum', email = '$email', password = '$hashedPassword' WHERE users_id = '$users_id'";
                    $updateResult = $conn->query($updateQuery);
                
                    if (!$updateResult) {
                        writeLog("Failed to update user. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Failed to update user'));
                        exit();
                    }
                
                    // Delete the user's old cars from the cars table
                    $deleteCarsQuery = "DELETE FROM cars WHERE users_users_id = '$users_id'";
                    $deleteCarsResult = $conn->query($deleteCarsQuery);
                
                    if (!$deleteCarsResult) {
                        writeLog("Failed to delete old cars. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Failed to delete old cars'));
                        exit();
                    }
                
                    // Insert new car information into the cars table
                    $carNumbers = $_POST['carNum'];
                    $carCount = min(count($carNumbers), 3); // Limit to 3 cars
                
                    for ($i = 0; $i < $carCount; $i++) {
                        $carNum = $carNumbers[$i];
                        $insertCarQuery = "INSERT INTO cars (carNum, users_users_id) VALUES ('$carNum', '$users_id')";
                        $insertCarResult = $conn->query($insertCarQuery);
                
                        if (!$insertCarResult) {
                            // If failed to insert car information, rollback user insertion and return error
                            $rollbackQuery = "DELETE FROM users WHERE users_id = '$users_id'";
                            $rollbackResult = $conn->query($rollbackQuery);
                
                            if (!$rollbackResult) {
                                // If rollback failed, log and return error
                                writeLog("Failed to rollback user update. User ID: $users_id");
                                header('Content-Type: application/json');
                                echo json_encode(array('error' => 'Failed to update user and rollback failed'));
                                exit();
                            }
                
                            // Rollback successful, return error
                            writeLog("Failed to add new car information. User ID: $users_id");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Failed to add new car information'));
                            exit();
                        }
                    }
                
                    writeLog("User and car information updated successfully. User ID: $users_id");
                    header('Content-Type: application/json');
                    echo json_encode(array('message' => 'User and car information updated successfully'));
                    break;
                case 'delete_user':
                    authenticateToken();
                    // Inside the 'delete_user' action
                    if (empty($_POST['users_id'])) {
                        writeLog("Missing one or more parameters, cannot delete user");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Missing one or more parameters'));
                        exit();
                    }
                
                    $users_id = $_POST['users_id'];
                
                    // Check if the user exists in the database
                    $checkQuery = "SELECT * FROM users WHERE users_id = '$users_id'";
                    $checkResult = $conn->query($checkQuery);
                
                    if ($checkResult->num_rows == 0) {
                        writeLog("User not found. User ID: $users_id to be deleted");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'User not found'));
                        exit();
                    }
                
                    // Delete the token row from the user_tokens table
                    $deleteTokenQuery = "DELETE FROM user_tokens WHERE users_users_id = '$users_id'";
                    $deleteTokenResult = $conn->query($deleteTokenQuery);
                
                    if (!$deleteTokenResult) {
                        writeLog("Failed to delete token for user. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Failed to delete token'));
                        exit();
                    }
                
                    // Delete the carNum associated with the user from the cars table
                    $deleteCarQuery = "DELETE FROM cars WHERE users_users_id = '$users_id'";
                    $deleteCarResult = $conn->query($deleteCarQuery);
                
                    if (!$deleteCarResult) {
                        writeLog("Failed to delete car information for user. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Failed to delete car information'));
                        exit();
                    }
                
                    // Delete the user from the database
                    $deleteQuery = "DELETE FROM users WHERE users_id = '$users_id'";
                    $deleteResult = $conn->query($deleteQuery);
                
                    if (!$deleteResult) {
                        writeLog("Failed to delete user. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Failed to delete user'));
                        exit();
                    }
                
                    writeLog("User deleted successfully. User ID: $users_id");
                    header('Content-Type: application/json');
                    echo json_encode(array('message' => 'User deleted successfully'));
                    break;                
                    case 'login':
                        // Handle the 'login' action
                        if (empty($_POST['email']) || empty($_POST['password'])) {
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Missing email or password'));
                            exit();
                        }
                    
                        $email = $_POST['email'];
                        $password = $_POST['password'];
                    
                        // Check if the user exists in the database
                        $loginQuery = "SELECT * FROM users WHERE email = '$email' ";
                        $loginResult = $conn->query($loginQuery);
                    
                        if ($loginResult->num_rows > 0) {
                            $user = $loginResult->fetch_assoc();
                            if (password_verify($password, $user['password'])) {
                                // User exists and credentials are correct
                                $userId = $user['users_id'];
                                $token = generateToken($userId);
                    
                                // Fetch cars associated with the user
                                $carsQuery = "SELECT carNum FROM cars WHERE users_users_id = '$userId'";
                                $carsResult = $conn->query($carsQuery);
                                $cars = array();
                                while ($car = $carsResult->fetch_assoc()) {
                                    $cars[] = $car;
                                }
                    
                                writeLog("Login successful. User ID: " . $user['users_id'] . ", Email: $email");
                                header('Content-Type: application/json');
                                echo json_encode(array(
                                    'message' => 'Login successful',
                                    'token' => $token,
                                    'user_data' => $user,
                                    'cars' => $cars // List of cars associated with the user
                                ));
                            } else {
                                // Invalid credentials
                                writeLog("Invalid email or password. Email: $email : $password");
                                header('Content-Type: application/json');
                                echo json_encode(array('error' => 'Invalid email or password  '));
                            }
                        } else {
                            // User does not exist
                            writeLog("Invalid email or password. Email: $email");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Invalid email or password'));
                        }
                        break;
                    
                case 'garage_info_automated':
                    authenticateToken();
                    // Handle the 'garage_info_automated' action
                    $sql = "SELECT COUNT(state) as empty_slots FROM automated_garage_info WHERE state = 'E';";
                    $result = $conn->query($sql);
                
                    if (!$result) {
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Database query failed'));
                        exit();
                    }
                
                    $row = $result->fetch_assoc();
                
                    if ($row['empty_slots'] === null) {
                        // No empty slots found
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'No Empty Slots Available'));
                        exit();
                    }
                
                    $emptySlotsCount = $row['empty_slots'];
                
                    // Return the number of empty slots as a JSON response
                    header('Content-Type: application/json');
                    echo json_encode(array('empty_slots_number' => $emptySlotsCount));
                    break;
                    case 'garage_info_standard':
                        authenticateToken();
                    
                        // Handle the 'garage_info_standard' action
                        $sql = "SELECT position, state FROM standard_garage_info;";
                        $result = $conn->query($sql);
                    
                        if (!$result) {
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Database query failed: ' . $conn->error));
                            exit();
                        }
                    
                        $garageInfo = array();
                    
                        while ($row = $result->fetch_assoc()) {
                            $garageInfo[] = array(
                                'id' => $row['id'],
                                'position' => $row['position'],
                                'state' => $row['state']
                            );
                        }
                    
                        // Close connection
                        $conn->close();
                    
                        // Return the garage information as a JSON response
                        header('Content-Type: application/json');
                        echo json_encode($garageInfo);
                        break;
                    

                case 'booking_automated':
                    authenticateToken();
                    // Inside the 'booking' action
                    if (empty($_POST['users_id']) || empty($_POST['dateTime']) || empty($_POST['carNum'])) {
                        writeLog("Missing one or more parameters.");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Missing one or more parameters'));
                        exit();
                    }
                
                    $users_id = $_POST['users_id'];
                    $dateTime = $_POST['dateTime'];
                    $carNum = $_POST['carNum'];
                
                    // Check if the user exists in the database
                    $checkUserQuery = "SELECT * FROM users WHERE users_id = '$users_id'";
                    $checkUserResult = $conn->query($checkUserQuery);
                
                    if ($checkUserResult->num_rows == 0) {
                        writeLog("User not found. User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'User not found'));
                        exit();
                    }
                
                    // Check if the provided datetime is in the future
                    $now = date('Y-m-d H:i:s');
                    $futureTime = date('Y-m-d H:i:s', strtotime('+1 hour')); // Adjust the offset as needed
                    if ($dateTime <= $futureTime) {
                        writeLog("Invalid date and time. Date and time should be in the future.");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Invalid date and time. Date and time should be in the future.'));
                        exit();
                    }
                
                    // Check if the car belongs to the user
                    $checkCarQuery = "SELECT * FROM cars WHERE carNum = '$carNum' AND users_users_id = '$users_id'";
                    $checkCarResult = $conn->query($checkCarQuery);
                
                    if ($checkCarResult->num_rows == 0) {
                        writeLog("Car does not belong to the user. Car Number: $carNum, User ID: $users_id");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Car does not belong to the user'));
                        exit();
                    }
                
                    // Update one row in automated_garage_info table from 'E' to 'B'
                    $updateStateQuery = "UPDATE automated_garage_info SET state = 'B', expected = '$dateTime', carNum = '$carNum' WHERE state = 'E' LIMIT 1";
                    $updateStateResult = $conn->query($updateStateQuery);
                
                    if (!$updateStateResult) {
                        writeLog("Failed to update state in automated_garage_info table");
                        header('Content-Type: application/json');
                        echo json_encode(array('error' => 'Failed to update state in automated_garage_info table'));
                        exit();
                    }
                
                    writeLog("Booking successful. User ID: $users_id, Car Number: $carNum, DateTime: $dateTime");
                    header('Content-Type: application/json');
                    echo json_encode(array('message' => 'Booking successful'));
                    break;

                    case 'booking_standard':
                        authenticateToken();
                        // Inside the 'booking' action
                        if (empty($_POST['users_id']) || empty($_POST['dateTime']) || empty($_POST['carNum'])) {
                            writeLog("Missing one or more parameters.");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Missing one or more parameters'));
                            exit();
                        }
                    
                        $users_id = $_POST['users_id'];
                        $dateTime = $_POST['dateTime'];
                        $carNum = $_POST['carNum'];
                    
                        // Check if the user exists in the database
                        $checkUserQuery = "SELECT * FROM users WHERE users_id = '$users_id'";
                        $checkUserResult = $conn->query($checkUserQuery);
                    
                        if ($checkUserResult->num_rows == 0) {
                            writeLog("User not found. User ID: $users_id");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'User not found'));
                            exit();
                        }
                    
                        // Check if the provided datetime is in the future
                        $now = date('Y-m-d H:i:s');
                        $futureTime = date('Y-m-d H:i:s', strtotime('+1 hour')); // Adjust the offset as needed
                        if ($dateTime <= $futureTime) {
                            writeLog("Invalid date and time. Date and time should be in the future.");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Invalid date and time. Date and time should be in the future.'));
                            exit();
                        }
                    
                        // Check if the car belongs to the user
                        $checkCarQuery = "SELECT * FROM cars WHERE carNum = '$carNum' AND users_users_id = '$users_id'";
                        $checkCarResult = $conn->query($checkCarQuery);
                    
                        if ($checkCarResult->num_rows == 0) {
                            writeLog("Car does not belong to the user. Car Number: $carNum, User ID: $users_id");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Car does not belong to the user'));
                            exit();
                        }
                    
                        // Update one row in standard_garage_info table from 'E' to 'B'
                        $updateStateQuery = "UPDATE standard_garage_info SET state = 'B', expected = '$dateTime', carNum = '$carNum' WHERE state = 'E' LIMIT 1";
                        $updateStateResult = $conn->query($updateStateQuery);
                    
                        if (!$updateStateResult) {
                            writeLog("Failed to update state in standard_garage_info table");
                            header('Content-Type: application/json');
                            echo json_encode(array('error' => 'Failed to update state in standard_garage_info table'));
                            exit(); 
                        }
                    
                        writeLog("Booking successful. User ID: $users_id, Car Number: $carNum, DateTime: $dateTime");
                        header('Content-Type: application/json');
                        echo json_encode(array('message' => 'Booking successful'));
                        break;
                        
            // Add more actions here...
        }
    }
}


function generateToken($userId) {
    // Generate a random token
    $token = bin2hex(random_bytes(32));

    // Token expiration time (adjust as needed)
    $expiration = strtotime('+7 day');

    // Store the token in the database
    global $conn;

    // Prepare the SQL statement to prevent SQL injection
    $insertTokenQuery = $conn->prepare("INSERT INTO user_tokens (users_users_id, token, expiration) VALUES (?, ?, ?)");
    $insertTokenQuery->bind_param("iss", $userId, $token, $expiration);
    $insertTokenQuery->execute();

    // Check for errors
    if ($insertTokenQuery->error) {
        // Handle the error, for example, log it
        error_log("Error inserting token: " . $insertTokenQuery->error);
        return false; // Indicate failure
    }

    return $token;
}

function writeLog($message) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = $timestamp . ' - ' . $message . PHP_EOL;
    file_put_contents($logFile, $logMessage, FILE_APPEND);
}
function authenticateToken() {
    global $conn;

    // Get the token from the request headers
    
    $headers = getallheaders();
    $token = isset($headers['Authorization']) ? $headers['Authorization'] : null;

    if (!$token) {
        header('Content-Type: application/json');
        echo json_encode(array('error' => 'Token not provided'));
        exit();
    }
    $users_id = $_POST['users_id'];
    // Check if the token exists and is not expired
    $checkTokenQuery = "SELECT * FROM user_tokens WHERE token = '$token' AND expiration > UNIX_TIMESTAMP() AND users_users_id = '$users_id'";
    $checkTokenResult = $conn->query($checkTokenQuery);

    if ($checkTokenResult->num_rows == 0) {
        header('Content-Type: application/json');
        echo json_encode(array('error' => 'Invalid or expired token'));
        exit();
    }
}