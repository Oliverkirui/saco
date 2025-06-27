<?php
include 'config.php';
$message = '';
$message_type = '';
function getSetting($conn, $key) {
    $stmt = $conn->prepare("SELECT setting_value FROM settings WHERE setting_key = ?");
    if (!$stmt) {
        error_log("Failed to prepare getSetting statement: " . $conn->error);
        return false;
    }
    $stmt->bind_param("s", $key);
    $stmt->execute();
    $stmt->bind_result($value);
    $stmt->fetch();
    $stmt->close();
    return $value;
}
function setSetting($conn, $key, $value) {
    // ON DUPLICATE KEY UPDATE is crucial here for updating existing settings
    $stmt = $conn->prepare("INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?");
    if (!$stmt) {
        error_log("Failed to prepare setSetting statement: " . $conn->error);
        return false;
    }
    $stmt->bind_param("sss", $key, $value, $value);
    $success = $stmt->execute();
    $stmt->close();
    return $success;
}
$adminPasswordHash = getSetting($conn, 'admin_password');
if ($adminPasswordHash === false || $adminPasswordHash === null || $adminPasswordHash === '') {
    string
    $defaultPassword = 'admin123';
    if (setSetting($conn, 'admin_password', password_hash($defaultPassword, PASSWORD_DEFAULT))) {
        $message = "Initial admin password set to 'admin123'. Please log in and change it immediately via Admin Settings.";
        $message_type = "info";
    } else {
        $message = "Error setting initial password. Check database connection/permissions.";
        $message_type = "error";}}
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login'])) {
    $inputPassword = $_POST['password'];
    $storedHash = getSetting($conn, 'admin_password');

    if ($storedHash && password_verify($inputPassword, $storedHash)) {
        $_SESSION['logged_in'] = true;
        $message = "Logged in successfully!";
        $message_type = "success";
        header("Location: index.php?msg=" . urlencode($message) . "&type=" . $message_type);
        exit();
    } else {
        $message = "Invalid password.";
        $message_type = "error";
    }
}
if (isset($_GET['logout'])) {
    session_destroy();
    session_start();
    session_regenerate_id(true);

    $message = "Logged out successfully.";
    $message_type = "success";
    header("Location: index.php?msg=" . urlencode($message) . "&type=" . $message_type);
    exit();
}
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['change_password']) && isset($_SESSION['logged_in'])) {
    $currentPassword = trim($_POST['current_password']);
    $newPassword = trim($_POST['new_password']);
    $confirmNewPassword = trim($_POST['confirm_new_password']);

    $storedHash = getSetting($conn, 'admin_password');

    if (!password_verify($currentPassword, $storedHash)) {
        $message = "Current password is incorrect.";
        $message_type = "error";
    } elseif ($newPassword !== $confirmNewPassword) {
        $message = "New password and confirmation do not match.";
        $message_type = "error";
    } elseif (strlen($newPassword) < 8) { // Minimum password length
        $message = "New password must be at least 8 characters long.";
        $message_type = "error";
    } else {
        if (setSetting($conn, 'admin_password', password_hash($newPassword, PASSWORD_DEFAULT))) {
            $message = "Password changed successfully!";
            $message_type = "success";
            header("Location: index.php?page=adminSettings&msg=" . urlencode($message) . "&type=" . $message_type);
            exit();
        } else {
            $message = "Error changing password: Database update failed.";
            $message_type = "error";
        }
    }
}
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['add_member'])) {
        $fullName = trim($_POST['fullName']);
        $idNumber = trim($_POST['idNumber']);
        $phoneNumber = trim($_POST['phoneNumber']);
        $nextOfKinFullName = trim($_POST['nextOfKinFullName']);
        $nextOfKinIdNumber = trim($_POST['nextOfKinIdNumber']);
        if (empty($fullName) || empty($idNumber) || empty($phoneNumber) || empty($nextOfKinFullName) || empty($nextOfKinIdNumber)) {
            $message = "Please fill in all required fields.";
            $message_type = "error";
        }
        elseif (!preg_match("/^[a-zA-Z\s]+$/", $fullName)) {
            $message = "Full Name must contain only alphabetic characters and spaces.";
            $message_type = "error";
        }
        elseif (!ctype_digit($idNumber)) {
            $message = "Member ID Number must contain only numbers.";
            $message_type = "error";
        }
        elseif (!preg_match("/^\+?[0-9\s\(\)\-]+$/", $phoneNumber)) {
            $message = "Phone Number format is invalid. Please use only numbers, spaces, and optionally a leading '+'.";
            $message_type = "error";
        }
        elseif (!preg_match("/^[a-zA-Z\s]+$/", $nextOfKinFullName)) {
            $message = "Next of Kin Full Name must contain only alphabetic characters and spaces.";
            $message_type = "error";
        }
        elseif (!ctype_digit($nextOfKinIdNumber)) {
            $message = "Next of Kin ID Number must contain only numbers.";
            $message_type = "error";
        }
else { 
            $stmt_check_id = $conn->prepare("SELECT id FROM members WHERE id_number = ?");
            if (!$stmt_check_id) {
                error_log("Failed to prepare ID check statement: " . $conn->error);
                $message = "An internal error occurred during ID check.";
                $message_type = "error";
            } else {
                $stmt_check_id->bind_param("s", $idNumber);
                $stmt_check_id->execute();
                $stmt_check_id->store_result();
                if ($stmt_check_id->num_rows > 0) {
                    $message = "A member with this ID Number already exists.";
                    $message_type = "error";
                } else {
                    $insert_stmt = $conn->prepare("INSERT INTO members (full_name, id_number, phone_number, next_of_kin_full_name, next_of_kin_id_number) VALUES (?, ?, ?, ?, ?)");
                    if (!$insert_stmt) {
                        error_log("Failed to prepare insert member statement: " . $conn->error);
                        $message = "An internal error occurred during member insertion.";
                        $message_type = "error";
                    } else {
                        $insert_stmt->bind_param("sssss", $fullName, $idNumber, $phoneNumber, $nextOfKinFullName, $nextOfKinIdNumber);
                        if ($insert_stmt->execute()) {
                            $message = "Member added successfully!";
                            $message_type = "success";
                            header("Location: index.php?page=viewMembers&msg=" . urlencode($message) . "&type=" . $message_type);
                            exit();
                        } else {
                            $message = "Error adding member: " . $conn->error;
                            $message_type = "error";
                        }
                        $insert_stmt->close();
                    }
                }
                $stmt_check_id->close();
            }
        }
    }
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['add_shares'])) {
        $memberId = (int)$_POST['memberId']; // Cast to int for security
        $sharesAmount = (float)$_POST['sharesAmount']; // Cast to float
if ($memberId <= 0 || $sharesAmount <= 0) {
            $message = "Please select a valid member and enter a positive shares amount.";
            $message_type = "error";
        } else {
            $conn->begin_transaction();
            try {
     $update_stmt = $conn->prepare("UPDATE members SET shares = shares + ? WHERE id = ?");
                if (!$update_stmt) {
                    throw new Exception("Failed to prepare update shares statement: " . $conn->error);
                }
                $update_stmt->bind_param("di", $sharesAmount, $memberId);
                if (!$update_stmt->execute()) {
                    throw new Exception("Error updating shares: " . $conn->error);
                }
                $update_stmt->close();
                $insert_txn_stmt = $conn->prepare("INSERT INTO transactions (member_id, transaction_type, amount, notes) VALUES (?, 'shares_deposit', ?, ?)");
                if (!$insert_txn_stmt) {
                    throw new Exception("Failed to prepare shares transaction statement: " . $conn->error);
                }
                $notes = "Shares deposit of Ksh " . number_format($sharesAmount, 2);
                $insert_txn_stmt->bind_param("ids", $memberId, $sharesAmount, $notes);
                if (!$insert_txn_stmt->execute()) {
                    throw new Exception("Error recording shares transaction: " . $conn->error);
                }
                $insert_txn_stmt->close();

                $conn->commit();
                $message = "Ksh " . number_format($sharesAmount, 2) . " shares added successfully!";
                $message_type = "success";
                header("Location: index.php?page=shares&msg=" . urlencode($message) . "&type=" . $message_type);
                exit();
            } catch (Exception $e) {
                $conn->rollback();
                $message = "Transaction failed: " . $e->getMessage();
                $message_type = "error";
            }
        }
    }
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['apply_loan'])) {
        $memberId = (int)$_POST['memberId'];
        $loanAmount = (float)$_POST['loanAmount'];

        if ($memberId <= 0 || $loanAmount <= 0) {
            $message = "Please select a valid member and enter a positive loan amount.";
            $message_type = "error";
        } else {
            $stmt_member = $conn->prepare("SELECT shares, loan_amount, loan_taken_date, loan_due_date FROM members WHERE id = ?");
            if (!$stmt_member) {
                error_log("Failed to prepare loan eligibility statement: " . $conn->error);
                $message = "An internal error occurred checking loan eligibility.";
                $message_type = "error";
            } else {
                $stmt_member->bind_param("i", $memberId);
                $stmt_member->execute();
                $stmt_member->bind_result($memberShares, $existingLoan, $loanTakenDateStr, $loanDueDateStr);
                $stmt_member->fetch();
                $stmt_member->close();
  if ($existingLoan > 0) {
                    $message = "Member already has an outstanding loan. Please pay it off first.";
                    $message_type = "error";
                } elseif ($memberShares < 5000) {
                    $message = "Member must have at least Ksh 5,000 in shares to apply for a loan.";
                    $message_type = "error";
                } else {
                    $maxLoanAmount = $memberShares * 0.60;
                    if ($loanAmount > $maxLoanAmount) {
                        $message = "Loan amount (Ksh " . number_format($loanAmount, 2) . ") exceeds eligibility. Maximum allowed: Ksh " . number_format($maxLoanAmount, 2) . " (60% of your shares).";
                        $message_type = "error";
                    } else {
                        $loanTakenDate = date('Y-m-d');
                        $loanDueDate = date('Y-m-d', strtotime('+3 months'));
$conn->begin_transaction();
                        try {
                            $update_loan_stmt = $conn->prepare("UPDATE members SET loan_amount = ?, loan_taken_date = ?, loan_due_date = ?, five_percent_interest_applied = 0 WHERE id = ?");
                            if (!$update_loan_stmt) {
                                throw new Exception("Failed to prepare update loan statement: " . $conn->error);
                            }
                            $update_loan_stmt->bind_param("dssi", $loanAmount, $loanTakenDate, $loanDueDate, $memberId);
                            if (!$update_loan_stmt->execute()) {
                                throw new Exception("Error applying loan: " . $conn->error);
                            }
                            $update_loan_stmt->close();
                            $insert_txn_stmt = $conn->prepare("INSERT INTO transactions (member_id, transaction_type, amount, notes) VALUES (?, 'loan_application', ?, ?)");
                            if (!$insert_txn_stmt) {
                                throw new Exception("Failed to prepare loan transaction statement: " . $conn->error);
                            }
                            $notes = "Loan application of Ksh " . number_format($loanAmount, 2);
                            $insert_txn_stmt->bind_param("ids", $memberId, $loanAmount, $notes);
                            if (!$insert_txn_stmt->execute()) {
                                throw new Exception("Error recording loan transaction: " . $conn->error);
                            }
                            $insert_txn_stmt->close();

                            $conn->commit();
                            $message = "Loan of Ksh " . number_format($loanAmount, 2) . " approved. Due by: " . $loanDueDate . ".";
                            $message_type = "success";
                            header("Location: index.php?page=loans&msg=" . urlencode($message) . "&type=" . $message_type);
                            exit();
                        } catch (Exception $e) {
                            $conn->rollback();
                            $message = "Loan application failed: " . $e->getMessage();
                            $message_type = "error";
                        }
                    }
                }
            }
        }
    }
    if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['pay_loan'])) {
        $memberId = (int)$_POST['memberId'];
        $paymentAmount = (float)$_POST['paymentAmount'];

        if ($memberId <= 0 || $paymentAmount <= 0) {
            $message = "Please select a valid member and enter a positive payment amount.";
            $message_type = "error";
        } else {
            $stmt_loan_details = $conn->prepare("SELECT loan_amount, loan_taken_date, loan_due_date, five_percent_interest_applied FROM members WHERE id = ?");
            if (!$stmt_loan_details) {
                error_log("Failed to prepare loan payment details statement: " . $conn->error);
                $message = "An internal error occurred checking loan details.";
                $message_type = "error";
            } else {
                $stmt_loan_details->bind_param("i", $memberId);
                $stmt_loan_details->execute();
                $stmt_loan_details->bind_result($currentLoanAmount, $loanTakenDateStr, $loanDueDateStr, $interestApplied); // Added $loanTakenDateStr
                $stmt_loan_details->fetch();
                $stmt_loan_details->close();
                if ($currentLoanAmount <= 0) {
                    $message = "This member has no outstanding loan.";
                    $message_type = "error";
                } elseif ($paymentAmount > $currentLoanAmount) {
                    $message = "Payment amount (Ksh " . number_format($paymentAmount, 2) . ") exceeds the outstanding loan (Ksh " . number_format($currentLoanAmount, 2) . ").";
                    $message_type = "error";
                } else{
                    $today = new DateTime();
                    $loanDueDate = ($loanDueDateStr && $loanDueDateStr != '0000-00-00') ? new DateTime($loanDueDateStr) : null;
                    $interestAdded = 0;
                    $interestMessage = "";

                    if ($loanDueDate && $today > $loanDueDate && !$interestApplied) {
                        $interestAmount = $currentLoanAmount * 0.05;
                        $currentLoanAmount += $interestAmount; 
                        $interestAdded = $interestAmount; 
                        $interestMessage = " 5% interest (Ksh " . number_format($interestAmount, 2) . ") applied due to overdue loan.";
                    }

                    $newLoanAmount = $currentLoanAmount - $paymentAmount;
                    $resetLoanDates = ($newLoanAmount <= 0) ? true : false; 

                    $conn->begin_transaction();
                    try {
                        $finalLoanTakenDate = $resetLoanDates ? null : $loanTakenDateStr;
                        $finalLoanDueDate = $resetLoanDates ? null : $loanDueDateStr;
                        $finalInterestStatus = ($interestAdded > 0) ? 1 : ($resetLoanDates ? 0 : $interestApplied);
  $update_stmt_loan = $conn->prepare("UPDATE members SET loan_amount = ?, loan_taken_date = ?, loan_due_date = ?, five_percent_interest_applied = ? WHERE id = ?");
if (!$update_stmt_loan) {
                            throw new Exception("Failed to prepare update loan statement: " . $conn->error);
                        }
                        $update_stmt_loan->bind_param("dssii",
                            $newLoanAmount,
                            $finalLoanTakenDate,
                            $finalLoanDueDate,  
                            $finalInterestStatus,
                            $memberId
                        );

                        if (!$update_stmt_loan->execute()) {
                            throw new Exception("Error updating loan: " . $conn->error);
                        }
                        $update_stmt_loan->close();

                        // Record transaction
                        $insert_txn_stmt = $conn->prepare("INSERT INTO transactions (member_id, transaction_type, amount, notes) VALUES (?, 'loan_payment', ?, ?)");
                        if (!$insert_txn_stmt) {
                            throw new Exception("Failed to prepare loan payment transaction statement: " . $conn->error);
                        }
                        $notes = "Loan payment of Ksh " . number_format($paymentAmount, 2);
                        if ($interestAdded > 0) {
                            $notes .= " (includes Ksh " . number_format($interestAdded, 2) . " interest)";
                        }
                        $insert_txn_stmt->bind_param("ids", $memberId, $paymentAmount, $notes);
                        if (!$insert_txn_stmt->execute()) {
                            throw new Exception("Error recording loan payment transaction: " . $conn->error);
                        }
                        $insert_txn_stmt->close();

                        $conn->commit();
                        $message = "Loan payment of Ksh " . number_format($paymentAmount, 2) . " processed successfully." . $interestMessage . " Outstanding loan: Ksh " . number_format($newLoanAmount, 2) . ".";
                        $message_type = "success";
                        header("Location: index.php?page=loans&msg=" . urlencode($message) . "&type=" . $message_type);
                        exit();
                    } catch (Exception $e) {
                        $conn->rollback();
                        $message = "Loan payment failed: " . $e->getMessage();
                        $message_type = "error";
                    }
                }
            }
        }
    }
} $members = [];
if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    $result = $conn->query("SELECT * FROM members ORDER BY full_name ASC");
    if ($result) { // Check if query itself was successful
        if ($result->num_rows > 0) {
            while($row = $result->fetch_assoc()) {
                $row['loan_taken_date_obj'] = ($row['loan_taken_date'] && $row['loan_taken_date'] != '0000-00-00') ? new DateTime($row['loan_taken_date']) : null;
                $row['loan_due_date_obj'] = ($row['loan_due_date'] && $row['loan_due_date'] != '0000-00-00') ? new DateTime($row['loan_due_date']) : null;
                $members[] = $row;
            }
        }
        $result->free(); 
    } else {
        error_log("Error fetching members: " . $conn->error);
        $message = "Error retrieving member list.";
        $message_type = "error";
    }
}
$currentPage = 'home';
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    $currentPage = 'login';
} elseif (isset($_GET['page'])) {
    $allowedPages = ['home', 'loans', 'addMember', 'shares', 'viewMembers', 'adminSettings'];
    if (in_array($_GET['page'], $allowedPages)) {
        $currentPage = $_GET['page'];
    } else {
        $currentPage = 'home';
    }
}
if (isset($_GET['msg'])) {
    $message = urldecode($_GET['msg']);
    $message_type = isset($_GET['type']) ? $_GET['type'] : 'info';
}
if (isset($conn) && $conn instanceof mysqli) {
    $conn->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MWTVC Students SACCO</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css"> <!-- Link to your custom CSS file -->
</head>
<body class="min-h-screen flex flex-col items-center py-8">

    <header>
        <div class="container">
            <h1>MWTVC Students SACCO</h1>
            <nav>
                <?php if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true): ?>
                    <a href="?page=home" class="nav-link <?= $currentPage == 'home' ? 'active' : 'default' ?>">
                        Home
                    </a>
                    <a href="?page=loans" class="nav-link <?= $currentPage == 'loans' ? 'active' : 'default' ?>">
                        Loans
                    </a>
                    <a href="?page=addMember" class="nav-link <?= $currentPage == 'addMember' ? 'active' : 'default' ?>">
                        Add New Member
                    </a>
                    <a href="?page=shares" class="nav-link <?= $currentPage == 'shares' ? 'active' : 'default' ?>">
                        Shares
                    </a>
                    <a href="?page=viewMembers" class="nav-link <?= $currentPage == 'viewMembers' ? 'active' : 'default' ?>">
                        View Members
                    </a>
                    <a href="?page=adminSettings" class="nav-link <?= $currentPage == 'adminSettings' ? 'active' : 'default' ?>">
                        Admin Settings
                    </a>
                    <a href="?logout=true" class="nav-link logout">
                        Logout
                    </a>
                <?php else: ?>
                    <a href="?page=login" class="nav-link <?= $currentPage == 'login' ? 'active' : 'default' ?>">
                        Login
                    </a>
                <?php endif; ?>
            </nav>
        </div>
    </header>

    <main id="main-content" class="container">
        <?php if ($message): ?>
            <div class="message-box <?= $message_type == 'success' ? 'message-success' : ($message_type == 'info' ? 'message-info' : 'message-error') ?>">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <?php
        switch ($currentPage) {
            case 'login':
                include 'templates/login.php';
                break;
            case 'home':
                include 'templates/home.php';
                break;
            case 'loans':
                include 'templates/loans.php';
                break;
            case 'addMember':
                include 'templates/add_member.php';
                break;
            case 'shares':
                include 'templates/shares.php';
                break;
            case 'viewMembers':
                include 'templates/view_members.php';
                break;
            case 'adminSettings':
                include 'templates/admin_settings.php';
                break;
            default:
                include 'templates/home.php';
                break;
        }
        ?>
    </main>

    <footer> &copy; DEVELOPED BY MWANIKHE OLIVER KIRUI. All Rights Reserved 2025<br>
        <p>
    <a href="mailto:oliverkirui2003@gmail.com" style="
        display: inline-block;
        padding: 0.75rem 1.5rem; /* Equivalent to px-6 py-3 */
        background-color: #2563eb; /* Blue-600 */
        color: #ffffff; /* White text */
        font-weight: 700; /* font-bold */
        border-radius: 0.5rem; /* rounded-lg */
        cursor: pointer;
        text-decoration: none; /* Remove underline from link */
        transition: background-color 0.3s ease-in-out, transform 0.3s ease-in-out, box-shadow 0.3s ease-in-out;
        border: none;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    " onmouseover="this.style.backgroundColor='#1e40af'; this.style.transform='translateY(-2px)';" onmouseout="this.style.backgroundColor='#2563eb'; this.style.transform='translateY(0)';">
        MAIL THE DEVELOPER
    </a>
</p>
    </footer>

    <script>
        document.getElementById('current-year').textContent = new Date().getFullYear();
    </script>
</body>
</html>
