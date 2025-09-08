<?php
/**
 * Document Tracking System - Authentication Backend
 * Handles user authentication, registration, and OTP verification
 */

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Include PHPMailer
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

// Set content type to JSON
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Database configuration for MySQL
$db_host = 'localhost';
$db_port = '8000';
$db_name = 'auth_db';
$db_user = 'root';
$db_pass = '';

// Email configuration
$email_config = [
    'smtp_host' => 'smtp.gmail.com',
    'smtp_port' => 587,
    'smtp_user' => 'systemdtrack@gmail.com',
    'smtp_pass' => 'buvj edrc pgfb qxfq',
    'from_email' => 'systemdtrack@gmail.com',
    'from_name' => 'Document Tracking System'
];

/**
 * Database connection class
 */
class Database {
    private $connection;
    
    public function __construct($host, $port, $dbname, $username, $password) {
        try {
            $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
            $this->connection = new PDO($dsn, $username, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4"
            ]);
        } catch (PDOException $e) {
            throw new Exception('Database connection failed: ' . $e->getMessage());
        }
    }
    
    public function getConnection() {
        return $this->connection;
    }
}

/**
 * Email service class
 */
class EmailService {
    private $config;
    
    public function __construct($config) {
        $this->config = $config;
    }
    
    /**
     * Send email using Gmail SMTP
     */
    public function sendEmail($to, $subject, $message) {
        $mail = new PHPMailer(true);

        try {
            // Server settings
            $mail->isSMTP();
            $mail->Host       = $this->config['smtp_host'];
            $mail->SMTPAuth   = true;
            $mail->Username   = $this->config['smtp_user'];
            $mail->Password   = $this->config['smtp_pass'];
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port       = $this->config['smtp_port'];

            // Recipients
            $mail->setFrom($this->config['from_email'], $this->config['from_name']);
            $mail->addAddress($to);

            // Content
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $message;

            $result = $mail->send();
            
            // Log success
            error_log("EMAIL SUCCESSFULLY SENT TO: {$to}");
            
            return $result;
        } catch (Exception $e) {
            // Log error
            error_log("EMAIL FAILED TO: {$to} - Error: {$mail->ErrorInfo}");
            return false;
        }
    }
    
    /**
     * Generate 6-digit OTP
     */
    public function generateOTP() {
        return str_pad(rand(100000, 999999), 6, '0', STR_PAD_LEFT);
    }
}

/**
 * Authentication service class
 */
class AuthService {
    private $db;
    private $emailService;
    
    public function __construct($database, $emailService) {
        $this->db = $database->getConnection();
        $this->emailService = $emailService;
    }
    
    /**
     * Validate user credentials
     */
    public function validateCredentials($username, $password) {
        try {
            $stmt = $this->db->prepare("
                SELECT id, first_name, last_name, email, username, password 
                FROM users 
                WHERE username = ? OR email = ?
            ");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            if ($user && password_verify($password, $user['password'])) {
                // Remove password from response
                unset($user['password']);
                return [
                    'success' => true,
                    'user' => $user
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Invalid username or password'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Database error: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Send OTP to user's email
     */
    public function sendOTP($email) {
        try {
            // Generate OTP
            $otp = $this->emailService->generateOTP();
            $expires_at = date('Y-m-d H:i:s', strtotime('+10 minutes'));
            
            // Store OTP in database
            $stmt = $this->db->prepare("
                INSERT INTO otp_codes (email, otp_code, expires_at) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([$email, $otp, $expires_at]);
            
            // Send email
            $subject = 'Your Login OTP - Document Tracking System';
            $message = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: linear-gradient(135deg, #ff9966, #e68553); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
                        .otp-code { background: #fff; border: 2px solid #ff9966; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; color: #e68553; margin: 20px 0; border-radius: 8px; }
                        .warning { color: #dc3545; font-size: 14px; margin-top: 15px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <div class='header'>
                            <h1>Document Tracking System</h1>
                            <p>One-Time Password (OTP)</p>
                        </div>
                        <div class='content'>
                            <h2>Your Login OTP</h2>
                            <p>Use the following 6-digit code to complete your login:</p>
                            <div class='otp-code'>{$otp}</div>
                            <p>This code will expire in 10 minutes.</p>
                            <p class='warning'>⚠️ If you didn't request this code, please ignore this email or contact support.</p>
                        </div>
                    </div>
                </body>
                </html>
            ";
            
            $emailSent = $this->emailService->sendEmail($email, $subject, $message);
            
            if ($emailSent) {
                return [
                    'success' => true,
                    'message' => 'OTP sent successfully'
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Failed to send OTP'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error sending OTP: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Verify OTP code
     */
    public function verifyOTP($email, $otp) {
        try {
            $stmt = $this->db->prepare("
                SELECT * FROM otp_codes 
                WHERE email = ? AND otp_code = ? AND used = false AND expires_at > NOW()
                ORDER BY created_at DESC 
                LIMIT 1
            ");
            $stmt->execute([$email, $otp]);
            $otpRecord = $stmt->fetch();
            
            if ($otpRecord) {
                // Mark OTP as used
                $updateStmt = $this->db->prepare("UPDATE otp_codes SET used = true WHERE id = ?");
                $updateStmt->execute([$otpRecord['id']]);
                
                return [
                    'success' => true,
                    'message' => 'OTP verified successfully'
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Invalid or expired OTP'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error verifying OTP: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Send verification code for signup
     */
    public function sendVerificationCode($email) {
        try {
            // Check if email already exists
            $stmt = $this->db->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                return [
                    'success' => false,
                    'message' => 'Email already registered'
                ];
            }
            
            // Generate verification code
            $code = $this->emailService->generateOTP();
            $expires_at = date('Y-m-d H:i:s', strtotime('+15 minutes'));
            
            // Store verification code
            $stmt = $this->db->prepare("
                INSERT INTO otp_codes (email, otp_code, expires_at) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([$email, $code, $expires_at]);
            
            // Send email
            $subject = 'Email Verification - Document Tracking System';
            $message = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: linear-gradient(135deg, #ff9966, #e68553); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
                        .code { background: #fff; border: 2px solid #ff9966; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; color: #e68553; margin: 20px 0; border-radius: 8px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <div class='header'>
                            <h1>Welcome to Document Tracking System</h1>
                            <p>Email Verification Required</p>
                        </div>
                        <div class='content'>
                            <h2>Verify Your Email Address</h2>
                            <p>Please use the following 6-digit code to verify your email:</p>
                            <div class='code'>{$code}</div>
                            <p>This code will expire in 15 minutes.</p>
                            <p>Once verified, you can complete your account registration.</p>
                        </div>
                    </div>
                </body>
                </html>
            ";
            
            $emailSent = $this->emailService->sendEmail($email, $subject, $message);
            
            if ($emailSent) {
                return [
                    'success' => true,
                    'message' => 'Verification code sent'
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Failed to send verification code'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error sending verification: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Verify email code for signup
     */
    public function verifyEmailCode($email, $code) {
        try {
            $stmt = $this->db->prepare("
                SELECT * FROM otp_codes 
                WHERE email = ? AND otp_code = ? AND used = false AND expires_at > NOW()
                ORDER BY created_at DESC 
                LIMIT 1
            ");
            $stmt->execute([$email, $code]);
            $codeRecord = $stmt->fetch();
            
            if ($codeRecord) {
                // Mark code as used
                $updateStmt = $this->db->prepare("UPDATE otp_codes SET used = true WHERE id = ?");
                $updateStmt->execute([$codeRecord['id']]);
                
                return [
                    'success' => true,
                    'message' => 'Email verified successfully'
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Invalid or expired verification code'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error verifying code: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Register new user
     */
    public function registerUser($data) {
        try {
            // Validate required fields
            $required = ['firstName', 'lastName', 'address', 'idNumber', 'department', 'year', 'email', 'username', 'password'];
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    return [
                        'success' => false,
                        'message' => "Missing required field: {$field}"
                    ];
                }
            }
            
            // Check for existing username or email
            $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR id_number = ?");
            $stmt->execute([$data['username'], $data['email'], $data['idNumber']]);
            if ($stmt->fetch()) {
                return [
                    'success' => false,
                    'message' => 'Username, email, or ID number already exists'
                ];
            }
            
            // Hash password
            $hashedPassword = password_hash($data['password'], PASSWORD_BCRYPT);
            
            // Insert user
            $stmt = $this->db->prepare("
                INSERT INTO users (first_name, last_name, address, id_number, department, year, email, username, password, email_verified) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, true)
            ");
            
            $result = $stmt->execute([
                $data['firstName'],
                $data['lastName'],
                $data['address'],
                $data['idNumber'],
                $data['department'],
                (int)$data['year'],
                $data['email'],
                $data['username'],
                $hashedPassword
            ]);
            
            if ($result) {
                return [
                    'success' => true,
                    'message' => 'User registered successfully'
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Failed to create user'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Registration error: ' . $e->getMessage()
            ];
        }
    }
    
    /**
     * Send password reset email
     */
    public function sendPasswordReset($email) {
        try {
            // Check if email exists
            $stmt = $this->db->prepare("SELECT id, first_name, username FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if (!$user) {
                return [
                    'success' => false,
                    'message' => 'Email address not found'
                ];
            }
            
            // Generate reset token
            $resetToken = $this->emailService->generateOTP();
            $expires_at = date('Y-m-d H:i:s', strtotime('+30 minutes'));
            
            // Store reset token
            $stmt = $this->db->prepare("
                INSERT INTO otp_codes (email, otp_code, expires_at) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([$email, $resetToken, $expires_at]);
            
            // Send email
            $subject = 'Password Reset - Document Tracking System';
            $message = "
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: linear-gradient(135deg, #ff9966, #e68553); color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 8px 8px; }
                        .reset-token { background: #fff; border: 2px solid #ff9966; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; color: #e68553; margin: 20px 0; border-radius: 8px; }
                        .warning { color: #dc3545; font-size: 14px; margin-top: 15px; }
                    </style>
                </head>
                <body>
                    <div class='container'>
                        <div class='header'>
                            <h1>Document Tracking System</h1>
                            <p>Password Reset Request</p>
                        </div>
                        <div class='content'>
                            <h2>Hello {$user['first_name']},</h2>
                            <p>We received a request to reset your password for username: <strong>{$user['username']}</strong></p>
                            <p>Please use the following reset code to create a new password:</p>
                            <div class='reset-token'>{$resetToken}</div>
                            <p>This code will expire in 30 minutes.</p>
                            <p class='warning'>⚠️ If you didn't request this password reset, please ignore this email and contact support immediately.</p>
                        </div>
                    </div>
                </body>
                </html>
            ";
            
            $emailSent = $this->emailService->sendEmail($email, $subject, $message);
            
            if ($emailSent) {
                return [
                    'success' => true,
                    'message' => 'Password reset code sent to your email'
                ];
            }
            
            return [
                'success' => false,
                'message' => 'Failed to send password reset email'
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Error sending password reset: ' . $e->getMessage()
            ];
        }
    }
}

// Initialize services
try {
    $database = new Database($db_host, $db_port, $db_name, $db_user, $db_pass);
    $emailService = new EmailService($email_config);
    $authService = new AuthService($database, $emailService);
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'message' => 'Service initialization error: ' . $e->getMessage()
    ]);
    exit;
}

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch ($action) {
        case 'validate_credentials':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            echo json_encode($authService->validateCredentials($username, $password));
            break;
            
        case 'send_otp':
            $email = $_POST['email'] ?? '';
            echo json_encode($authService->sendOTP($email));
            break;
            
        case 'verify_otp':
            $email = $_POST['email'] ?? '';
            $otp = $_POST['otp'] ?? '';
            echo json_encode($authService->verifyOTP($email, $otp));
            break;
            
        case 'send_verification':
            $email = $_POST['email'] ?? '';
            echo json_encode($authService->sendVerificationCode($email));
            break;
            
        case 'verify_code':
            $email = $_POST['email'] ?? '';
            $code = $_POST['code'] ?? '';
            echo json_encode($authService->verifyEmailCode($email, $code));
            break;
            
        case 'signup':
            echo json_encode($authService->registerUser($_POST));
            break;
            
        case 'forgot_password':
            $email = $_POST['email'] ?? '';
            echo json_encode($authService->sendPasswordReset($email));
            break;
            
        default:
            echo json_encode([
                'success' => false,
                'message' => 'Invalid action'
            ]);
            break;
    }
} else {
    echo json_encode([
        'success' => false,
        'message' => 'Only POST requests are allowed'
    ]);
}
?>