<?php
session_start();

// ===================== CONFIGURATION =====================
define('BOT_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('TELEGRAM_API', 'https://api.telegram.org/bot' . BOT_TOKEN . '/');
define('STORAGE_CHAT_ID', '-1003632097565'); // Ganti dengan channel/group ID
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD', 'admin');
define('MAX_FILE_SIZE', 1000 * 1024 * 1024); // 2GB
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', 'mp4', 'mp3', 'avi', 'mov', 'wav', 'xls', 'xlsx', 'ppt', 'pptx']);
define('USERS_FILE', __DIR__ . '/users.json');
define('FILES_FILE', __DIR__ . '/files.json');

// Inisialisasi file users.json jika belum ada
if (!file_exists(USERS_FILE)) {
    file_put_contents(USERS_FILE, json_encode([
        'admin' => [
            'password' => password_hash('admin', PASSWORD_DEFAULT),
            'is_admin' => true,
            'created_at' => date('Y-m-d H:i:s'),
            'created_by' => 'system'
        ]
    ], JSON_PRETTY_PRINT));
}

// Inisialisasi file files.json jika belum ada
if (!file_exists(FILES_FILE)) {
    file_put_contents(FILES_FILE, json_encode([], JSON_PRETTY_PRINT));
}

// ===================== HELPER FUNCTIONS =====================
function isLoggedIn() {
    return isset($_SESSION['user']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === true;
}

function redirect($url) {
    header("Location: $url");
    exit();
}

function sanitize($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, 2) . ' ' . $units[$pow];
}

function getFileIcon($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icon_map = [
        'pdf' => 'fas fa-file-pdf',
        'doc' => 'fas fa-file-word', 'docx' => 'fas fa-file-word',
        'txt' => 'fas fa-file-lines',
        'zip' => 'fas fa-file-zipper', 'rar' => 'fas fa-file-zipper', '7z' => 'fas fa-file-zipper',
        'jpg' => 'fas fa-image', 'jpeg' => 'fas fa-image', 'png' => 'fas fa-image', 'gif' => 'fas fa-image', 'bmp' => 'fas fa-image',
        'mp4' => 'fas fa-file-video', 'avi' => 'fas fa-file-video', 'mov' => 'fas fa-file-video', 'mkv' => 'fas fa-file-video',
        'mp3' => 'fas fa-file-audio', 'wav' => 'fas fa-file-audio', 'flac' => 'fas fa-file-audio',
        'xls' => 'fas fa-file-excel', 'xlsx' => 'fas fa-file-excel',
        'ppt' => 'fas fa-file-powerpoint', 'pptx' => 'fas fa-file-powerpoint'
    ];
    return $icon_map[$ext] ?? 'fas fa-file';
}

// ===================== TELEGRAM BOT CLASS =====================
class TelegramNAS {
    private $bot_token;
    
    public function __construct($token = null) {
        $this->bot_token = $token ?: BOT_TOKEN;
    }
    
    public function sendDocument($file_path, $caption = '') {
        $url = TELEGRAM_API . 'sendDocument';
        
        $post_fields = [
            'chat_id' => STORAGE_CHAT_ID,
            'caption' => $caption,
            'document' => new CURLFile($file_path)
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: multipart/form-data']);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true);
    }
    
    public function getFile($file_id) {
        $url = TELEGRAM_API . 'getFile?file_id=' . urlencode($file_id);
        $response = file_get_contents($url);
        return json_decode($response, true);
    }
    
    public function getFileUrl($file_id) {
        $file_info = $this->getFile($file_id);
        if ($file_info['ok']) {
            $file_path = $file_info['result']['file_path'];
            return 'https://api.telegram.org/file/bot' . $this->bot_token . '/' . $file_path;
        }
        return null;
    }
    
    public function deleteMessage($message_id) {
        $url = TELEGRAM_API . 'deleteMessage';
        
        $post_fields = [
            'chat_id' => STORAGE_CHAT_ID,
            'message_id' => $message_id
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($post_fields));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true);
    }
    
    public function uploadFile($file_input_name, $username) {
        if (!isset($_FILES[$file_input_name])) {
            return ['success' => false, 'error' => 'No file uploaded'];
        }
        
        $file = $_FILES[$file_input_name];
        $file_name = basename($file['name']);
        $file_tmp = $file['tmp_name'];
        
        // Validasi ukuran file
        if ($file['size'] > MAX_FILE_SIZE) {
            return ['success' => false, 'error' => 'File too large (Max 2GB)'];
        }
        
        // Validasi ekstensi
        $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
        if (!in_array($file_ext, ALLOWED_EXTENSIONS)) {
            return ['success' => false, 'error' => 'File type not allowed'];
        }
        
        // Buat caption dengan format: filename:username::cloudnas
        $caption = $file_name . ':' . $username . '::cloudnas';
        
        // Upload ke Telegram
        $result = $this->sendDocument($file_tmp, $caption);
        
        if ($result['ok']) {
            // Simpan metadata file
            $this->saveFileMetadata(
                $result['result']['message_id'],
                $file_name,
                $username,
                $file['size'],
                $file_ext,
                isset($result['result']['document']['file_id']) ? $result['result']['document']['file_id'] : null
            );
            
            return [
                'success' => true,
                'message_id' => $result['result']['message_id'],
                'file_name' => $file_name,
                'file_size' => $file['size']
            ];
        }
        
        return ['success' => false, 'error' => 'Telegram upload failed: ' . ($result['description'] ?? 'Unknown error')];
    }
    
    private function saveFileMetadata($message_id, $filename, $username, $size, $extension, $file_id = null) {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        
        $files[$message_id] = [
            'id' => $message_id,
            'name' => $filename,
            'username' => $username,
            'size' => $size,
            'extension' => $extension,
            'file_id' => $file_id,
            'uploaded_at' => date('Y-m-d H:i:s'),
            'caption' => $filename . ':' . $username . '::cloudnas'
        ];
        
        file_put_contents(FILES_FILE, json_encode($files, JSON_PRETTY_PRINT));
    }
    
    public function getUserFiles($username) {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        $user_files = [];
        
        foreach ($files as $file) {
            if ($file['username'] === $username) {
                $user_files[] = $file;
            }
        }
        
        // Urutkan berdasarkan tanggal upload (terbaru dulu)
        usort($user_files, function($a, $b) {
            return strtotime($b['uploaded_at']) - strtotime($a['uploaded_at']);
        });
        
        return $user_files;
    }
    
    public function getAllFiles() {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        return array_values($files);
    }
    
    public function deleteFile($message_id, $username) {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        
        if (isset($files[$message_id]) && ($files[$message_id]['username'] === $username || isAdmin())) {
            // Hapus dari Telegram
            $delete_result = $this->deleteMessage($message_id);
            
            if ($delete_result['ok']) {
                // Hapus dari metadata
                unset($files[$message_id]);
                file_put_contents(FILES_FILE, json_encode($files, JSON_PRETTY_PRINT));
                return ['success' => true];
            }
            return ['success' => false, 'error' => 'Failed to delete from Telegram'];
        }
        
        return ['success' => false, 'error' => 'File not found or access denied'];
    }
}

// ===================== ROUTING =====================
$action = $_GET['action'] ?? '';
$telegram = new TelegramNAS();

// Handle API actions
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['api_action'])) {
    header('Content-Type: application/json');
    
    switch ($_POST['api_action']) {
        case 'login':
            $username = sanitize($_POST['username']);
            $password = $_POST['password'];
            
            $users = json_decode(file_get_contents(USERS_FILE), true);
            
            if (isset($users[$username]) && password_verify($password, $users[$username]['password'])) {
                $_SESSION['user'] = $username;
                $_SESSION['is_admin'] = $users[$username]['is_admin'] ?? false;
                
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Invalid credentials']);
            }
            exit;
            
        case 'upload':
            if (!isLoggedIn()) {
                echo json_encode(['success' => false, 'error' => 'Not authenticated']);
                exit;
            }
            
            $result = $telegram->uploadFile('file', $_SESSION['user']);
            echo json_encode($result);
            exit;
            
        case 'logout':
            session_destroy();
            echo json_encode(['success' => true]);
            exit;
            
        case 'add_user':
            if (!isAdmin()) {
                echo json_encode(['success' => false, 'error' => 'Access denied']);
                exit;
            }
            
            $new_username = sanitize($_POST['username']);
            $new_password = $_POST['password'];
            
            $users = json_decode(file_get_contents(USERS_FILE), true);
            
            if (isset($users[$new_username])) {
                echo json_encode(['success' => false, 'error' => 'Username already exists']);
            } elseif (strlen($new_password) < 4) {
                echo json_encode(['success' => false, 'error' => 'Password must be at least 4 characters']);
            } else {
                $users[$new_username] = [
                    'password' => password_hash($new_password, PASSWORD_DEFAULT),
                    'is_admin' => false,
                    'created_at' => date('Y-m-d H:i:s'),
                    'created_by' => $_SESSION['user']
                ];
                
                file_put_contents(USERS_FILE, json_encode($users, JSON_PRETTY_PRINT));
                echo json_encode(['success' => true]);
            }
            exit;
            
        case 'delete_user':
            if (!isAdmin()) {
                echo json_encode(['success' => false, 'error' => 'Access denied']);
                exit;
            }
            
            $delete_user = sanitize($_POST['username']);
            $users = json_decode(file_get_contents(USERS_FILE), true);
            
            if ($delete_user !== $_SESSION['user'] && $delete_user !== 'admin' && isset($users[$delete_user])) {
                unset($users[$delete_user]);
                file_put_contents(USERS_FILE, json_encode($users, JSON_PRETTY_PRINT));
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'error' => 'Cannot delete this user']);
            }
            exit;
            
        case 'delete_file':
            if (!isLoggedIn()) {
                echo json_encode(['success' => false, 'error' => 'Not authenticated']);
                exit;
            }
            
            $message_id = intval($_POST['message_id']);
            $result = $telegram->deleteFile($message_id, $_SESSION['user']);
            echo json_encode($result);
            exit;
    }
}

// Handle file download
if ($action === 'download' && isset($_GET['id'])) {
    if (!isLoggedIn()) {
        header('HTTP/1.0 401 Unauthorized');
        exit('Unauthorized');
    }
    
    $message_id = intval($_GET['id']);
    $username = $_SESSION['user'];
    
    $files = json_decode(file_get_contents(FILES_FILE), true);
    
    if (isset($files[$message_id]) && ($files[$message_id]['username'] === $username || isAdmin())) {
        if (!empty($files[$message_id]['file_id'])) {
            $file_url = $telegram->getFileUrl($files[$message_id]['file_id']);
            if ($file_url) {
                // Redirect ke file Telegram
                header('Location: ' . $file_url);
                exit;
            }
        }
        
        // Fallback: beritahu user untuk download manual
        $filename = $files[$message_id]['name'];
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        echo "File: " . $filename . "\n";
        echo "File ID: " . $message_id . "\n";
        echo "Please download this file manually from Telegram\n";
        echo "or ask the administrator to check the configuration.";
        exit;
    }
    
    header('HTTP/1.0 404 Not Found');
    exit('File not found');
}

// Handle GET requests (pages)
switch ($action) {
    case 'logout':
        session_destroy();
        redirect('index.php');
        break;
        
    case 'admin':
        if (!isAdmin()) {
            redirect('index.php');
        }
        break;
        
    default:
        // Jika sudah login dan tidak ada action spesifik, tampilkan dashboard
        if (isLoggedIn() && empty($action)) {
            $action = 'dashboard';
        }
        break;
}

// ===================== PAGE RENDERING =====================
if (empty($action) || $action === 'login') {
    // LOGIN PAGE
    if (isLoggedIn()) {
        redirect('index.php?action=dashboard');
    }
    
    $users = json_decode(file_get_contents(USERS_FILE), true);
    $user_list = array_keys($users);
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CloudNAS - Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {
                background: linear-gradient(135deg, #0b1220, #07102a);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #fff;
            }
            .login-box {
                background: #0f1724;
                padding: 2rem;
                border-radius: 12px;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 6px 18px rgba(0,0,0,.6);
            }
            .btn-primary {
                background: #2563eb;
                border: none;
            }
            .btn-primary:hover {
                background: #1d4ed8;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2 class="text-center mb-4">
                <i class="fas fa-cloud me-2"></i>CloudNAS ☁️
            </h2>
            <div id="login-message"></div>
            <form id="login-form">
                <div class="mb-3">
                    <label class="form-label">Username</label>
                    <select name="username" class="form-control bg-dark text-white border-dark" required>
                        <?php foreach ($user_list as $user): ?>
                        <option value="<?= $user ?>"><?= $user ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="mb-3">
                    <label class="form-label">Password</label>
                    <input type="password" name="password" class="form-control bg-dark text-white border-dark" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">
                    <i class="fas fa-sign-in-alt me-2"></i>Login
                </button>
            </form>
        </div>
        
        <script>
        document.getElementById('login-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.append('api_action', 'login');
            
            const response = await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                window.location.href = 'index.php?action=dashboard';
            } else {
                document.getElementById('login-message').innerHTML = 
                    '<div class="alert alert-danger">' + (result.error || 'Login failed') + '</div>';
            }
        });
        </script>
    </body>
    </html>
    <?php
} elseif ($action === 'dashboard') {
    // DASHBOARD PAGE
    if (!isLoggedIn()) {
        redirect('index.php');
    }
    
    $username = $_SESSION['user'];
    $is_admin = isAdmin();
    $files = $telegram->getUserFiles($username);
    $total_size = 0;
    
    foreach ($files as $file) {
        $total_size += $file['size'];
    }
    
    // Hitung persentase penggunaan (asumsi 5GB storage)
    $max_storage = 5 * 1024 * 1024 * 1024; // 5GB
    $usage_percent = min(($total_size / $max_storage) * 100, 100);
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CloudNAS - Dashboard</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #007bff;
                --primary-dark: #0056b3;
                --secondary: #1a202c;
                --dark: #0f172a;
                --darker: #0d121c;
                --light: #e2e8f0;
                --gray: #94a3b8;
                --gray-dark: #4a5568;
                --success: #10b981;
                --danger: #f87171;
                --warning: #f59e0b;
            }
            
            body {
                font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: var(--darker);
                color: var(--light);
                min-height: 100vh;
            }
            
            .app-container {
                display: flex;
                min-height: 100vh;
            }
            
            .sidebar {
                width: 280px;
                background: var(--secondary);
                border-right: 1px solid rgba(255,255,255,0.08);
                display: flex;
                flex-direction: column;
            }
            
            .sidebar-header {
                padding: 20px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                background: var(--dark);
            }
            
            .nav-section {
                padding: 15px 0;
                border-bottom: 1px solid rgba(255,255,255,0.08);
            }
            
            .nav-item {
                display: flex;
                align-items: center;
                gap: 15px;
                padding: 10px 20px;
                color: var(--light);
                text-decoration: none;
                transition: all 0.2s ease;
                border-left: 4px solid transparent;
            }
            
            .nav-item:hover, .nav-item.active {
                background: rgba(255,255,255,0.08);
                border-left-color: var(--primary);
                color: white;
            }
            
            .storage-bar {
                padding: 20px;
                background: var(--dark);
                border-top: 1px solid rgba(255,255,255,0.1);
            }
            
            .progress-bar-custom {
                height: 8px;
                background-color: var(--gray-dark);
                border-radius: 4px;
                overflow: hidden;
            }
            
            .progress-bar-fill {
                height: 100%;
                background-color: var(--success);
            }
            
            .main-content {
                flex: 1;
                display: flex;
                flex-direction: column;
                overflow: hidden;
            }
            
            .top-bar {
                background: var(--secondary);
                padding: 18px 30px;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .card-custom {
                background: var(--secondary);
                border: 1px solid rgba(255,255,255,0.05);
                border-radius: 12px;
                margin-bottom: 30px;
                overflow: hidden;
            }
            
            .card-header-custom {
                padding: 18px 24px;
                border-bottom: 1px solid rgba(255,255,255,0.08);
                background: var(--dark);
            }
            
            .upload-area {
                border: 2px dashed rgba(255,255,255,0.3);
                border-radius: 10px;
                padding: 50px 24px;
                text-align: center;
                transition: all 0.3s ease;
                background: rgba(0, 0, 0, 0.2);
                cursor: pointer;
            }
            
            .upload-area:hover {
                border-color: var(--primary);
                background: rgba(0, 123, 255, 0.1);
            }
            
            .files-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                gap: 20px;
            }
            
            .file-card {
                background: var(--dark);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 10px;
                padding: 20px;
                transition: all 0.2s ease;
            }
            
            .file-card:hover {
                border-color: var(--primary);
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.4);
            }
            
            .file-icon {
                font-size: 2.5rem;
                margin-bottom: 12px;
                color: var(--primary);
            }
            
            @media (max-width: 768px) {
                .app-container {
                    flex-direction: column;
                }
                .sidebar {
                    width: 100%;
                }
                .files-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="app-container">
            <div class="sidebar">
                <div class="sidebar-header">
                    <h3><i class="fas fa-cloud me-2"></i>CloudNAS</h3>
                </div>
                
                <div class="nav-section">
                    <h6 class="px-3 text-uppercase text-gray">Storage</h6>
                    <a href="#" class="nav-item active">
                        <i class="fas fa-folder-open"></i>
                        <span>File Browser</span>
                    </a>
                    <a href="#" class="nav-item">
                        <i class="fas fa-chart-bar"></i>
                        <span>Statistics</span>
                    </a>
                </div>
                
                <?php if ($is_admin): ?>
                <div class="nav-section">
                    <h6 class="px-3 text-uppercase text-gray">Administration</h6>
                    <a href="index.php?action=admin" class="nav-item">
                        <i class="fas fa-users"></i>
                        <span>User Management</span>
                    </a>
                </div>
                <?php endif; ?>
                
                <div class="storage-bar mt-auto">
                    <div class="d-flex justify-content-between mb-2">
                        <small>Storage Usage</small>
                        <small><?= formatSize($total_size) ?> / 5.0 GB</small>
                    </div>
                    <div class="progress-bar-custom">
                        <div class="progress-bar-fill" style="width: <?= $usage_percent ?>%"></div>
                    </div>
                    <div class="mt-3 d-flex align-items-center">
                        <i class="fas fa-user-circle me-2"></i>
                        <div class="flex-grow-1">
                            <div class="fw-bold"><?= $username ?></div>
                            <small class="text-success">
                                <i class="fas fa-circle"></i> Online
                            </small>
                        </div>
                        <button onclick="logout()" class="btn btn-sm btn-danger">
                            <i class="fas fa-sign-out-alt"></i>
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="main-content">
                <div class="top-bar">
                    <h4 class="mb-0">TGCLOUD Storage ☁️</h4>
                    <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                        <i class="fas fa-upload me-2"></i>Upload File
                    </button>
                </div>
                
                <div class="content-area p-4" style="overflow-y: auto;">
                    <!-- Upload Card -->
                    <div class="card-custom mb-4">
                        <div class="card-header-custom">
                            <h5 class="mb-0"><i class="fas fa-cloud-arrow-up me-2"></i>Upload Files</h5>
                        </div>
                        <div class="card-body p-4">
                            <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                                <div class="upload-icon mb-3">
                                    <i class="fas fa-upload fa-3x text-primary"></i>
                                </div>
                                <h5>Drag & Drop files here</h5>
                                <p class="text-gray">or click to browse files (Max 2GB)</p>
                                <div class="mt-3">
                                    <button class="btn btn-primary">
                                        <i class="fas fa-folder-open me-2"></i>Browse Files
                                    </button>
                                </div>
                            </div>
                            <input type="file" id="fileInput" multiple style="display: none;" onchange="uploadFiles()">
                            <div id="upload-status" class="mt-3 p-3 rounded" style="background: rgba(0,0,0,0.3);"></div>
                        </div>
                    </div>
                    
                    <!-- Files Card -->
                    <div class="card-custom">
                        <div class="card-header-custom">
                            <h5 class="mb-0"><i class="fas fa-folder me-2"></i>Your Files (<?= count($files) ?>)</h5>
                        </div>
                        <div class="card-body p-4">
                            <?php if (empty($files)): ?>
                                <div class="text-center py-5">
                                    <i class="fas fa-box-open fa-4x text-gray mb-3"></i>
                                    <h5>No files found</h5>
                                    <p class="text-gray">Upload your first file to get started</p>
                                </div>
                            <?php else: ?>
                                <div class="files-grid">
                                    <?php foreach ($files as $file): ?>
                                    <div class="file-card">
                                        <div class="file-icon">
                                            <i class="<?= getFileIcon($file['name']) ?>"></i>
                                        </div>
                                        <div class="file-name fw-bold mb-1"><?= htmlspecialchars($file['name']) ?></div>
                                        <div class="file-meta text-gray mb-3">
                                            <?= formatSize($file['size']) ?> • <?= $file['uploaded_at'] ?>
                                        </div>
                                        <div class="file-actions d-flex gap-2">
                                            <button class="btn btn-sm btn-primary flex-grow-1" 
                                                    onclick="downloadFile(<?= $file['id'] ?>, '<?= addslashes($file['name']) ?>')">
                                                <i class="fas fa-download me-1"></i>Download
                                            </button>
                                            <button class="btn btn-sm btn-danger" 
                                                    onclick="deleteFile(<?= $file['id'] ?>)">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        // Format file size
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Upload files
        async function uploadFiles() {
            const files = document.getElementById('fileInput').files;
            const status = document.getElementById('upload-status');
            
            if (files.length === 0) return;
            
            status.innerHTML = `<div class="alert alert-info">Uploading ${files.length} file(s)...</div>`;
            status.className = 'mt-3 p-3 rounded alert-info';
            
            for (let file of files) {
                const formData = new FormData();
                formData.append('file', file);
                formData.append('api_action', 'upload');
                
                try {
                    const response = await fetch('index.php', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const result = await response.json();
                    
                    if (result.success) {
                        status.innerHTML = `<div class="alert alert-success">✓ Uploaded: ${file.name}</div>`;
                        status.className = 'mt-3 p-3 rounded alert-success';
                    } else {
                        status.innerHTML = `<div class="alert alert-danger">✗ ${file.name}: ${result.error}</div>`;
                        status.className = 'mt-3 p-3 rounded alert-danger';
                    }
                } catch (error) {
                    status.innerHTML = `<div class="alert alert-danger">✗ ${file.name}: Network error</div>`;
                    status.className = 'mt-3 p-3 rounded alert-danger';
                }
            }
            
            // Reload file list setelah 2 detik
            setTimeout(() => location.reload(), 2000);
        }
        
        // Download file
        function downloadFile(id, name) {
            window.open(`index.php?action=download&id=${id}`, '_blank');
        }
        
        // Delete file
        async function deleteFile(id) {
            if (!confirm('Are you sure you want to delete this file?')) return;
            
            const formData = new FormData();
            formData.append('api_action', 'delete_file');
            formData.append('message_id', id);
            
            const response = await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                alert('File deleted successfully');
                location.reload();
            } else {
                alert('Error: ' + result.error);
            }
        }
        
        // Logout
        async function logout() {
            const formData = new FormData();
            formData.append('api_action', 'logout');
            
            await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            window.location.href = 'index.php';
        }
        
        // Drag and drop functionality
        const uploadArea = document.querySelector('.upload-area');
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--primary)';
            uploadArea.style.background = 'rgba(0, 123, 255, 0.1)';
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'rgba(255,255,255,0.3)';
            uploadArea.style.background = 'rgba(0, 0, 0, 0.2)';
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'rgba(255,255,255,0.3)';
            uploadArea.style.background = 'rgba(0, 0, 0, 0.2)';
            
            const files = e.dataTransfer.files;
            document.getElementById('fileInput').files = files;
            uploadFiles();
        });
        </script>
    </body>
    </html>
    <?php
} elseif ($action === 'admin') {
    // ADMIN PAGE
    if (!isAdmin()) {
        redirect('index.php');
    }
    
    $users = json_decode(file_get_contents(USERS_FILE), true);
    $files = $telegram->getAllFiles();
    $total_files = count($files);
    $total_users = count($users);
    $total_storage = 0;
    
    foreach ($files as $file) {
        $total_storage += $file['size'];
    }
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CloudNAS - Admin Panel</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {
                background: linear-gradient(135deg, #0b1220, #07102a);
                color: white;
                min-height: 100vh;
                padding: 20px;
            }
            
            .card-custom {
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 10px;
                backdrop-filter: blur(10px);
            }
            
            .stat-card {
                transition: transform 0.3s;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <h2><i class="fas fa-crown me-2"></i>Admin Panel</h2>
                <div>
                    <a href="index.php?action=dashboard" class="btn btn-secondary me-2">
                        <i class="fas fa-arrow-left me-1"></i>Back to Dashboard
                    </a>
                    <button onclick="logout()" class="btn btn-danger">
                        <i class="fas fa-sign-out-alt me-1"></i>Logout
                    </button>
                </div>
            </div>
            
            <!-- Statistics -->
            <div class="row mb-4">
                <div class="col-md-3 mb-3">
                    <div class="card card-custom stat-card">
                        <div class="card-body text-center">
                            <i class="fas fa-users fa-2x text-primary mb-2"></i>
                            <h3><?= $total_users ?></h3>
                            <p class="text-gray">Total Users</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card card-custom stat-card">
                        <div class="card-body text-center">
                            <i class="fas fa-file fa-2x text-success mb-2"></i>
                            <h3><?= $total_files ?></h3>
                            <p class="text-gray">Total Files</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card card-custom stat-card">
                        <div class="card-body text-center">
                            <i class="fas fa-database fa-2x text-warning mb-2"></i>
                            <h3><?= formatSize($total_storage) ?></h3>
                            <p class="text-gray">Total Storage Used</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card card-custom stat-card">
                        <div class="card-body text-center">
                            <i class="fas fa-robot fa-2x text-info mb-2"></i>
                            <h3>Telegram</h3>
                            <p class="text-gray">Storage Backend</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row">
                <!-- Add User Form -->
                <div class="col-md-4 mb-4">
                    <div class="card card-custom">
                        <div class="card-body">
                            <h5 class="card-title mb-4">
                                <i class="fas fa-user-plus me-2"></i>Add New User
                            </h5>
                            <div id="add-user-message"></div>
                            <form id="add-user-form">
                                <div class="mb-3">
                                    <label class="form-label">Username</label>
                                    <input type="text" name="username" class="form-control bg-dark text-white border-dark" required>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Password</label>
                                    <input type="password" name="password" class="form-control bg-dark text-white border-dark" required>
                                </div>
                                <button type="submit" class="btn btn-primary w-100">
                                    <i class="fas fa-user-plus me-2"></i>Add User
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <!-- Users List -->
                <div class="col-md-8">
                    <div class="card card-custom">
                        <div class="card-body">
                            <h5 class="card-title mb-4">
                                <i class="fas fa-users me-2"></i>User Management
                                <span class="badge bg-primary ms-2"><?= $total_users ?></span>
                            </h5>
                            
                            <div class="table-responsive">
                                <table class="table table-dark table-hover">
                                    <thead>
                                        <tr>
                                            <th>Username</th>
                                            <th>Role</th>
                                            <th>Created At</th>
                                            <th>Created By</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($users as $username => $user): ?>
                                        <tr>
                                            <td>
                                                <?= $username ?>
                                                <?php if ($username === $_SESSION['user']): ?>
                                                    <span class="badge bg-info ms-1">You</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?php if ($user['is_admin']): ?>
                                                    <span class="badge bg-danger">Admin</span>
                                                <?php else: ?>
                                                    <span class="badge bg-secondary">User</span>
                                                <?php endif; ?>
                                            </td>
                                            <td><?= $user['created_at'] ?></td>
                                            <td><?= $user['created_by'] ?></td>
                                            <td>
                                                <?php if ($username !== 'admin' && $username !== $_SESSION['user']): ?>
                                                    <button class="btn btn-sm btn-danger" 
                                                            onclick="deleteUser('<?= $username ?>')">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <!-- All Files -->
                    <div class="card card-custom mt-4">
                        <div class="card-body">
                            <h5 class="card-title mb-4">
                                <i class="fas fa-folder me-2"></i>All System Files
                                <span class="badge bg-success ms-2"><?= $total_files ?></span>
                            </h5>
                            
                            <?php if (empty($files)): ?>
                                <div class="text-center py-4">
                                    <i class="fas fa-box-open fa-3x text-gray mb-3"></i>
                                    <p class="text-gray">No files in the system</p>
                                </div>
                            <?php else: ?>
                                <div class="table-responsive">
                                    <table class="table table-dark table-hover">
                                        <thead>
                                            <tr>
                                                <th>File Name</th>
                                                <th>Owner</th>
                                                <th>Size</th>
                                                <th>Uploaded</th>
                                                <th>Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php foreach ($files as $file): ?>
                                            <tr>
                                                <td>
                                                    <i class="<?= getFileIcon($file['name']) ?> me-2"></i>
                                                    <?= htmlspecialchars($file['name']) ?>
                                                </td>
                                                <td>
                                                    <span class="badge bg-primary"><?= $file['username'] ?></span>
                                                </td>
                                                <td><?= formatSize($file['size']) ?></td>
                                                <td><?= $file['uploaded_at'] ?></td>
                                                <td>
                                                    <button class="btn btn-sm btn-info me-1"
                                                            onclick="window.open('index.php?action=download&id=<?= $file['id'] ?>', '_blank')">
                                                        <i class="fas fa-download"></i>
                                                    </button>
                                                    <button class="btn btn-sm btn-danger"
                                                            onclick="adminDeleteFile(<?= $file['id'] ?>, '<?= addslashes($file['name']) ?>')">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </td>
                                            </tr>
                                            <?php endforeach; ?>
                                        </tbody>
                                    </table>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        // Add user
        document.getElementById('add-user-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            formData.append('api_action', 'add_user');
            
            const response = await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                document.getElementById('add-user-message').innerHTML = 
                    '<div class="alert alert-success">User added successfully!</div>';
                this.reset();
                setTimeout(() => location.reload(), 1000);
            } else {
                document.getElementById('add-user-message').innerHTML = 
                    '<div class="alert alert-danger">' + result.error + '</div>';
            }
        });
        
        // Delete user
        async function deleteUser(username) {
            if (!confirm(`Delete user "${username}"? All their files will remain but become orphaned.`)) return;
            
            const formData = new FormData();
            formData.append('api_action', 'delete_user');
            formData.append('username', username);
            
            const response = await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                alert('User deleted successfully');
                location.reload();
            } else {
                alert('Error: ' + result.error);
            }
        }
        
        // Admin delete file
        async function adminDeleteFile(id, name) {
            if (!confirm(`Delete file "${name}"?`)) return;
            
            const formData = new FormData();
            formData.append('api_action', 'delete_file');
            formData.append('message_id', id);
            
            const response = await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (result.success) {
                alert('File deleted successfully');
                location.reload();
            } else {
                alert('Error: ' + result.error);
            }
        }
        
        // Logout
        async function logout() {
            const formData = new FormData();
            formData.append('api_action', 'logout');
            
            await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            window.location.href = 'index.php';
        }
        </script>
    </body>
    </html>
    <?php
}
?>
