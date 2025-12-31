<?php
session_start();

// ===================== KONFIGURASI =====================
define('BOT_TOKEN', '8337490666:AAHhTs1w57Ynqs70GP3579IHqo491LHaCl8');
define('TELEGRAM_API', 'https://api.telegram.org/bot' . BOT_TOKEN . '/');
define('STORAGE_CHAT_ID', '-1003632097565');
define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD', 'admin');
define('MAX_FILE_SIZE', 2000 * 1024 * 1024); // 2GB
define('ALLOWED_EXTENSIONS', ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'pdf', 'doc', 'docx', 'txt', 'zip', 'rar', '7z', 'mp4', 'mp3', 'avi', 'mov', 'wav', 'flac', 'xls', 'xlsx', 'ppt', 'pptx', 'csv', 'json', 'py', 'js', 'gif', 'go', 'ino', 'cpp', 'c', 'php', 'xml']);
define('USERS_FILE', __DIR__ . '/users.json');
define('FILES_FILE', __DIR__ . '/files.json');

// Inisialisasi file jika belum ada
if (!file_exists(USERS_FILE)) {
    file_put_contents(USERS_FILE, json_encode([
        'admin' => [
            'password' => password_hash('admin', PASSWORD_DEFAULT),
            'is_admin' => true,
            'created_at' => date('Y-m-d H:i:s'),
            'created_by' => 'system',
            'storage_limit' => 5368709120 // 5GB
        ]
    ], JSON_PRETTY_PRINT));
}

if (!file_exists(FILES_FILE)) {
    file_put_contents(FILES_FILE, json_encode([], JSON_PRETTY_PRINT));
}

// ===================== FUNGSI HELPER =====================
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
        // Images
        'jpg' => 'far fa-image text-warning', 'jpeg' => 'far fa-image text-warning', 
        'png' => 'far fa-image text-warning', 'gif' => 'far fa-image text-warning',
        'webp' => 'far fa-image text-warning', 'bmp' => 'far fa-image text-warning',
        'svg' => 'far fa-image text-warning',
        
        // Videos
        'mp4' => 'far fa-file-video text-danger', 'avi' => 'far fa-file-video text-danger',
        'mov' => 'far fa-file-video text-danger', 'mkv' => 'far fa-file-video text-danger',
        'flv' => 'far fa-file-video text-danger', 'wmv' => 'far fa-file-video text-danger',
        
        // Audio
        'mp3' => 'far fa-file-audio text-success', 'wav' => 'far fa-file-audio text-success',
        'flac' => 'far fa-file-audio text-success', 'ogg' => 'far fa-file-audio text-success',
        
        // Documents
        'pdf' => 'far fa-file-pdf text-danger', 
        'doc' => 'far fa-file-word text-primary', 'docx' => 'far fa-file-word text-primary',
        'txt' => 'far fa-file-lines text-secondary',
        'xls' => 'far fa-file-excel text-success', 'xlsx' => 'far fa-file-excel text-success',
        'ppt' => 'far fa-file-powerpoint text-danger', 'pptx' => 'far fa-file-powerpoint text-danger',
        'csv' => 'far fa-file-csv text-info',
        
        // Archives
        'zip' => 'far fa-file-zipper text-warning', 'rar' => 'far fa-file-zipper text-warning',
        '7z' => 'far fa-file-zipper text-warning', 'tar' => 'far fa-file-zipper text-warning',
        'gz' => 'far fa-file-zipper text-warning',
        
        // Code
        'php' => 'far fa-file-code text-info', 'js' => 'far fa-file-code text-warning',
        'html' => 'far fa-file-code text-danger', 'css' => 'far fa-file-code text-primary',
        'json' => 'far fa-file-code text-warning', 'xml' => 'far fa-file-code text-info',
    ];
    return $icon_map[$ext] ?? 'far fa-file text-secondary';
}

function isImageFile($filename) {
    $image_ext = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($ext, $image_ext);
}

function isVideoFile($filename) {
    $video_ext = ['mp4', 'avi', 'mov', 'mkv', 'flv', 'wmv', 'webm'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($ext, $video_ext);
}

function isAudioFile($filename) {
    $audio_ext = ['mp3', 'wav', 'flac', 'ogg', 'm4a'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($ext, $audio_ext);
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
        
        if ($file['size'] > MAX_FILE_SIZE) {
            return ['success' => false, 'error' => 'File too large (Max 2GB)'];
        }
        
        $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
        if (!in_array($file_ext, ALLOWED_EXTENSIONS)) {
            return ['success' => false, 'error' => 'File type not allowed'];
        }
        
        $caption = $file_name . ':' . $username . '::cloudnas';
        $result = $this->sendDocument($file_tmp, $caption);
        
        if ($result['ok']) {
            $file_id = isset($result['result']['document']['file_id']) ? $result['result']['document']['file_id'] : null;
            $this->saveFileMetadata(
                $result['result']['message_id'],
                $file_name,
                $username,
                $file['size'],
                $file_ext,
                $file_id
            );
            
            return [
                'success' => true,
                'message_id' => $result['result']['message_id'],
                'file_name' => $file_name,
                'file_size' => $file['size'],
                'file_type' => $file_ext
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
            'last_modified' => date('Y-m-d H:i:s'),
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
        
        usort($user_files, function($a, $b) {
            return strtotime($b['uploaded_at']) - strtotime($a['uploaded_at']);
        });
        
        return $user_files;
    }
    
    public function searchFiles($username, $query) {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        $results = [];
        
        foreach ($files as $file) {
            if ($file['username'] === $username && stripos($file['name'], $query) !== false) {
                $results[] = $file;
            }
        }
        
        return $results;
    }
    
    public function getAllFiles() {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        return array_values($files);
    }
    
    public function deleteFile($message_id, $username) {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        
        if (isset($files[$message_id]) && ($files[$message_id]['username'] === $username || isAdmin())) {
            $delete_result = $this->deleteMessage($message_id);
            
            if ($delete_result['ok']) {
                unset($files[$message_id]);
                file_put_contents(FILES_FILE, json_encode($files, JSON_PRETTY_PRINT));
                return ['success' => true];
            }
            return ['success' => false, 'error' => 'Failed to delete from Telegram'];
        }
        
        return ['success' => false, 'error' => 'File not found or access denied'];
    }
    
    public function getUserStorageStats($username) {
        $files = json_decode(file_get_contents(FILES_FILE), true);
        $total_size = 0;
        $file_count = 0;
        $by_type = [];
        
        foreach ($files as $file) {
            if ($file['username'] === $username) {
                $total_size += $file['size'];
                $file_count++;
                
                $type = $file['extension'];
                if (!isset($by_type[$type])) {
                    $by_type[$type] = 0;
                }
                $by_type[$type] += $file['size'];
            }
        }
        
        return [
            'total_size' => $total_size,
            'file_count' => $file_count,
            'by_type' => $by_type
        ];
    }
}

// ===================== ROUTING & API HANDLING =====================
$telegram = new TelegramNAS();
$action = $_GET['action'] ?? '';

// Handle API requests
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
            $storage_limit = $_POST['storage_limit'] ?? 1073741824; // Default 1GB
            
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
                    'created_by' => $_SESSION['user'],
                    'storage_limit' => $storage_limit
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
            
        case 'search':
            if (!isLoggedIn()) {
                echo json_encode(['success' => false, 'error' => 'Not authenticated']);
                exit;
            }
            $query = sanitize($_POST['query']);
            $results = $telegram->searchFiles($_SESSION['user'], $query);
            echo json_encode(['success' => true, 'results' => $results]);
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
                header('Location: ' . $file_url);
                exit;
            }
        }
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $files[$message_id]['name'] . '"');
        echo "File download via Telegram Bot\n";
        exit;
    }
    header('HTTP/1.0 404 Not Found');
    exit('File not found');
}

// Handle preview (direct file access for images/videos)
if ($action === 'preview' && isset($_GET['id'])) {
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
                // For direct preview, we redirect to Telegram file URL
                header('Location: ' . $file_url);
                exit;
            }
        }
    }
    header('HTTP/1.0 404 Not Found');
    exit('File not found');
}

// Handle page routing
switch ($action) {
    case 'logout':
        session_destroy();
        redirect('index.php');
        break;
    case 'admin':
        if (!isAdmin()) redirect('index.php');
        break;
    default:
        if (isLoggedIn() && empty($action)) {
            $action = 'dashboard';
        }
        break;
}

// ===================== PAGE RENDERING =====================
if (empty($action) || $action === 'login') {
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
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #1a1f35 0%, #0f1525 100%);
                height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #e2e8f0;
            }
            .login-container {
                background: rgba(15, 23, 42, 0.95);
                border-radius: 16px;
                padding: 40px;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
            }
            .logo {
                text-align: center;
                margin-bottom: 30px;
            }
            .logo i {
                font-size: 48px;
                color: #3b82f6;
                margin-bottom: 10px;
            }
            .logo h1 {
                font-size: 28px;
                font-weight: 700;
                background: linear-gradient(90deg, #3b82f6, #8b5cf6);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: #94a3b8;
            }
            select, input {
                width: 100%;
                padding: 12px 16px;
                background: rgba(30, 41, 59, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                color: #e2e8f0;
                font-size: 14px;
                transition: all 0.3s;
            }
            select:focus, input:focus {
                outline: none;
                border-color: #3b82f6;
                box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
            }
            .btn-login {
                width: 100%;
                padding: 14px;
                background: linear-gradient(90deg, #3b82f6, #2563eb);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
            }
            .btn-login:hover {
                background: linear-gradient(90deg, #2563eb, #1d4ed8);
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);
            }
            .alert {
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
                font-size: 14px;
            }
            .alert-danger {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #fca5a5;
            }
            .footer {
                text-align: center;
                margin-top: 20px;
                color: #64748b;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">
                <i class="fas fa-cloud"></i>
                <h1>CloudNAS</h1>
            </div>
            <div id="login-message"></div>
            <form id="login-form">
                <div class="form-group">
                    <label for="username">Username</label>
                    <select name="username" id="username" required>
                        <?php foreach ($user_list as $user): ?>
                        <option value="<?= $user ?>"><?= $user ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" name="password" id="password" required>
                </div>
                <button type="submit" class="btn-login">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </form>
            <div class="footer">
                <p>Powered by Telegram Bot API</p>
            </div>
        </div>
        <script>
        document.getElementById('login-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('api_action', 'login');
            
            const btn = this.querySelector('button');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
            btn.disabled = true;
            
            try {
                const response = await fetch('index.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                if (result.success) {
                    window.location.href = 'index.php?action=dashboard';
                } else {
                    document.getElementById('login-message').innerHTML = 
                        '<div class="alert alert-danger">' + (result.error || 'Login failed') + '</div>';
                }
            } catch (error) {
                document.getElementById('login-message').innerHTML = 
                    '<div class="alert alert-danger">Network error: ' + error + '</div>';
            } finally {
                btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Login';
                btn.disabled = false;
            }
        });
        </script>
    </body>
    </html>
    <?php
} elseif ($action === 'dashboard') {
    if (!isLoggedIn()) redirect('index.php');
    
    $username = $_SESSION['user'];
    $is_admin = isAdmin();
    $files = $telegram->getUserFiles($username);
    $stats = $telegram->getUserStorageStats($username);
    
    // Get user storage limit
    $users = json_decode(file_get_contents(USERS_FILE), true);
    $storage_limit = $users[$username]['storage_limit'] ?? 5368709120; // Default 5GB
    $usage_percent = min(($stats['total_size'] / $storage_limit) * 100, 100);
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CloudNAS - Dashboard</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary: #3b82f6;
                --primary-dark: #2563eb;
                --secondary: #1e293b;
                --dark: #0f172a;
                --light: #e2e8f0;
                --gray: #64748b;
                --success: #10b981;
                --danger: #ef4444;
                --warning: #f59e0b;
                --info: #06b6d4;
            }
            
            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background: var(--dark);
                color: var(--light);
                min-height: 100vh;
                overflow-x: hidden;
            }
            
            /* Sidebar */
            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: 280px;
                height: 100vh;
                background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
                border-right: 1px solid rgba(255, 255, 255, 0.1);
                padding: 24px;
                overflow-y: auto;
                z-index: 1000;
            }
            
            .logo {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 32px;
            }
            
            .logo i {
                font-size: 28px;
                color: var(--primary);
            }
            
            .logo h1 {
                font-size: 22px;
                font-weight: 700;
                background: linear-gradient(90deg, var(--primary), #8b5cf6);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .nav-section {
                margin-bottom: 32px;
            }
            
            .nav-title {
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 1px;
                color: var(--gray);
                margin-bottom: 12px;
                font-weight: 600;
            }
            
            .nav-links {
                list-style: none;
            }
            
            .nav-links li {
                margin-bottom: 8px;
            }
            
            .nav-links a {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 10px 16px;
                color: var(--light);
                text-decoration: none;
                border-radius: 8px;
                transition: all 0.3s;
                font-weight: 500;
            }
            
            .nav-links a:hover, .nav-links a.active {
                background: rgba(59, 130, 246, 0.1);
                color: var(--primary);
            }
            
            .nav-links a i {
                width: 20px;
                text-align: center;
            }
            
            .storage-widget {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                padding: 20px;
                margin-top: auto;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .storage-title {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
            }
            
            .storage-title h3 {
                font-size: 14px;
                color: var(--gray);
            }
            
            .storage-title span {
                font-size: 14px;
                color: var(--light);
            }
            
            .progress-bar {
                height: 8px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
                overflow: hidden;
                margin-bottom: 8px;
            }
            
            .progress-fill {
                height: 100%;
                background: linear-gradient(90deg, var(--primary), var(--info));
                border-radius: 4px;
                transition: width 0.5s ease;
            }
            
            /* Main Content */
            .main-content {
                margin-left: 280px;
                padding: 24px;
                min-height: 100vh;
            }
            
            .top-bar {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 32px;
                background: rgba(255, 255, 255, 0.05);
                padding: 16px 24px;
                border-radius: 12px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .page-title h2 {
                font-size: 24px;
                font-weight: 700;
            }
            
            .page-title p {
                color: var(--gray);
                font-size: 14px;
            }
            
            .search-box {
                position: relative;
                width: 300px;
            }
            
            .search-box input {
                width: 100%;
                padding: 12px 16px 12px 48px;
                background: rgba(30, 41, 59, 0.8);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                color: var(--light);
                font-size: 14px;
            }
            
            .search-box i {
                position: absolute;
                left: 16px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--gray);
            }
            
            .user-actions {
                display: flex;
                align-items: center;
                gap: 16px;
            }
            
            .btn {
                padding: 10px 20px;
                border-radius: 8px;
                border: none;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                font-size: 14px;
            }
            
            .btn-primary {
                background: linear-gradient(90deg, var(--primary), var(--primary-dark));
                color: white;
            }
            
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);
            }
            
            .btn-danger {
                background: linear-gradient(90deg, var(--danger), #dc2626);
                color: white;
            }
            
            .btn-logout {
                background: rgba(239, 68, 68, 0.1);
                color: var(--danger);
                border: 1px solid rgba(239, 68, 68, 0.3);
            }
            
            .btn-logout:hover {
                background: rgba(239, 68, 68, 0.2);
            }
            
            /* Content Grid */
            .content-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 24px;
                margin-bottom: 32px;
            }
            
            .card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.8), rgba(15, 23, 42, 0.8));
                border-radius: 16px;
                padding: 24px;
                border: 1px solid rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                transition: transform 0.3s, box-shadow 0.3s;
            }
            
            .card:hover {
                transform: translateY(-4px);
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
            }
            
            .card-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 20px;
            }
            
            .card-header h3 {
                font-size: 18px;
                font-weight: 600;
            }
            
            .card-header i {
                font-size: 24px;
                color: var(--primary);
            }
            
            .stat-number {
                font-size: 32px;
                font-weight: 700;
                margin-bottom: 8px;
            }
            
            .stat-label {
                color: var(--gray);
                font-size: 14px;
            }
            
            /* Upload Area */
            .upload-area {
                grid-column: 1 / -1;
                text-align: center;
                padding: 60px 40px;
                border: 3px dashed rgba(59, 130, 246, 0.3);
                border-radius: 20px;
                background: rgba(59, 130, 246, 0.05);
                cursor: pointer;
                transition: all 0.3s;
            }
            
            .upload-area:hover {
                background: rgba(59, 130, 246, 0.1);
                border-color: var(--primary);
            }
            
            .upload-icon {
                font-size: 64px;
                color: var(--primary);
                margin-bottom: 20px;
            }
            
            .upload-text h3 {
                font-size: 20px;
                margin-bottom: 8px;
            }
            
            .upload-text p {
                color: var(--gray);
                margin-bottom: 20px;
            }
            
            /* Files Table */
            .files-table-container {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.8), rgba(15, 23, 42, 0.8));
                border-radius: 16px;
                overflow: hidden;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .table-header {
                padding: 24px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .table-header h3 {
                font-size: 18px;
                font-weight: 600;
            }
            
            .table-wrapper {
                overflow-x: auto;
            }
            
            table {
                width: 100%;
                border-collapse: collapse;
            }
            
            thead {
                background: rgba(255, 255, 255, 0.05);
            }
            
            th {
                padding: 16px;
                text-align: left;
                font-weight: 600;
                color: var(--gray);
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            tbody tr {
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                transition: background 0.3s;
            }
            
            tbody tr:hover {
                background: rgba(59, 130, 246, 0.05);
            }
            
            td {
                padding: 16px;
                vertical-align: middle;
            }
            
            .file-info {
                display: flex;
                align-items: center;
                gap: 12px;
            }
            
            .file-icon {
                font-size: 24px;
                width: 40px;
                height: 40px;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
            }
            
            .file-name {
                font-weight: 500;
            }
            
            .file-meta {
                color: var(--gray);
                font-size: 12px;
                margin-top: 4px;
            }
            
            .file-size, .file-date {
                color: var(--gray);
                font-size: 14px;
            }
            
            .file-actions {
                display: flex;
                gap: 8px;
            }
            
            .btn-action {
                padding: 8px 12px;
                border-radius: 6px;
                border: none;
                background: rgba(255, 255, 255, 0.05);
                color: var(--light);
                cursor: pointer;
                transition: all 0.3s;
                font-size: 12px;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }
            
            .btn-action:hover {
                background: rgba(59, 130, 246, 0.1);
                color: var(--primary);
            }
            
            .btn-preview {
                background: rgba(16, 185, 129, 0.1);
                color: var(--success);
            }
            
            .btn-preview:hover {
                background: rgba(16, 185, 129, 0.2);
            }
            
            .btn-delete {
                background: rgba(239, 68, 68, 0.1);
                color: var(--danger);
            }
            
            .btn-delete:hover {
                background: rgba(239, 68, 68, 0.2);
            }
            
            /* No Files */
            .no-files {
                text-align: center;
                padding: 60px 24px;
                color: var(--gray);
            }
            
            .no-files i {
                font-size: 64px;
                margin-bottom: 20px;
                opacity: 0.5;
            }
            
            /* Preview Modal */
            .preview-modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                z-index: 2000;
                backdrop-filter: blur(10px);
            }
            
            .preview-content {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                max-width: 90%;
                max-height: 90%;
                background: var(--dark);
                border-radius: 16px;
                overflow: hidden;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .preview-header {
                padding: 20px;
                background: rgba(255, 255, 255, 0.05);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .preview-body {
                padding: 20px;
                max-height: 70vh;
                overflow-y: auto;
            }
            
            .preview-image {
                max-width: 100%;
                max-height: 60vh;
                display: block;
                margin: 0 auto;
                border-radius: 8px;
            }
            
            .preview-video {
                width: 100%;
                max-height: 60vh;
                border-radius: 8px;
            }
            
            .btn-close {
                background: none;
                border: none;
                color: var(--light);
                font-size: 24px;
                cursor: pointer;
                padding: 8px;
                border-radius: 8px;
            }
            
            .btn-close:hover {
                background: rgba(255, 255, 255, 0.1);
            }
            
            /* Responsive */
            @media (max-width: 1024px) {
                .sidebar {
                    width: 240px;
                }
                .main-content {
                    margin-left: 240px;
                }
            }
            
            @media (max-width: 768px) {
                .sidebar {
                    transform: translateX(-100%);
                    transition: transform 0.3s;
                }
                .sidebar.active {
                    transform: translateX(0);
                }
                .main-content {
                    margin-left: 0;
                }
                .content-grid {
                    grid-template-columns: 1fr;
                }
                .top-bar {
                    flex-direction: column;
                    gap: 16px;
                }
                .search-box {
                    width: 100%;
                }
            }
            
            /* Loading */
            .loading {
                text-align: center;
                padding: 40px;
                color: var(--gray);
            }
            
            .loading i {
                font-size: 32px;
                margin-bottom: 16px;
                animation: spin 1s linear infinite;
            }
            
            @keyframes spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <i class="fas fa-cloud"></i>
                <h1>CloudNAS</h1>
            </div>
            
            <div class="nav-section">
                <div class="nav-title">Storage</div>
                <ul class="nav-links">
                    <li><a href="#" class="active"><i class="fas fa-cloud"></i> My Cloud</a></li>
                    <li><a href="#"><i class="fas fa-folder"></i> My Documents</a></li>
                    <li><a href="#"><i class="fas fa-images"></i> My Images</a></li>
                    <li><a href="#"><i class="fas fa-video"></i> My Videos</a></li>
                    <li><a href="#"><i class="fas fa-music"></i> My Music</a></li>
                </ul>
            </div>
            
            <div class="nav-section">
                <div class="nav-title">Tasks</div>
                <ul class="nav-links">
                    <li><a href="#"><i class="fas fa-sync"></i> SUS Tasks</a></li>
                    <li><a href="#"><i class="fas fa-upload"></i> Upload Queue</a></li>
                    <li><a href="#"><i class="fas fa-download"></i> Downloads</a></li>
                    <li><a href="#"><i class="fas fa-trash"></i> Recycle Bin</a></li>
                </ul>
            </div>
            
            <?php if ($is_admin): ?>
            <div class="nav-section">
                <div class="nav-title">Administration</div>
                <ul class="nav-links">
                    <li><a href="index.php?action=admin"><i class="fas fa-users-cog"></i> User Management</a></li>
                    <li><a href="#"><i class="fas fa-chart-bar"></i> Statistics</a></li>
                    <li><a href="#"><i class="fas fa-cogs"></i> System Settings</a></li>
                </ul>
            </div>
            <?php endif; ?>
            
            <div class="storage-widget">
                <div class="storage-title">
                    <h3>Storage Usage</h3>
                    <span><?= formatSize($stats['total_size']) ?> / <?= formatSize($storage_limit) ?></span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: <?= $usage_percent ?>%"></div>
                </div>
                <div style="font-size: 12px; color: var(--gray); margin-top: 8px;">
                    <?= $stats['file_count'] ?> files • <?= round($usage_percent, 2) ?>% used
                </div>
                
                <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid rgba(255, 255, 255, 0.1);">
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <div style="width: 36px; height: 36px; border-radius: 50%; background: rgba(59, 130, 246, 0.1); display: flex; align-items: center; justify-content: center;">
                                <i class="fas fa-user" style="color: var(--primary);"></i>
                            </div>
                            <div>
                                <div style="font-weight: 600; font-size: 14px;"><?= $username ?></div>
                                <div style="font-size: 12px; color: var(--success);">
                                    <i class="fas fa-circle" style="font-size: 8px;"></i> Online
                                </div>
                            </div>
                        </div>
                        <button onclick="logout()" class="btn-action">
                            <i class="fas fa-sign-out-alt"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            <!-- Top Bar -->
            <div class="top-bar">
                <div class="page-title">
                    <h2>My Cloud Storage</h2>
                    <p>Telegram Bot Powered Cloud Storage</p>
                </div>
                
                <div class="search-box">
                    <i class="fas fa-search"></i>
                    <input type="text" id="searchInput" placeholder="Search files...">
                </div>
                
                <div class="user-actions">
                    <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                        <i class="fas fa-upload"></i> Upload Files
                    </button>
                    <button class="btn btn-logout" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </button>
                </div>
            </div>
            
            <!-- Stats Grid -->
            <div class="content-grid">
                <div class="card">
                    <div class="card-header">
                        <h3>Total Files</h3>
                        <i class="fas fa-file"></i>
                    </div>
                    <div class="stat-number"><?= $stats['file_count'] ?></div>
                    <div class="stat-label">Files stored</div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3>Storage Used</h3>
                        <i class="fas fa-database"></i>
                    </div>
                    <div class="stat-number"><?= formatSize($stats['total_size']) ?></div>
                    <div class="stat-label">of <?= formatSize($storage_limit) ?></div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3>Images</h3>
                        <i class="fas fa-image"></i>
                    </div>
                    <div class="stat-number">
                        <?php 
                        $image_count = 0;
                        $image_ext = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'];
                        foreach ($files as $file) {
                            if (in_array(strtolower($file['extension']), $image_ext)) $image_count++;
                        }
                        echo $image_count;
                        ?>
                    </div>
                    <div class="stat-label">Image files</div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3>Videos</h3>
                        <i class="fas fa-video"></i>
                    </div>
                    <div class="stat-number">
                        <?php 
                        $video_count = 0;
                        $video_ext = ['mp4', 'avi', 'mov', 'mkv', 'flv', 'wmv', 'webm'];
                        foreach ($files as $file) {
                            if (in_array(strtolower($file['extension']), $video_ext)) $video_count++;
                        }
                        echo $video_count;
                        ?>
                    </div>
                    <div class="stat-label">Video files</div>
                </div>
            </div>
            
            <!-- Upload Area -->
            <div class="card upload-area" onclick="document.getElementById('fileInput').click()">
                <div class="upload-icon">
                    <i class="fas fa-cloud-upload-alt"></i>
                </div>
                <div class="upload-text">
                    <h3>Drag & Drop Files Here</h3>
                    <p>or click to browse files (Max 2GB per file)</p>
                </div>
                <button class="btn btn-primary">
                    <i class="fas fa-folder-open"></i> Browse Files
                </button>
                <input type="file" id="fileInput" multiple style="display: none;" onchange="uploadFiles()">
            </div>
            
            <!-- Files Table -->
            <div class="files-table-container">
                <div class="table-header">
                    <h3><i class="fas fa-file-alt"></i> All Files (<?= count($files) ?>)</h3>
                </div>
                <div id="uploadStatus" class="loading" style="display: none;">
                    <i class="fas fa-spinner fa-spin"></i>
                    <p>Uploading files...</p>
                </div>
                <div class="table-wrapper">
                    <?php if (empty($files)): ?>
                        <div class="no-files">
                            <i class="fas fa-box-open"></i>
                            <h3>No files found</h3>
                            <p>Upload your first file to get started</p>
                        </div>
                    <?php else: ?>
                        <table>
                            <thead>
                                <tr>
                                    <th style="width: 40px;">#</th>
                                    <th>Name</th>
                                    <th style="width: 120px;">Size</th>
                                    <th style="width: 180px;">Date</th>
                                    <th style="width: 200px;">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="filesTableBody">
                                <?php $counter = 1; ?>
                                <?php foreach ($files as $file): ?>
                                <tr data-file-id="<?= $file['id'] ?>" data-file-name="<?= htmlspecialchars($file['name']) ?>" data-file-type="<?= $file['extension'] ?>">
                                    <td><?= $counter++ ?></td>
                                    <td>
                                        <div class="file-info">
                                            <div class="file-icon">
                                                <i class="<?= getFileIcon($file['name']) ?>"></i>
                                            </div>
                                            <div>
                                                <div class="file-name"><?= htmlspecialchars($file['name']) ?></div>
                                                <div class="file-meta">ID: <?= $file['id'] ?> • <?= strtoupper($file['extension']) ?></div>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="file-size"><?= formatSize($file['size']) ?></td>
                                    <td class="file-date"><?= date('M d, Y H:i', strtotime($file['uploaded_at'])) ?></td>
                                    <td>
                                        <div class="file-actions">
                                            <?php if (isImageFile($file['name'])): ?>
                                            <button class="btn-action btn-preview" onclick="previewFile(<?= $file['id'] ?>, '<?= $file['extension'] ?>', '<?= htmlspecialchars($file['name']) ?>')">
                                                <i class="fas fa-eye"></i> Preview
                                            </button>
                                            <?php elseif (isVideoFile($file['name'])): ?>
                                            <button class="btn-action btn-preview" onclick="previewFile(<?= $file['id'] ?>, '<?= $file['extension'] ?>', '<?= htmlspecialchars($file['name']) ?>')">
                                                <i class="fas fa-play"></i> Play
                                            </button>
                                            <?php endif; ?>
                                            <button class="btn-action" onclick="downloadFile(<?= $file['id'] ?>, '<?= htmlspecialchars($file['name']) ?>')">
                                                <i class="fas fa-download"></i> Download
                                            </button>
                                            <button class="btn-action btn-delete" onclick="deleteFile(<?= $file['id'] ?>)">
                                                <i class="fas fa-trash"></i> Delete
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Preview Modal -->
        <div class="preview-modal" id="previewModal">
            <div class="preview-content">
                <div class="preview-header">
                    <h3 id="previewTitle">Preview</h3>
                    <button class="btn-close" onclick="closePreview()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="preview-body" id="previewBody">
                    <!-- Content will be loaded here -->
                </div>
            </div>
        </div>
        
        <script>
        // Format file size
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        // Upload files
        async function uploadFiles() {
            const files = document.getElementById('fileInput').files;
            if (files.length === 0) return;
            
            const status = document.getElementById('uploadStatus');
            status.style.display = 'block';
            status.scrollIntoView({ behavior: 'smooth' });
            
            let successCount = 0;
            let errorCount = 0;
            
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
                        successCount++;
                    } else {
                        errorCount++;
                        console.error(`Upload failed for ${file.name}:`, result.error);
                    }
                } catch (error) {
                    errorCount++;
                    console.error(`Network error for ${file.name}:`, error);
                }
            }
            
            if (successCount > 0) {
                status.innerHTML = `<i class="fas fa-check-circle" style="color: #10b981;"></i>
                                   <p>Successfully uploaded ${successCount} file(s)</p>`;
                setTimeout(() => location.reload(), 1500);
            } else {
                status.innerHTML = `<i class="fas fa-times-circle" style="color: #ef4444;"></i>
                                   <p>Upload failed for all ${errorCount} file(s)</p>`;
                setTimeout(() => status.style.display = 'none', 3000);
            }
        }
        
        // Download file
        function downloadFile(id, name) {
            window.open(`index.php?action=download&id=${id}`, '_blank');
        }
        
        // Preview file
        function previewFile(id, type, name) {
            const modal = document.getElementById('previewModal');
            const title = document.getElementById('previewTitle');
            const body = document.getElementById('previewBody');
            
            title.textContent = name;
            
            const imageTypes = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'];
            const videoTypes = ['mp4', 'avi', 'mov', 'mkv', 'flv', 'wmv', 'webm'];
            
            if (imageTypes.includes(type.toLowerCase())) {
                body.innerHTML = `
                    <div style="text-align: center;">
                        <img src="index.php?action=preview&id=${id}" 
                             alt="${name}" 
                             class="preview-image"
                             onerror="this.onerror=null; this.src='#'; this.alt='Preview not available'">
                        <div style="margin-top: 20px;">
                            <button class="btn-action" onclick="downloadFile(${id}, '${name.replace(/'/g, "\\'")}')">
                                <i class="fas fa-download"></i> Download Image
                            </button>
                        </div>
                    </div>
                `;
            } else if (videoTypes.includes(type.toLowerCase())) {
                body.innerHTML = `
                    <div style="text-align: center;">
                        <video controls class="preview-video">
                            <source src="index.php?action=preview&id=${id}" type="video/${type === 'mp4' ? 'mp4' : type === 'webm' ? 'webm' : 'ogg'}">
                            Your browser does not support the video tag.
                        </video>
                        <div style="margin-top: 20px;">
                            <button class="btn-action" onclick="downloadFile(${id}, '${name.replace(/'/g, "\\'")}')">
                                <i class="fas fa-download"></i> Download Video
                            </button>
                        </div>
                    </div>
                `;
            } else {
                body.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-file" style="font-size: 64px; color: #64748b; margin-bottom: 20px;"></i>
                        <h3>Preview not available</h3>
                        <p style="color: #94a3b8; margin-bottom: 20px;">Preview is only available for image and video files.</p>
                        <button class="btn-action" onclick="downloadFile(${id}, '${name.replace(/'/g, "\\'")}')">
                            <i class="fas fa-download"></i> Download File
                        </button>
                    </div>
                `;
            }
            
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        }
        
        // Close preview
        function closePreview() {
            const modal = document.getElementById('previewModal');
            modal.style.display = 'none';
            document.body.style.overflow = 'auto';
            
            // Stop video playback
            const video = modal.querySelector('video');
            if (video) {
                video.pause();
                video.currentTime = 0;
            }
        }
        
        // Delete file
        async function deleteFile(id) {
            if (!confirm('Are you sure you want to delete this file? This action cannot be undone.')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('api_action', 'delete_file');
            formData.append('message_id', id);
            
            try {
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
            } catch (error) {
                alert('Network error: ' + error);
            }
        }
        
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('input', function() {
            const query = this.value.toLowerCase();
            const rows = document.querySelectorAll('#filesTableBody tr');
            
            rows.forEach(row => {
                const fileName = row.querySelector('.file-name').textContent.toLowerCase();
                const fileId = row.getAttribute('data-file-id');
                const fileType = row.getAttribute('data-file-type');
                
                const matches = fileName.includes(query) || 
                               fileId.toString().includes(query) ||
                               fileType.toLowerCase().includes(query);
                
                row.style.display = matches ? '' : 'none';
            });
        });
        
        // Logout
        async function logout() {
            if (!confirm('Are you sure you want to logout?')) return;
            
            const formData = new FormData();
            formData.append('api_action', 'logout');
            
            await fetch('index.php', {
                method: 'POST',
                body: formData
            });
            
            window.location.href = 'index.php';
        }
        
        // Drag and drop
        const uploadArea = document.querySelector('.upload-area');
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = '#3b82f6';
            uploadArea.style.background = 'rgba(59, 130, 246, 0.1)';
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.style.borderColor = 'rgba(59, 130, 246, 0.3)';
            uploadArea.style.background = 'rgba(59, 130, 246, 0.05)';
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'rgba(59, 130, 246, 0.3)';
            uploadArea.style.background = 'rgba(59, 130, 246, 0.05)';
            
            const files = e.dataTransfer.files;
            document.getElementById('fileInput').files = files;
            uploadFiles();
        });
        
        // Close preview on ESC key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closePreview();
            }
        });
        
        // Close preview when clicking outside
        document.getElementById('previewModal').addEventListener('click', (e) => {
            if (e.target === document.getElementById('previewModal')) {
                closePreview();
            }
        });
        </script>
    </body>
    </html>
    <?php
} elseif ($action === 'admin') {
    if (!isAdmin()) redirect('index.php');
    
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
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                color: #e2e8f0;
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            .header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
                background: rgba(255, 255, 255, 0.05);
                padding: 20px;
                border-radius: 12px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .header h1 {
                font-size: 24px;
                font-weight: 700;
                background: linear-gradient(90deg, #3b82f6, #8b5cf6);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            .btn {
                padding: 10px 20px;
                border-radius: 8px;
                border: none;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }
            .btn-primary {
                background: linear-gradient(90deg, #3b82f6, #2563eb);
                color: white;
            }
            .btn-secondary {
                background: rgba(255, 255, 255, 0.1);
                color: #e2e8f0;
            }
            .btn-danger {
                background: linear-gradient(90deg, #ef4444, #dc2626);
                color: white;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .stat-card {
                background: linear-gradient(145deg, rgba(30, 41, 59, 0.8), rgba(15, 23, 42, 0.8));
                border-radius: 12px;
                padding: 20px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .stat-card h3 {
                font-size: 14px;
                color: #94a3b8;
                margin-bottom: 10px;
            }
            .stat-card .number {
                font-size: 32px;
                font-weight: 700;
            }
            .tabs {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                background: rgba(255, 255, 255, 0.05);
                padding: 10px;
                border-radius: 8px;
            }
            .tab {
                padding: 10px 20px;
                border-radius: 6px;
                background: none;
                border: none;
                color: #94a3b8;
                cursor: pointer;
                transition: all 0.3s;
            }
            .tab.active {
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
            }
            .tab-content {
                display: none;
            }
            .tab-content.active {
                display: block;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                overflow: hidden;
            }
            th, td {
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }
            th {
                background: rgba(255, 255, 255, 0.1);
                font-weight: 600;
                color: #94a3b8;
            }
            .badge {
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 600;
            }
            .badge-success {
                background: rgba(16, 185, 129, 0.2);
                color: #10b981;
            }
            .badge-danger {
                background: rgba(239, 68, 68, 0.2);
                color: #ef4444;
            }
            .badge-primary {
                background: rgba(59, 130, 246, 0.2);
                color: #3b82f6;
            }
            .add-user-form {
                background: rgba(255, 255, 255, 0.05);
                padding: 20px;
                border-radius: 12px;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .form-group label {
                display: block;
                margin-bottom: 5px;
                color: #94a3b8;
            }
            .form-group input {
                width: 100%;
                padding: 10px;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 6px;
                color: #e2e8f0;
            }
            .alert {
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 20px;
            }
            .alert-success {
                background: rgba(16, 185, 129, 0.1);
                border: 1px solid rgba(16, 185, 129, 0.3);
                color: #10b981;
            }
            .alert-danger {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #ef4444;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1><i class="fas fa-crown"></i> Admin Panel</h1>
                <div>
                    <button class="btn btn-secondary" onclick="window.location.href='index.php?action=dashboard'">
                        <i class="fas fa-arrow-left"></i> Back to Dashboard
                    </button>
                    <button class="btn btn-danger" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </button>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Users</h3>
                    <div class="number"><?= $total_users ?></div>
                </div>
                <div class="stat-card">
                    <h3>Total Files</h3>
                    <div class="number"><?= $total_files ?></div>
                </div>
                <div class="stat-card">
                    <h3>Total Storage Used</h3>
                    <div class="number"><?= formatSize($total_storage) ?></div>
                </div>
                <div class="stat-card">
                    <h3>Storage Backend</h3>
                    <div class="number">Telegram</div>
                </div>
            </div>
            
            <div class="tabs">
                <button class="tab active" onclick="showTab('users')">Users</button>
                <button class="tab" onclick="showTab('files')">All Files</button>
                <button class="tab" onclick="showTab('addUser')">Add User</button>
            </div>
            
            <div id="usersTab" class="tab-content active">
                <div class="add-user-form">
                    <h3><i class="fas fa-users"></i> User Management</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Role</th>
                                <th>Created</th>
                                <th>Created By</th>
                                <th>Storage Limit</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($users as $username => $user): ?>
                            <tr>
                                <td>
                                    <?= $username ?>
                                    <?php if ($username === $_SESSION['user']): ?>
                                        <span class="badge badge-primary">You</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($user['is_admin']): ?>
                                        <span class="badge badge-danger">Admin</span>
                                    <?php else: ?>
                                        <span class="badge badge-success">User</span>
                                    <?php endif; ?>
                                </td>
                                <td><?= $user['created_at'] ?></td>
                                <td><?= $user['created_by'] ?></td>
                                <td><?= formatSize($user['storage_limit'] ?? 5368709120) ?></td>
                                <td>
                                    <?php if ($username !== 'admin' && $username !== $_SESSION['user']): ?>
                                    <button class="btn btn-danger btn-sm" onclick="deleteUser('<?= $username ?>')">
                                        <i class="fas fa-trash"></i> Delete
                                    </button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="filesTab" class="tab-content">
                <div class="add-user-form">
                    <h3><i class="fas fa-file"></i> All System Files (<?= $total_files ?>)</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>File Name</th>
                                <th>Owner</th>
                                <th>Size</th>
                                <th>Type</th>
                                <th>Uploaded</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($files as $file): ?>
                            <tr>
                                <td>
                                    <i class="<?= getFileIcon($file['name']) ?>"></i>
                                    <?= htmlspecialchars($file['name']) ?>
                                </td>
                                <td><span class="badge badge-primary"><?= $file['username'] ?></span></td>
                                <td><?= formatSize($file['size']) ?></td>
                                <td><?= strtoupper($file['extension']) ?></td>
                                <td><?= $file['uploaded_at'] ?></td>
                                <td>
                                    <button class="btn btn-secondary btn-sm" onclick="window.open('index.php?action=download&id=<?= $file['id'] ?>', '_blank')">
                                        <i class="fas fa-download"></i>
                                    </button>
                                    <button class="btn btn-danger btn-sm" onclick="adminDeleteFile(<?= $file['id'] ?>, '<?= addslashes($file['name']) ?>')">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="addUserTab" class="tab-content">
                <div class="add-user-form">
                    <h3><i class="fas fa-user-plus"></i> Add New User</h3>
                    <div id="addUserMessage"></div>
                    <form id="addUserForm">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" name="username" required>
                        </div>
                        <div class="form-group">
                            <label>Password</label>
                            <input type="password" name="password" required>
                        </div>
                        <div class="form-group">
                            <label>Storage Limit (in GB)</label>
                            <input type="number" name="storage_limit" value="5" min="1" max="100">
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-user-plus"></i> Add User
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + 'Tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        // Add user
        document.getElementById('addUserForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('api_action', 'add_user');
            
            const btn = this.querySelector('button');
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Adding...';
            btn.disabled = true;
            
            try {
                const response = await fetch('index.php', { method: 'POST', body: formData });
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('addUserMessage').innerHTML = 
                        '<div class="alert alert-success">User added successfully!</div>';
                    this.reset();
                    setTimeout(() => location.reload(), 1500);
                } else {
                    document.getElementById('addUserMessage').innerHTML = 
                        '<div class="alert alert-danger">' + result.error + '</div>';
                }
            } catch (error) {
                document.getElementById('addUserMessage').innerHTML = 
                    '<div class="alert alert-danger">Network error: ' + error + '</div>';
            } finally {
                btn.innerHTML = '<i class="fas fa-user-plus"></i> Add User';
                btn.disabled = false;
            }
        });
        
        // Delete user
        async function deleteUser(username) {
            if (!confirm(`Delete user "${username}"? This action cannot be undone.`)) return;
            
            const formData = new FormData();
            formData.append('api_action', 'delete_user');
            formData.append('username', username);
            
            const response = await fetch('index.php', { method: 'POST', body: formData });
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
            
            const response = await fetch('index.php', { method: 'POST', body: formData });
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
            await fetch('index.php', { method: 'POST', body: formData });
            window.location.href = 'index.php';
        }
        </script>
    </body>
    </html>
    <?php
}
?>
