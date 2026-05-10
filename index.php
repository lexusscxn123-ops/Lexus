<?php
// ==============================================
// 🔐 PANEL SİSTEMİ - AÇIK TEMA + GALERİ + ID SORGULAMA
// ==============================================

session_start();
error_reporting(0);
ini_set('display_errors', 0);

// ========== SABİTLER ==========
define('DB_FILE', 'users.enc');
define('LOG_FILE', 'logs.enc');
define('DATA_FILE', 'iddxta.txt');
define('ADMIN_EMAIL', 'admin@gmail.com');
define('ADMIN_PASS', 'Lexus');
define('ADMIN_NAME', 'Messi');
define('ENCRYPT_KEY', 'xK9#mP2$vL5@nQ7&wR3!tY8^zU6*');
define('ENCRYPT_IV', 'a1b2c3d4e5f6g7h8');

// ========== ŞİFRELEME ==========
function encryptData($data) {
    $json = json_encode($data);
    $encrypted = openssl_encrypt($json, 'AES-256-CBC', ENCRYPT_KEY, 0, ENCRYPT_IV);
    return base64_encode($encrypted);
}

function decryptData($file) {
    if (!file_exists($file)) return [];
    $content = file_get_contents($file);
    if (empty($content)) return [];
    $decoded = base64_decode($content);
    $json = openssl_decrypt($decoded, 'AES-256-CBC', ENCRYPT_KEY, 0, ENCRYPT_IV);
    return json_decode($json, true) ?? [];
}

function saveUsers($users) {
    file_put_contents(DB_FILE, encryptData($users));
}

function loadUsers() {
    if (!file_exists(DB_FILE)) {
        $default = [
            'admin' => [
                'email' => ADMIN_EMAIL,
                'password' => password_hash(ADMIN_PASS, PASSWORD_DEFAULT),
                'name' => ADMIN_NAME,
                'role' => 'admin',
                'avatar' => 'default1',
                'created' => date('Y-m-d H:i:s')
            ]
        ];
        saveUsers($default);
        return $default;
    }
    return decryptData(DB_FILE);
}

// LOG KAYIT
function addLog($user_id, $user_name, $action, $detail = '') {
    $logs = decryptData(LOG_FILE);
    $logs[] = [
        'id' => uniqid(),
        'user_id' => $user_id,
        'user_name' => $user_name,
        'action' => $action,
        'detail' => $detail,
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
        'time' => date('Y-m-d H:i:s')
    ];
    file_put_contents(LOG_FILE, encryptData($logs));
}

// IP Derin Analiz
function getDeepIntel($ip) {
    if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) return null;
    try {
        $url = "http://ip-api.com/json/{$ip}?fields=66846719";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $response = curl_exec($ch);
        curl_close($ch);
        $data = json_decode($response, true);
        if ($data && isset($data['status']) && $data['status'] == 'success') {
            $security = [];
            if (!empty($data['proxy'])) $security[] = "🚨 Proxy/VPN";
            if (!empty($data['hosting'])) $security[] = "🏢 Hosting";
            if (!empty($data['mobile'])) $security[] = "📱 Mobil";
            if (empty($security)) $security[] = "🏠 Ev İnterneti";
            return [
                'query' => $data['query'],
                'isp' => $data['isp'] ?? '?',
                'country' => $data['country'] ?? '?',
                'city' => $data['city'] ?? '?',
                'lat' => $data['lat'] ?? 0,
                'lon' => $data['lon'] ?? 0,
                'security' => implode(' | ', $security),
                'maps' => "https://www.google.com/maps?q={$data['lat']},{$data['lon']}"
            ];
        }
    } catch (Exception $e) {}
    return null;
}

// ID Sorgulama - GERÇEK DOSYADAN OKUYOR
function searchId($target_id) {
    $result = ['found' => false, 'email' => 'Bulunamadı', 'ips' => [], 'servers' => 'Bulunamadı', 'lines' => []];
    
    if (!file_exists(DATA_FILE)) {
        return $result;
    }
    
    $handle = fopen(DATA_FILE, 'r');
    if ($handle) {
        while (($line = fgets($handle)) !== false) {
            if (strpos($line, $target_id) !== false) {
                $result['found'] = true;
                $result['lines'][] = substr($line, 0, 500);
                
                if ($result['email'] == 'Bulunamadı') {
                    preg_match('/[\w\.-]+@[\w\.-]+\.\w+/', $line, $m);
                    if ($m) $result['email'] = $m[0];
                }
                preg_match_all('/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $line, $ip_matches);
                foreach ($ip_matches[0] as $ip) {
                    if (!preg_match('/^(127\.|192\.168\.|10\.|172\.)/', $ip)) {
                        $result['ips'][] = $ip;
                    }
                }
                if ($result['servers'] == 'Bulunamadı') {
                    preg_match('/\[(\d{17,20}(?:,\s*\d{17,20})*)\]/', $line, $srv);
                    if ($srv) $result['servers'] = $srv[0];
                }
            }
        }
        fclose($handle);
    }
    $result['ips'] = array_unique($result['ips']);
    return $result;
}

// ========== İŞLEMLER ==========
$error = '';
$success = '';
$action = $_GET['action'] ?? 'login';
$currentPage = $_GET['page'] ?? 'dashboard';
$user_ip = $_SERVER['REMOTE_ADDR'];

// Kayıt Ol
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['register'])) {
    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';
    
    if (empty($name) || empty($email) || empty($password)) {
        $error = 'Tüm alanlar zorunludur!';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Geçerli e-posta giriniz!';
    } elseif ($password !== $confirm) {
        $error = 'Şifreler eşleşmiyor!';
    } elseif (strlen($password) < 4) {
        $error = 'Şifre en az 4 karakter!';
    } else {
        $users = loadUsers();
        $emailExists = false;
        foreach ($users as $u) {
            if ($u['email'] === $email) $emailExists = true;
        }
        if ($emailExists) {
            $error = 'Bu e-posta zaten kayıtlı!';
        } else {
            $newId = 'user_' . time() . '_' . rand(1000, 9999);
            $users[$newId] = [
                'email' => $email,
                'password' => password_hash($password, PASSWORD_DEFAULT),
                'name' => $name,
                'role' => 'user',
                'avatar' => 'default1',
                'created' => date('Y-m-d H:i:s')
            ];
            saveUsers($users);
            addLog($newId, $name, 'KAYIT OLDU', "IP: $user_ip");
            $success = 'Kayıt başarılı! Giriş yapın.';
            $action = 'login';
        }
    }
}

// Giriş Yap
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $identifier = trim($_POST['identifier'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($identifier) || empty($password)) {
        $error = 'Kullanıcı adı/e-posta ve şifre giriniz!';
    } else {
        $users = loadUsers();
        $found = false;
        foreach ($users as $id => $user) {
            if ($user['email'] === $identifier || $user['name'] === $identifier) {
                if (password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $id;
                    $_SESSION['user_name'] = $user['name'];
                    $_SESSION['user_email'] = $user['email'];
                    $_SESSION['user_role'] = $user['role'];
                    $_SESSION['user_avatar'] = $user['avatar'] ?? 'default1';
                    $found = true;
                    addLog($id, $user['name'], 'GİRİŞ YAPTI', "IP: $user_ip");
                    break;
                }
            }
        }
        if ($found) {
            header('Location: ?page=dashboard');
            exit;
        } else {
            addLog('unknown', 'Bilinmeyen', 'BAŞARISIZ GİRİŞ', "ID: $identifier");
            $error = 'Hatalı giriş!';
        }
    }
}

// Profil Güncelleme (Galeri)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_avatar']) && isset($_SESSION['user_id'])) {
    $new_avatar = $_POST['avatar'] ?? 'default1';
    $users = loadUsers();
    $users[$_SESSION['user_id']]['avatar'] = $new_avatar;
    saveUsers($users);
    $_SESSION['user_avatar'] = $new_avatar;
    addLog($_SESSION['user_id'], $_SESSION['user_name'], 'PROFİL RESMİ DEĞİŞTİRDİ', "Avatar: $new_avatar");
    $success = 'Profil resmi güncellendi!';
}

// Discord ID Sorgula
$query_result = null;
$searched_id = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['query_discord_id']) && isset($_SESSION['user_id'])) {
    $searched_id = trim($_POST['discord_id']);
    if (!empty($searched_id)) {
        $query_result = searchId($searched_id);
        addLog($_SESSION['user_id'], $_SESSION['user_name'], 'ID SORGULADI', "ID: $searched_id | Sonuç: " . ($query_result['found'] ? 'BULUNDU' : 'BULUNAMADI'));
        if ($query_result['found'] && !empty($query_result['ips'])) {
            $query_result['ip_intel'] = getDeepIntel($query_result['ips'][0]);
        }
    }
}

// Çıkış
if (isset($_GET['logout'])) {
    if (isset($_SESSION['user_id'])) {
        addLog($_SESSION['user_id'], $_SESSION['user_name'], 'ÇIKIŞ YAPTI', "");
    }
    session_destroy();
    header('Location: ?action=login');
    exit;
}

// Admin işlemleri
$isAdmin = isset($_SESSION['user_role']) && $_SESSION['user_role'] === 'admin';
$isLoggedIn = isset($_SESSION['user_id']);

if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['delete_user'])) {
        $deleteId = $_POST['delete_user'];
        $users = loadUsers();
        if ($deleteId !== 'admin' && isset($users[$deleteId])) {
            $userName = $users[$deleteId]['name'];
            unset($users[$deleteId]);
            saveUsers($users);
            addLog($_SESSION['user_id'], $_SESSION['user_name'], 'KULLANICI SİLDİ', "Silinen: $userName");
            $success = 'Kullanıcı silindi!';
        }
    }
    if (isset($_POST['change_role'])) {
        $roleId = $_POST['change_role'];
        $newRole = $_POST['new_role'];
        $users = loadUsers();
        if ($roleId !== 'admin' && isset($users[$roleId])) {
            $users[$roleId]['role'] = $newRole;
            saveUsers($users);
            addLog($_SESSION['user_id'], $_SESSION['user_name'], 'ROL DEĞİŞTİRDİ', "Kullanıcı: {$users[$roleId]['name']}");
            $success = 'Rol güncellendi!';
        }
    }
    if (isset($_POST['clear_logs'])) {
        file_put_contents(LOG_FILE, encryptData([]));
        addLog($_SESSION['user_id'], $_SESSION['user_name'], 'LOGLARI TEMİZLEDİ', '');
        $success = 'Loglar temizlendi!';
    }
}

// Avatar listesi (galeri)
$avatars = [
    'default1' => '😎', 'default2' => '🔥', 'default3' => '💀', 'default4' => '👑',
    'default5' => '🤖', 'default6' => '🎮', 'default7' => '⚡', 'default8' => '🐉',
    'default9' => '🚀', 'default10' => '⭐', 'default11' => '🌈', 'default12' => '🎯',
    'default13' => '💎', 'default14' => '🔮', 'default15' => '🦁', 'default16' => '🐺'
];
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $isLoggedIn ? '✨ PANEL | ' . htmlspecialchars($_SESSION['user_name']) : '✨ GİZLİ GİRİŞ'; ?></title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background: linear-gradient(135deg, #f5f7ff 0%, #e8ecf5 100%);
            font-family: 'Segoe UI', 'Poppins', system-ui, sans-serif;
            min-height: 100vh;
        }
        
        /* AÇIK RENK TEMA - CANLI RENKLER */
        .sidebar {
            position: fixed;
            top: 0;
            left: -280px;
            width: 280px;
            height: 100%;
            background: linear-gradient(180deg, #ffffff 0%, #f0f3ff 100%);
            box-shadow: 5px 0 30px rgba(0,0,0,0.1);
            transition: 0.3s ease;
            z-index: 1000;
            padding: 2rem 1rem;
            border-right: 3px solid #ff6b35;
        }
        
        .sidebar.open { left: 0; }
        
        .sidebar .close-btn {
            position: absolute;
            top: 1rem;
            right: 1rem;
            font-size: 1.8rem;
            cursor: pointer;
            color: #ff6b35;
        }
        
        .sidebar .menu-item {
            padding: 1rem;
            margin: 0.5rem 0;
            background: linear-gradient(135deg, #ff6b35, #ff9f4a);
            border-radius: 16px;
            cursor: pointer;
            transition: 0.2s;
            text-align: center;
            font-weight: bold;
        }
        
        .sidebar .menu-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 20px rgba(255,107,53,0.3);
        }
        
        .sidebar .menu-item a {
            color: white;
            text-decoration: none;
            display: block;
        }
        
        .menu-toggle {
            position: fixed;
            top: 1rem;
            left: 1rem;
            font-size: 2rem;
            cursor: pointer;
            color: #ff6b35;
            z-index: 999;
            background: white;
            padding: 0.3rem 0.8rem;
            border-radius: 16px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
            transition: 0.2s;
        }
        
        .menu-toggle:hover {
            transform: scale(1.05);
        }
        
        .overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.4);
            z-index: 998;
            display: none;
        }
        
        .overlay.active { display: block; }
        
        .main-content {
            margin-left: 0;
            padding: 2rem;
            transition: 0.3s;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .card {
            background: white;
            border-radius: 28px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.08);
            overflow: hidden;
            border: 1px solid rgba(255,107,53,0.2);
        }
        
        .card-header {
            background: linear-gradient(135deg, #ff6b35, #ff9f4a);
            padding: 1.5rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .card-header h2 {
            color: white;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }
        
        .profile-area {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            background: rgba(255,255,255,0.25);
            padding: 0.5rem 1.2rem;
            border-radius: 60px;
            backdrop-filter: blur(5px);
        }
        
        .profile-avatar {
            font-size: 2rem;
        }
        
        .profile-name {
            font-weight: bold;
            color: white;
            font-size: 1.1rem;
        }
        
        .card-body {
            padding: 2rem;
        }
        
        /* FORM ELEMANLARI */
        input, select, textarea {
            background: #f8f9ff;
            border: 2px solid #ffe0d0;
            padding: 0.8rem;
            border-radius: 16px;
            font-size: 1rem;
            transition: 0.2s;
            width: 100%;
        }
        
        input:focus {
            border-color: #ff6b35;
            outline: none;
            box-shadow: 0 0 0 3px rgba(255,107,53,0.2);
        }
        
        button, .btn {
            background: linear-gradient(135deg, #ff6b35, #ff9f4a);
            border: none;
            padding: 0.8rem 1.8rem;
            border-radius: 16px;
            color: white;
            font-weight: bold;
            font-size: 1rem;
            cursor: pointer;
            transition: 0.2s;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(255,107,53,0.4);
        }
        
        .alert {
            padding: 1rem;
            border-radius: 16px;
            margin-bottom: 1rem;
            font-weight: bold;
        }
        
        .alert-error { background: #ffe0e0; border-left: 5px solid #ff4444; color: #cc0000; }
        .alert-success { background: #e0ffe0; border-left: 5px solid #44ff44; color: #008800; }
        
        /* TABLO */
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid #ffe0d0;
        }
        
        th {
            background: #fff0e8;
            color: #ff6b35;
            font-weight: bold;
        }
        
        /* GALERI */
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
            gap: 1rem;
            margin: 1.5rem 0;
        }
        
        .gallery-item {
            background: #f8f9ff;
            border: 3px solid #ffe0d0;
            border-radius: 20px;
            text-align: center;
            padding: 1rem;
            cursor: pointer;
            transition: 0.2s;
            font-size: 2.5rem;
        }
        
        .gallery-item:hover {
            border-color: #ff6b35;
            transform: scale(1.05);
            background: #fff0e8;
        }
        
        .gallery-item.selected {
            border-color: #ff6b35;
            background: linear-gradient(135deg, #fff0e8, #ffe4d8);
            box-shadow: 0 0 15px rgba(255,107,53,0.3);
        }
        
        /* SORGU SONUCU */
        .result-card {
            background: linear-gradient(135deg, #fff8f0, #fff0e8);
            border-radius: 24px;
            padding: 1.5rem;
            margin-top: 1.5rem;
            border-left: 8px solid #ff6b35;
        }
        
        .badge-admin { background: #ff6b35; color: white; padding: 0.2rem 0.8rem; border-radius: 20px; font-size: 0.7rem; font-weight: bold; }
        .badge-user { background: #a0a0c0; color: white; padding: 0.2rem 0.8rem; border-radius: 20px; font-size: 0.7rem; }
        
        @media (max-width: 768px) {
            .main-content { padding: 4rem 1rem 1rem 1rem; }
            .card-header { flex-direction: column; text-align: center; }
        }
    </style>
    <script>
        function toggleSidebar() {
            document.querySelector('.sidebar').classList.toggle('open');
            document.querySelector('.overlay').classList.toggle('active');
        }
        
        function selectAvatar(avatar) {
            document.getElementById('avatar_input').value = avatar;
            document.querySelectorAll('.gallery-item').forEach(el => {
                el.classList.remove('selected');
                if (el.getAttribute('data-avatar') === avatar) {
                    el.classList.add('selected');
                }
            });
        }
        
        // Koruma
        document.addEventListener('contextmenu', e => e.preventDefault());
        document.addEventListener('keydown', e => {
            if (e.ctrlKey && (e.key === 'u' || e.key === 'U' || e.key === 's' || e.key === 'S')) e.preventDefault();
            if (e.key === 'F12') e.preventDefault();
        });
    </script>
</head>
<body>

<?php if (!$isLoggedIn): ?>
    <!-- GİRİŞ PANELİ - AÇIK TEMA -->
    <div style="display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 2rem;">
        <div class="card" style="max-width: 450px; width: 100%;">
            <div class="card-header">
                <h2>🔐 RESMİ PANEL SAYFASI</h2>
                <p style="color:white;">Hoş Geldiniz!</p>
            </div>
            <div class="card-body">
                <?php if ($error): ?><div class="alert alert-error">⚠️ <?php echo htmlspecialchars($error); ?></div><?php endif; ?>
                <?php if ($success): ?><div class="alert alert-success">✅ <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                
                <?php if ($action === 'login'): ?>
                    <form method="POST">
                        <div style="margin-bottom:1rem;">
                            <label style="font-weight:bold;">👤 Kullanıcı Adı / E-posta</label>
                            <input type="text" name="identifier" placeholder="Kullanıcı adı veya e-posta" required>
                        </div>
                        <div style="margin-bottom:1.5rem;">
                            <label style="font-weight:bold;">🔒 Şifre</label>
                            <input type="password" name="password" placeholder="Şifre" required>
                        </div>
                        <button type="submit" name="login" style="width:100%;">🔓 GİRİŞ YAP</button>
                        <div style="text-align:center; margin-top:1rem;">
                            Hesabınız yok mu? <a href="?action=register" style="color:#ff6b35; font-weight:bold;">Kayıt ol</a>
                        </div>
                    </form>
                <?php else: ?>
                    <form method="POST">
                        <div style="margin-bottom:1rem;"><label style="font-weight:bold;">👤 Kullanıcı Adı</label><input type="text" name="name" required></div>
                        <div style="margin-bottom:1rem;"><label style="font-weight:bold;">📧 E-posta</label><input type="email" name="email" required></div>
                        <div style="margin-bottom:1rem;"><label style="font-weight:bold;">🔒 Şifre</label><input type="password" name="password" required></div>
                        <div style="margin-bottom:1.5rem;"><label style="font-weight:bold;">🔒 Şifre (Tekrar)</label><input type="password" name="confirm_password" required></div>
                        <button type="submit" name="register" style="width:100%;">📝 KAYIT OL</button>
                        <div style="text-align:center; margin-top:1rem;">
                            Zaten hesabınız var mı? <a href="?action=login" style="color:#ff6b35; font-weight:bold;">Giriş yap</a>
                        </div>
                    </form>
                <?php endif; ?>
            </div>
        </div>
    </div>
<?php else: ?>
    <!-- ANA PANEL -->
    <div class="menu-toggle" onclick="toggleSidebar()">☰</div>
    <div class="sidebar">
        <div class="close-btn" onclick="toggleSidebar()">✕</div>
        <div style="text-align:center; margin-bottom:2rem;">
            <div style="font-size:4rem;"><?php 
                $avatarMap = $avatars;
                echo $avatarMap[$_SESSION['user_avatar']] ?? '😎';
            ?></div>
            <div style="color:#ff6b35; font-weight:bold; font-size:1.2rem;"><?php echo htmlspecialchars($_SESSION['user_name']); ?></div>
            <div style="font-size:0.8rem; color:#888;"><?php echo $_SESSION['user_role'] === 'admin' ? 'Yönetici' : 'Üye'; ?></div>
        </div>
        <div class="menu-item"><a href="?page=dashboard">📊 DASHBOARD</a></div>
        <div class="menu-item"><a href="?page=discord_query">🎮 DISCORD ID QUERY</a></div>
        <div class="menu-item"><a href="?page=profile">👤 PROFİL DÜZENLE</a></div>
        <?php if ($isAdmin): ?>
        <div class="menu-item"><a href="?page=admin">⚙️ ADMIN PANEL</a></div>
        <div class="menu-item"><a href="?page=logs">📜 TÜM LOGLAR</a></div>
        <?php endif; ?>
        <div class="menu-item"><a href="?logout=1" style="background:#ff4444;">🚪 ÇIKIŞ</a></div>
    </div>
    <div class="overlay" onclick="toggleSidebar()"></div>
    
    <div class="main-content">
        <div class="container">
            <div class="card">
                <div class="card-header">
                    <h2>✨ <?php 
                        if($currentPage === 'discord_query') echo 'DISCORD ID SORGULA';
                        elseif($currentPage === 'admin') echo 'YÖNETİCİ PANELİ';
                        elseif($currentPage === 'logs') echo 'SİSTEM LOGLARI';
                        elseif($currentPage === 'profile') echo 'PROFİL DÜZENLE';
                        else echo 'ANA PANEL';
                    ?></h2>
                    <div class="profile-area">
                        <span class="profile-avatar"><?php echo $avatarMap[$_SESSION['user_avatar']] ?? '😎'; ?></span>
                        <span class="profile-name"><?php echo htmlspecialchars($_SESSION['user_name']); ?></span>
                    </div>
                </div>
                <div class="card-body">
                    <?php if ($success): ?><div class="alert alert-success">✅ <?php echo htmlspecialchars($success); ?></div><?php endif; ?>
                    <?php if ($error): ?><div class="alert alert-error">⚠️ <?php echo htmlspecialchars($error); ?></div><?php endif; ?>
                    
                    <!-- DASHBOARD -->
                    <?php if ($currentPage === 'dashboard'): ?>
                        <div style="background:#fff8f0; padding:1.5rem; border-radius:24px;">
                            <p style="font-size:1.1rem;">📅 <strong>Giriş Tarihi:</strong> <?php echo date('d.m.Y H:i:s'); ?></p>
                            <p style="font-size:1.1rem;">🌐 <strong>IP Adresiniz:</strong> <?php echo $user_ip; ?></p>
                            <p style="font-size:1.1rem;">👑 <strong>Rol:</strong> <?php echo $isAdmin ? 'Yönetici' : 'Üye'; ?></p>
                            <hr style="margin:1rem 0; border-color:#ffe0d0;">
                            <h3 style="color:#ff6b35;">⚡ HOŞ GELDİNİZ</h3>
                            <p>Sol üstteki ☰ menüden Discord ID sorgulama, profil düzenleme ve admin paneli (yetkiniz varsa) erişebilirsiniz.</p>
                        </div>
                    <?php endif; ?>
                    
                    <!-- PROFİL DÜZENLE - GALERİ -->
                    <?php if ($currentPage === 'profile'): ?>
                        <form method="POST">
                            <div style="text-align:center; margin-bottom:1rem;">
                                <div style="font-size:5rem; margin-bottom:0.5rem;"><?php echo $avatarMap[$_SESSION['user_avatar']] ?? '😎'; ?></div>
                                <p style="color:#888;">Mevcut avatarınız</p>
                            </div>
                            
                            <h3 style="color:#ff6b35; margin-bottom:1rem;">🎨 Avatar Galerisi</h3>
                            <div class="gallery">
                                <?php foreach ($avatars as $key => $emoji): ?>
                                <div class="gallery-item <?php echo $_SESSION['user_avatar'] == $key ? 'selected' : ''; ?>" 
                                     data-avatar="<?php echo $key; ?>" 
                                     onclick="selectAvatar('<?php echo $key; ?>')">
                                    <?php echo $emoji; ?>
                                </div>
                                <?php endforeach; ?>
                            </div>
                            
                            <input type="hidden" name="avatar" id="avatar_input" value="<?php echo $_SESSION['user_avatar']; ?>">
                            <button type="submit" name="update_avatar" style="width:100%; margin-top:1rem;">💾 PROFİLİ GÜNCELLE</button>
                        </form>
                    <?php endif; ?>
                    
                    <!-- DISCORD ID QUERY -->
                    <?php if ($currentPage === 'discord_query'): ?>
                        <form method="POST">
                            <div style="display:flex; gap:1rem; flex-wrap:wrap;">
                                <input type="text" name="discord_id" placeholder="Discord ID Girin (Örn: 123456789012345678)" value="<?php echo htmlspecialchars($searched_id); ?>" style="flex:1;" required>
                                <button type="submit" name="query_discord_id">🔍 DERİN ARA</button>
                            </div>
                        </form>
                        
                        <?php if ($query_result !== null): ?>
                            <?php if (!$query_result['found']): ?>
                                <div class="alert alert-error" style="margin-top:1.5rem;">❌ Hedef ID'ye ait herhangi bir veri sızıntısı bulunamadı.</div>
                            <?php else: ?>
                                <div class="result-card">
                                    <h3 style="color:#ff6b35;">🕵️ MAKSİMUM İSTİHBARAT RAPORU</h3>
                                    <hr style="margin:1rem 0; border-color:#ffd0b0;">
                                    
                                    <p><strong>📧 Sızdırılan E-posta:</strong> <code style="background:#fff; padding:0.2rem 0.5rem; border-radius:8px;"><?php echo htmlspecialchars($query_result['email']); ?></code></p>
                                    
                                    <?php if (!empty($query_result['ips'])): ?>
                                        <p><strong>🌐 Tespit Edilen IP'ler:</strong></p>
                                        <?php foreach (array_slice($query_result['ips'], 0, 5) as $ip): ?>
                                            <code style="display:inline-block; background:#fff; padding:0.2rem 0.6rem; margin:0.2rem; border-radius:12px;"><?php echo $ip; ?></code>
                                        <?php endforeach; ?>
                                        
                                        <?php if (isset($query_result['ip_intel'])): 
                                            $intel = $query_result['ip_intel']; ?>
                                            <hr style="margin:1rem 0;">
                                            <h4>📡 DEEP IP ANALİZİ</h4>
                                            <p>🌐 IP: <strong><?php echo $intel['query']; ?></strong></p>
                                            <p>🏢 ISS: <?php echo $intel['isp']; ?></p>
                                            <p>📍 Konum: <?php echo $intel['country']; ?> / <?php echo $intel['city']; ?></p>
                                            <p>🛡️ Güvenlik: <?php echo $intel['security']; ?></p>
                                            <p>🗺️ <a href="<?php echo $intel['maps']; ?>" target="_blank" style="color:#ff6b35;">Google Maps'te Görüntüle →</a></p>
                                        <?php endif; ?>
                                    <?php endif; ?>
                                    
                                    <?php if ($query_result['servers'] != 'Bulunamadı'): ?>
                                        <hr style="margin:1rem 0;">
                                        <p><strong>🏠 Discord Sunucu Logları:</strong></p>
                                        <div style="background:#fff; padding:1rem; border-radius:16px; font-family:monospace; font-size:0.8rem; overflow-x:auto;">
                                            <?php echo htmlspecialchars(substr($query_result['servers'], 0, 400)); ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                        <?php endif; ?>
                    <?php endif; ?>
                    
                    <!-- ADMIN PANEL -->
                    <?php if ($currentPage === 'admin' && $isAdmin): 
                        $users = loadUsers();
                    ?>
                        <div style="background:#fff8f0; padding:1.5rem; border-radius:24px; margin-bottom:2rem;">
                            <h3 style="color:#ff6b35;">➕ Yeni Kullanıcı Ekle</h3>
                            <form method="POST">
                                <div style="display:grid; gap:0.8rem; margin-top:1rem;">
                                    <input type="text" name="name" placeholder="Kullanıcı adı" required>
                                    <input type="email" name="email" placeholder="E-posta" required>
                                    <input type="password" name="password" placeholder="Şifre" required>
                                    <select name="role"><option value="user">Üye</option><option value="admin">Admin</option></select>
                                    <button type="submit" name="add_user">➕ Kullanıcı Ekle</button>
                                </div>
                            </form>
                        </div>
                        
                        <h3 style="color:#ff6b35;">📋 Kayıtlı Kullanıcılar</h3>
                        <div style="overflow-x:auto;">
                            <table>
                                <thead>
                                    <tr><th>Avatar</th><th>Kullanıcı</th><th>E-posta</th><th>Rol</th><th>İşlem</th></tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $id => $user): ?>
                                    <tr>
                                        <td style="font-size:1.5rem;"><?php echo $avatars[$user['avatar']] ?? '😎'; ?></td>
                                        <td><?php echo htmlspecialchars($user['name']); ?></td>
                                        <td><?php echo htmlspecialchars($user['email']); ?></td>
                                        <td><span class="<?php echo $user['role'] === 'admin' ? 'badge-admin' : 'badge-user'; ?>"><?php echo $user['role']; ?></span></td>
                                        <td>
                                            <?php if ($id !== 'admin'): ?>
                                            <form method="POST" style="display:inline;">
                                                <button type="submit" name="delete_user" value="<?php echo $id; ?>" style="background:#ff4444; padding:0.3rem 1rem;">🗑️ Sil</button>
                                            </form>
                                            <form method="POST" style="display:inline; margin-left:0.5rem;">
                                                <select name="new_role" style="width:auto; display:inline; padding:0.3rem;">
                                                    <option value="user">Üye</option><option value="admin">Admin</option>
                                                </select>
                                                <button type="submit" name="change_role" value="<?php echo $id; ?>" style="padding:0.3rem 1rem;">🔄 Değiştir</button>
                                            </form>
                                            <?php else: ?>
                                                <span style="color:#888;">Admin</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                    
                    <!-- TÜM LOGLAR -->
                    <?php if ($currentPage === 'logs' && $isAdmin): 
                        $logs = decryptData(LOG_FILE);
                        $logs = array_reverse($logs);
                    ?>
                        <form method="POST" style="margin-bottom:1.5rem;">
                            <button type="submit" name="clear_logs" style="background:#ff4444;">🗑️ TÜM LOGLARI TEMİZLE</button>
                        </form>
                        <div style="overflow-x:auto;">
                            <table>
                                <thead><tr><th>Zaman</th><th>Kullanıcı</th><th>İşlem</th><th>Detay</th><th>IP</th></tr></thead>
                                <tbody>
                                    <?php foreach ($logs as $log): ?>
                                    <tr>
                                        <td><?php echo $log['time']; ?></td>
                                        <td><?php echo htmlspecialchars($log['user_name']); ?></td>
                                        <td><span style="background:#fff0e8; padding:0.2rem 0.6rem; border-radius:12px;"><?php echo $log['action']; ?></span></td>
                                        <td><?php echo htmlspecialchars(substr($log['detail'], 0, 60)); ?></td>
                                        <td><code><?php echo $log['ip']; ?></code></td>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php if (empty($logs)): ?>
                                    <tr><td colspan="5" style="text-align:center;">Henüz log kaydı yok</td></tr>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
<?php endif; ?>
</body>
</html>
