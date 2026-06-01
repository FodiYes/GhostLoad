<?php
declare(strict_types=1);

/**
 * Enhanced API endpoint with traffic obfuscation and encrypted containers
 */

require_once __DIR__ . '/../core/Bootstrap.php';
require_once __DIR__ . '/../core/Obfuscator.php';
require_once __DIR__ . '/../core/AntiFingerprint.php';
require_once __DIR__ . '/../core/KeyDerivation.php';

use Core\Bootstrap;
use Core\Obfuscator;
use Core\AntiFingerprint;
use Core\KeyDerivation;

$app = new Bootstrap();
$obfuscator = new Obfuscator();
$antiFingerprint = new AntiFingerprint();
$keyDerivation = new KeyDerivation($app->getConfig()->get('MASTER_KEY'));

// Detect encoding format from request
$format = $_GET['f'] ?? 'json';

// Anti-fingerprinting
$antiFingerprint->sanitizeHeaders();
$antiFingerprint->addJitter(50, 200);

// Handle OPTIONS for CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    $antiFingerprint->addCORSHeaders();
    http_response_code(204);
    exit;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new \Exception('Method Not Allowed', 405);
    }

    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $app->getSecurity()->enforceRateLimit($ip);

    // Decode request based on format
    $input = file_get_contents('php://input');

    $data = match($format) {
        'image' => $obfuscator->decodeFromImage($input),
        'css'   => $obfuscator->decodeFromCSS($input),
        'js'    => $obfuscator->decodeFromJS($input),
        default => json_decode($input, true),
    };

    if (!$data) {
        throw new \Exception('Invalid payload', 400);
    }

    // Validate request (HMAC, nonce, timestamp)
    $app->getSecurity()->validateRequest($data);

    $profile = $data['profile'];
    $files = $app->getConfig()->getDeployment($profile);

    if (!$files) {
        throw new \Exception('Profile not found', 404);
    }

    // ключ выводим из мастер-ключа + имени файла (детерминированный)
    foreach ($files as &$file) {
        $keyInfo = $keyDerivation->generateFileKey($profile, $file['name']);
        $file['key']     = $keyInfo['key'];
        $file['expires'] = $keyInfo['expires'];
    }

    $app->getLogger()->success("Granted access to profile: $profile for IP: $ip");

    // Encode response based on format
    $response = ['success' => true, 'files' => $files];

    $output = match($format) {
        'image' => $obfuscator->encodeAsImage($response, 'jpeg'),
        'css'   => $obfuscator->encodeAsCSS($response),
        'js'    => $obfuscator->encodeAsJS($response),
        default => json_encode($response),
    };

    // Set appropriate headers
    match($format) {
        'image' => $antiFingerprint->mimicStaticContent('image/jpeg'),
        'css'   => $antiFingerprint->mimicStaticContent('text/css'),
        'js'    => $antiFingerprint->mimicStaticContent('application/javascript'),
        default => header('Content-Type: application/json'),
    };

    if ($format !== 'json') {
        $antiFingerprint->mimicCDN();
    }

    http_response_code(200);
    echo $output;

} catch (\Exception $e) {
    $code = $e->getCode() ?: 500;
    $msg = $e->getMessage();
    $app->getLogger()->error("Failed request: $msg");

    $errorResponse = ['success' => false, 'error' => 'An error occurred'];

    $output = match($format) {
        'image' => $obfuscator->encodeAsImage($errorResponse, 'jpeg'),
        'css'   => $obfuscator->encodeAsCSS($errorResponse),
        'js'    => $obfuscator->encodeAsJS($errorResponse),
        default => json_encode($errorResponse),
    };

    http_response_code($code);
    echo $output;
}
