<?php
declare(strict_types=1);

namespace Core;

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Logger.php';
require_once __DIR__ . '/Security.php';

final class Bootstrap {
    private Config $config;
    private Logger $logger;
    private Security $security;

    public function __construct() {
        $baseDir = dirname(__DIR__);
        
        $this->config = new Config(
            $baseDir . '/config/.env',
            $baseDir . '/config/deployments.php'
        );
        
        $this->logger = new Logger($baseDir . '/logs');
        
        if (!is_dir($baseDir . '/data')) {
            mkdir($baseDir . '/data', 0700, true);
        }
        
        $this->security = new Security($this->config, $this->logger, $baseDir . '/data/security.sqlite');
    }

    public function getConfig(): Config {
        return $this->config;
    }

    public function getLogger(): Logger {
        return $this->logger;
    }

    public function getSecurity(): Security {
        return $this->security;
    }

    public function run(): void {
        $this->enforceProductionSettings();

        try {
            // Only allow POST
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new \Exception('Method Not Allowed', 405);
            }

            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $this->security->enforceRateLimit($ip);

            $input = file_get_contents('php://input');
            $data = json_decode($input, true);

            if (!$data) {
                throw new \Exception('Invalid JSON payload', 400);
            }

            // Validates Time, Nonce (Replay), and HMAC Signature
            $this->security->validateRequest($data);

            $profile = $data['profile'];
            $files = $this->config->getDeployment($profile);

            if (!$files) {
                throw new \Exception('Profile not found', 404);
            }

            $this->logger->success("Granted access to profile: $profile for IP: $ip");
            $this->sendResponse(true, ['files' => $files]);

        } catch (\Exception $e) {
            $code = $e->getCode() ?: 500;
            $msg = $e->getMessage();
            $this->logger->error("Failed request: $msg");
            $this->sendResponse(false, ['error' => 'An error occurred'], $code);
        } catch (\Throwable $e) {
            // Catch fatal PHP errors cleanly
            $this->logger->error("System Error: " . $e->getMessage());
            $this->sendResponse(false, ['error' => 'Internal Server Error'], 500);
        }
    }

    private function enforceProductionSettings(): void {
        if ($this->config->isProduction()) {
            ini_set('display_errors', '0');
            error_reporting(0);
            header_remove('X-Powered-By');
        } else {
            ini_set('display_errors', '1');
            error_reporting(E_ALL);
        }

        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        
        // Enable output compression
        if (extension_loaded('zlib') && !headers_sent()) {
            ob_start('ob_gzhandler');
        }
    }

    private function sendResponse(bool $success, array $data, int $code = 200): void {
        http_response_code($code);
        $response = array_merge(['success' => $success], $data);
        
        // Minify JSON output in production
        $flags = $this->config->isProduction() ? 0 : JSON_PRETTY_PRINT;
        echo json_encode($response, $flags);
        exit;
    }
}
