<?php
declare(strict_types=1);

namespace Core;

use PDO;

final class Security {
    private Config $config;
    private Logger $logger;
    private PDO $db;

    public function __construct(Config $config, Logger $logger, string $dbPath) {
        $this->config = $config;
        $this->logger = $logger;
        
        $isNewDb = !file_exists($dbPath);
        $this->db = new PDO('sqlite:' . $dbPath);
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        if ($isNewDb) {
            $this->initDb();
        }
    }

    private function initDb(): void {
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip TEXT PRIMARY KEY,
                hits INTEGER,
                last_reset INTEGER
            );
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                created_at INTEGER
            );
        ");
    }

    public function enforceRateLimit(string $ip): void {
        $maxReqs = (int)$this->config->get('RATE_LIMIT_REQ', 20);
        $window = (int)$this->config->get('RATE_LIMIT_SEC', 60);
        $now = time();

        $stmt = $this->db->prepare("SELECT hits, last_reset FROM rate_limits WHERE ip = ?");
        $stmt->execute([$ip]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            $stmt = $this->db->prepare("INSERT INTO rate_limits (ip, hits, last_reset) VALUES (?, 1, ?)");
            $stmt->execute([$ip, $now]);
        } else {
            if ($now - $row['last_reset'] > $window) {
                // Reset window
                $stmt = $this->db->prepare("UPDATE rate_limits SET hits = 1, last_reset = ? WHERE ip = ?");
                $stmt->execute([$now, $ip]);
            } else {
                if ($row['hits'] >= $maxReqs) {
                    $this->logger->error("Rate limit exceeded for IP: $ip");
                    throw new \Exception('Too many requests', 429);
                }
                $stmt = $this->db->prepare("UPDATE rate_limits SET hits = hits + 1 WHERE ip = ?");
                $stmt->execute([$ip]);
            }
        }
    }

    public function validateRequest(array $data): void {
        $profile = $data['profile'] ?? '';
        $timestamp = $data['timestamp'] ?? 0;
        $nonce = $data['nonce'] ?? '';
        $signature = $data['signature'] ?? '';

        if (!$profile || !$timestamp || !$nonce || !$signature) {
            throw new \Exception('Invalid payload', 400);
        }

        // 1. Time Drift Validation
        $maxDrift = (int)$this->config->get('MAX_TIME_DRIFT', 15);
        if (abs(time() - (int)$timestamp) > $maxDrift) {
            throw new \Exception('Request expired', 403);
        }

        // 2. Nonce Validation (Replay Attack Prevention)
        $stmt = $this->db->prepare("SELECT 1 FROM nonces WHERE nonce = ?");
        $stmt->execute([$nonce]);
        if ($stmt->fetchColumn()) {
            throw new \Exception('Replay attack detected', 403);
        }

        // Clean old nonces to prevent DB bloat
        $this->db->exec("DELETE FROM nonces WHERE created_at < " . (time() - 3600));
        
        $stmt = $this->db->prepare("INSERT INTO nonces (nonce, created_at) VALUES (?, ?)");
        $stmt->execute([$nonce, time()]);

        // 3. Signature Validation
        $secret = $this->config->get('SECRET_KEY');
        $stringToSign = $profile . $timestamp . $nonce;
        $expectedSignature = hash_hmac('sha256', $stringToSign, $secret);

        if (!hash_equals($expectedSignature, $signature)) {
            throw new \Exception('Invalid signature', 403);
        }
    }
}
