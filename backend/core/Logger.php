<?php
declare(strict_types=1);

namespace Core;

final class Logger {
    private string $logFile;

    public function __construct(string $logDir) {
        if (!is_dir($logDir)) {
            mkdir($logDir, 0700, true);
        }
        $this->logFile = $logDir . '/access_' . date('Y-m-d') . '.log';
    }

    public function log(string $status, string $details): void {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // Structured logging (JSON per line)
        $entry = json_encode([
            'time' => date('Y-m-d\TH:i:sP'),
            'ip' => $ip,
            'status' => $status,
            'details' => $details
        ]) . PHP_EOL;

        file_put_contents($this->logFile, $entry, FILE_APPEND | LOCK_EX);
    }

    public function error(string $message): void {
        $this->log('ERROR', $message);
    }
    
    public function success(string $message): void {
        $this->log('SUCCESS', $message);
    }
}
