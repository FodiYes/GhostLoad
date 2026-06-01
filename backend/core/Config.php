<?php
declare(strict_types=1);

namespace Core;

final class Config {
    private array $env;
    private array $deployments;

    public function __construct(string $envPath, string $deploymentsPath) {
        $this->env = $this->parseEnv($envPath);
        $this->deployments = require $deploymentsPath;
    }

    private function parseEnv(string $path): array {
        if (!file_exists($path)) {
            throw new \RuntimeException('Environment file missing.');
        }
        
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $env = [];
        foreach ($lines as $line) {
            if (strpos(trim($line), '#') === 0) continue;
            [$key, $value] = explode('=', $line, 2);
            $env[trim($key)] = trim($value);
        }
        return $env;
    }

    public function get(string $key, $default = null) {
        return $this->env[$key] ?? $default;
    }

    public function getDeployment(string $profile): ?array {
        return $this->deployments[$profile] ?? null;
    }

    public function isProduction(): bool {
        return $this->get('APP_ENV', 'production') === 'production';
    }
}
