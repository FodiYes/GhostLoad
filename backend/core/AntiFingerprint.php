<?php
declare(strict_types=1);

namespace Core;

/**
 * Anti-fingerprinting and domain fronting support
 */
final class AntiFingerprint
{
    /**
     * Randomize response timing to prevent timing analysis
     */
    public function addJitter(int $minMs = 50, int $maxMs = 300): void
    {
        usleep(random_int($minMs * 1000, $maxMs * 1000));
    }

    /**
     * Strip identifying headers
     */
    public function sanitizeHeaders(): void
    {
        header_remove('X-Powered-By');
        header_remove('Server');
        header_remove('X-PHP-Version');
    }

    /**
     * Add fake headers to mimic legitimate services
     */
    public function mimicCDN(): void
    {
        $cdns = [
            'cloudflare' => [
                'CF-Ray' => $this->generateCFRay(),
                'CF-Cache-Status' => 'HIT',
                'Server' => 'cloudflare',
            ],
            'cloudfront' => [
                'X-Amz-Cf-Id' => $this->generateAWSId(),
                'X-Cache' => 'Hit from cloudfront',
                'Via' => '1.1 ' . $this->generateAWSId() . '.cloudfront.net (CloudFront)',
            ],
            'fastly' => [
                'X-Served-By' => 'cache-' . bin2hex(random_bytes(4)),
                'X-Cache' => 'HIT',
                'X-Cache-Hits' => (string)random_int(1, 100),
            ],
        ];

        $cdn = $cdns[array_rand($cdns)];

        foreach ($cdn as $name => $value) {
            header("$name: $value");
        }
    }

    /**
     * Generate fake CloudFlare Ray ID
     */
    private function generateCFRay(): string
    {
        return bin2hex(random_bytes(8)) . '-' . strtoupper(substr(bin2hex(random_bytes(2)), 0, 3));
    }

    /**
     * Generate fake AWS CloudFront ID
     */
    private function generateAWSId(): string
    {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $id = '';
        for ($i = 0; $i < 56; $i++) {
            $id .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $id;
    }

    /**
     * Validate domain fronting request
     * Checks if Host header matches expected CDN domain
     */
    public function validateDomainFronting(array $allowedDomains): bool
    {
        $host = $_SERVER['HTTP_HOST'] ?? '';

        foreach ($allowedDomains as $domain) {
            if (str_ends_with($host, $domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add CORS headers for domain fronting
     */
    public function addCORSHeaders(string $origin = '*'): void
    {
        header("Access-Control-Allow-Origin: $origin");
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
        header('Access-Control-Max-Age: 86400');
    }

    /**
     * Generate fake ETag to look like static content
     */
    public function generateETag(): string
    {
        return '"' . md5((string)time() . random_bytes(8)) . '"';
    }

    /**
     * Add cache headers to mimic static content
     */
    public function mimicStaticContent(string $contentType = 'image/jpeg'): void
    {
        header("Content-Type: $contentType");
        header('Cache-Control: public, max-age=31536000, immutable');
        header('ETag: ' . $this->generateETag());
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', time() - random_int(86400, 2592000)) . ' GMT');
    }
}
