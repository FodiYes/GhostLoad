<?php
declare(strict_types=1);

namespace Core;

/**
 * URL obfuscation and proxying
 */
final class URLObfuscator
{
    private string $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    /**
     * Encrypt URL with AES-256-CBC
     */
    public function encryptURL(string $url): string
    {
        $iv = random_bytes(16);
        $key = hash('sha256', $this->secret, true);

        $encrypted = openssl_encrypt($url, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        // Combine IV + encrypted data and base64 encode
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt URL
     */
    public function decryptURL(string $encrypted): ?string
    {
        $data = base64_decode($encrypted);
        if ($data === false || strlen($data) < 16) {
            return null;
        }

        $iv = substr($data, 0, 16);
        $ciphertext = substr($data, 16);
        $key = hash('sha256', $this->secret, true);

        $decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);

        return $decrypted !== false ? $decrypted : null;
    }

    /**
     * Generate proxy URL that hides real file location
     * Format: /proxy.php?id=<encrypted_url>&t=<timestamp>&sig=<signature>
     */
    public function generateProxyURL(string $realURL, string $baseURL): string
    {
        $encrypted = $this->encryptURL($realURL);
        $timestamp = time();

        // Generate signature to prevent tampering
        $signature = hash_hmac('sha256', $encrypted . $timestamp, $this->secret);

        return $baseURL . '/proxy.php?id=' . urlencode($encrypted) .
               '&t=' . $timestamp .
               '&sig=' . substr($signature, 0, 16);
    }

    /**
     * Validate proxy request signature
     */
    public function validateProxyRequest(string $encrypted, int $timestamp, string $signature): bool
    {
        // Check timestamp (max 1 hour old)
        if (abs(time() - $timestamp) > 3600) {
            return false;
        }

        $expectedSig = hash_hmac('sha256', $encrypted . $timestamp, $this->secret);

        return hash_equals(substr($expectedSig, 0, 16), $signature);
    }

    /**
     * Obfuscate URL by replacing with random-looking path
     * Example: https://cdn.com/a3f2b1c9.jpg instead of real URL
     */
    public function generateFakeStaticURL(string $realURL, string $cdnBase): string
    {
        $encrypted = $this->encryptURL($realURL);

        // Generate fake filename from hash
        $hash = substr(md5($encrypted), 0, 8);

        // Random extension to look like static asset
        $extensions = ['jpg', 'png', 'css', 'js', 'woff2', 'svg'];
        $ext = $extensions[array_rand($extensions)];

        return $cdnBase . '/assets/' . $hash . '.' . $ext . '?v=' . time();
    }
}
