<?php
declare(strict_types=1);

namespace Core;

/**
 * HKDF-based key derivation for one-time decryption keys
 */
final class KeyDerivation
{
    private string $masterKey;

    public function __construct(string $masterKeyHex)
    {
        $this->masterKey = hex2bin($masterKeyHex);

        if (strlen($this->masterKey) !== 32) {
            throw new \RuntimeException('Master key must be 32 bytes (256-bit)');
        }
    }

    /**
     * Детерминированный ключ для файла: HKDF(master, profile|filename)
     * Не зависит от timestamp/nonce — один и тот же при любом запросе.
     * Используй этот же вывод когда шифруешь .enc офлайн.
     *
     * @return array{key: string, expires: int}
     */
    public function generateFileKey(string $profile, string $filename): array
    {
        $context = $profile . '|' . $filename;

        $salt = hash('sha256', $context, true);
        $prk  = hash_hmac('sha256', $this->masterKey, $salt, true);

        $derivedKey = $this->hkdfExpand($prk, 'payload-decryption-key', 32);

        return [
            'key'     => bin2hex($derivedKey),
            'expires' => time() + 600,
        ];
    }

    /**
     * One-time ключ (оставлен для совместимости, больше не используется для файлов)
     *
     * @return array{key: string, expires: int}
     */
    public function generateOneTimeKey(string $profile, int $timestamp, string $nonce): array
    {
        $context = $profile . '|' . $timestamp . '|' . $nonce;

        $salt = hash('sha256', $context, true);
        $prk  = hash_hmac('sha256', $this->masterKey, $salt, true);

        $derivedKey = $this->hkdfExpand($prk, 'payload-decryption-key', 32);

        return [
            'key'     => bin2hex($derivedKey),
            'expires' => $timestamp + 600,
        ];
    }

    /**
     * HKDF Expand function
     */
    private function hkdfExpand(string $prk, string $info, int $length): string
    {
        $hashLen = 32; // SHA-256 output length
        $n = (int)ceil($length / $hashLen);

        $okm = '';
        $t = '';

        for ($i = 1; $i <= $n; $i++) {
            $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }

    /**
     * Validate key expiration
     */
    public function isKeyExpired(int $expires): bool
    {
        return time() > $expires;
    }
}
