<?php
declare(strict_types=1);

return [
    'Default' => [
        [
            'name' => 'example_app.exe',
            'url' => 'https://example.com/downloads/example_app.enc',
            'sha256' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'target' => '%APPDATA%\\ExampleClient\\example_app.exe',
            'run' => true,
            'elevated' => true
        ]
    ],
    'beta_channel' => [
        [
            'name' => 'client_beta.exe',
            'url' => 'https://example.com/downloads/client_beta.enc',
            'sha256' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'target' => '%APPDATA%\\ClientBeta\\client_beta.exe',
            'run' => true,
            'elevated' => false
        ]
    ]
];
