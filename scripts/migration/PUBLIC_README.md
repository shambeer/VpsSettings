# VPS Migration

Общий интерактивный установщик и мигратор VPN для чистого Linux VPS. Запускайте его на своём компьютере с SSH-ключом. Клонирование репозитория не требуется.

## Запуск одной командой

Windows PowerShell 5.1+:

```powershell
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/shambeer/VpsMigration/releases/latest/download/run.ps1').Content))
```

Linux/WSL:

```bash
curl -fsSL https://github.com/shambeer/VpsMigration/releases/latest/download/run.sh | bash
```

Нужны Python 3.11+ с актуальными исправлениями tarfile и OpenSSH. Для Linux также нужны curl и Bash. Запускатели проверяют SHA-256 Python-пакета перед исполнением; сам скачиваемый запускатель требует доверия к владельцу репозитория и GitHub. При необходимости сначала скачайте и прочитайте его. Временный пакет удаляется после завершения; результаты остаются в локальном каталоге версии.

Для проверки без SSH добавьте `--check` в конец PowerShell-команды. В Linux используйте `curl -fsSL https://github.com/shambeer/VpsMigration/releases/latest/download/run.sh | bash -s -- --check`.

## Что будет дальше

1. Выберите новую установку, перенос из полной копии либо создание копии.
2. Введите адрес VPS, SSH-порт и локальный путь к приватному SSH-ключу. Содержимое ключа на сервер не отправляется.
3. Укажите домен с A-записью на новый IPv4 без AAAA, HTTPS-цель REALITY и сетевой профиль.
4. Подтвердите BACKUP/DEPLOY с адресом сервера. Для цели нужен чистый Linux x86_64: Ubuntu 24.04/26.04 или Debian 12/13, systemd, root по ключу и Python 3.11+.

Устанавливаются XRay/REALITY, AmneziaWG, Telegram-прокси, панели 3x-ui/3DP и резервные WireGuard, OpenVPN, Shadowsocks, Hysteria2. Профиль `filtered` по умолчанию публикует только VPN TCP 443; SSH и HTTP для сертификата сохраняются, другие VPN и панели доступны локально. Профиль `all` публикует остальные VPN-порты. Настраиваются Fail2ban и SSH по ключу с проверкой и таймером отката.

Личные и общие конфиги/строки раздельно сохраняются в `private-vpn/server-settings/migrations/<id>/access/` внутри локальной папки версии. Её полный путь выводится при запуске. `admin/` и `legacy/` не раздавайте другим пользователям. Резервные копии и доступы не загружаются в GitHub.

Основное соединение не получает дополнительного туннеля или ограничения полосы. Скорость и доступность зависят от VPS и сети. Маскировка не скрывает IP сервера и не устраняет блокировку целого IP. Полная установка/восстановление на чистом VPS ещё требуют сквозного испытания; сначала используйте тестовый сервер.

Подробные требования, пути, резервные копии, доступ к панелям и ограничения: [инструкция](scripts/migration/README.md). Исходники находятся в scripts/migration/. Локальная проверка: `python -m unittest discover -s scripts/migration/tests`.
