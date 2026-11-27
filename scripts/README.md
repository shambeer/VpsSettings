# Сценарии

[migration/README.md](migration/README.md) — установка, полный backup, перенос, защита SSH и экспорт доступов. Точка входа — migration/migrate.py; доступны обёртки и переносимый пакет с curl-запускателем.

Локальные проверки не подтверждают готовность к боевому переносу без испытания на чистой машине. Исторические установщики и hook с настройками конкретного сервера перенесены в private-vpn/server-settings/scripts/.

Код мигратора разложен в migration/vps_migration/{cli,core,server,packaging}/; шаблоны запускателей — packaging/templates/, проверки — migration/tests/. Корневые migrate.py и build_portable.py сохраняют прежние команды.
