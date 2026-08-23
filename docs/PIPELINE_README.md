# DevSecOps starter kit для форка DefectDojo

Комплект файлов для безопасного CI/CD-пайплайна поверх
[DefectDojo](https://github.com/DefectDojo/django-DefectDojo) на GitHub Actions.

## Структура

```
.github/workflows/
  security.yml        # SAST + SCA + секреты + IaC/образы + Security Gateway
  dast.yml            # OWASP ZAP baseline + full против запущенного DefectDojo
security/
  gate.py             # Security Gateway: агрегация SARIF, блок релиза, комментарий в PR
  dojo_upload.py      # выгрузка отчётов в отдельный DefectDojo (менеджмент)
.zap/
  rules.tsv           # подавление шума ZAP
  zap-auth.yaml       # шаблон аутентифицированного скана (зона роста)
docs/
  DEVSECOPS.md        # документация процесса + аналитика выбора инструментов
```

## Как поднять

1. Форкни DefectDojo и скопируй сюда каталоги `.github/`, `security/`, `.zap/`, `docs/`.
2. На выданной VPS подними **отдельный** инстанс DefectDojo как систему менеджмента
   (по официальной инструкции: `./dc-up.sh postgres-redis`). Создай в нём API-токен.
3. В настройках репозитория (Settings → Secrets and variables → Actions) добавь:
   - `DOJO_URL` — например `https://<vps-адрес>:8080`
   - `DOJO_TOKEN` — API v2 Key из профиля DefectDojo
   - (для аутентифицированного DAST) `ZAP_USER`, `ZAP_PASSWORD`
4. Запусти workflow `security` (на push/PR) и `dast` (вручную или по расписанию).
5. Проверь результаты в трёх местах: вкладка **Security** репозитория, комментарий
   в **Pull Request**, дашборд **DefectDojo**.

## Раскатка (этап 1 — облако/VPS)

- Пайплайн исполняется на GitHub-hosted раннерах по умолчанию.
- Чтобы задействовать выданную VPS как исполнителя, зарегистрируй на ней
  self-hosted runner (Settings → Actions → Runners) и замени в workflow
  `runs-on: ubuntu-latest` на `runs-on: self-hosted`.
- DAST-инстанс мишени и DefectDojo-менеджмент разворачиваются на VPS через
  их штатный `docker-compose`.

## Важные оговорки

- Версии сторонних GitHub Actions в workflow — ориентировочные. Перед сдачей
  зафиксируй их и по возможности пиннингуй к commit SHA (это отдельный плюс к защите).
- Строки `scan_type` в `dojo_upload.py` должны совпадать с парсерами твоей версии
  DefectDojo — сверься с `GET {DOJO_URL}/api/v2/test_types/`.
- Пороги гейта настраиваются переменной `GATE_FAIL_ON` (по умолчанию `HIGH`).
