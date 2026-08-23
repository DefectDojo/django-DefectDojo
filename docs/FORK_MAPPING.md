# Привязка к раскладке форка DefectDojo

Пайплайн настроен под стандартную структуру upstream-репозитория DefectDojo.
Перед запуском сверь пункты ниже со своим форком и поправь при расхождении.

## Предполагаемая раскладка

| Что | Значение по умолчанию | Где используется |
|---|---|---|
| Dockerfile'ы | `Dockerfile.django-alpine`, `Dockerfile.nginx-alpine`, `*-debian`, `Dockerfile.integration-tests-debian` | Hadolint (по маске, менять не нужно) |
| Подъём сервиса | `./dc-build.sh` + `./dc-up-d.sh postgres-redis` | `dast.yml` |
| URL мишени | `http://localhost:8080` | `dast.yml`, `.zap/zap-auth.yaml` |
| Страница логина | `/login`, поле CSRF `csrfmiddlewaretoken` | browser-auth ZAP (CSRF решается автоматически) |
| Языки | Python, JavaScript/Vue, SCSS, Dockerfile, shell | матрица покрытия SAST |

## Чек-лист перед сдачей

1. **Dockerfile'ы.** Hadolint берёт все файлы по маске `Dockerfile*` через `git ls-files` —
   ручной правки не требует. Убедись, что твои Dockerfile попадают в маску.
2. **Порт.** Если nginx опубликован не на `8080`, поменяй `TARGET_URL` в `dast.yml` и
   `urls`/`loginPageUrl` в `.zap/zap-auth.yaml`.
3. **scan_type.** Все SARIF грузятся парсером `SARIF`, ZAP — `ZAP Scan`. Сверь, что оба
   парсера есть в твоей версии DefectDojo: `GET {DOJO_URL}/api/v2/test_types/`.
4. **Тестовый пользователь ZAP.** Заведи `zaptester` в мишени и положи `ZAP_USER`/`ZAP_PASSWORD`
   в секреты репозитория.
5. **Профиль БД.** Если compose стартует иначе (другой профиль/скрипт) — поправь шаг
   «Build & start DefectDojo» в `dast.yml`.
6. **Версии Actions.** Зафиксируй теги (лучше — commit SHA) в обоих workflow.

## Что править НЕ нужно

- `gate.py` — универсален, работает с любыми SARIF в каталоге `reports/`.
- Матрица покрытия SAST — Semgrep + Bandit + njsscan + Trivy покрывают все языки форка.
