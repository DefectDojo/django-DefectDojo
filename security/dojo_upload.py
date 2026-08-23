#!/usr/bin/env python3
"""Выгрузка отчётов сканеров в DefectDojo через /api/v2/import-scan/.

Использует auto_create_context — продукт и engagement создаются по имени.
Переменные окружения: DOJO_URL, DOJO_TOKEN, DOJO_PRODUCT, DOJO_ENGAGEMENT.

Ключевое решение по scan_type:
  - Все SARIF-отчёты грузятся УНИВЕРСАЛЬНЫМ парсером "SARIF" (он валиден для
    Semgrep, Bandit, njsscan, Trivy, Checkov, Hadolint, Gitleaks — все умеют SARIF).
  - ZAP грузится своим НАТИВНЫМ парсером "ZAP Scan" (traditional-json отчёт).

Так исключён рассинхрон «файл SARIF, а парсер ждёт родной JSON».
Сверить доступные парсеры: GET {DOJO_URL}/api/v2/test_types/
"""
import argparse
import os
import sys

import requests

# report file -> DefectDojo scan_type
REPORTS = {
    "sast": {
        "reports/semgrep.sarif": "SARIF",
        "reports/bandit.sarif": "SARIF",
        "reports/njsscan.sarif": "SARIF",
        "reports/trivy-fs.sarif": "SARIF",
        "reports/trivy-config.sarif": "SARIF",
        "reports/checkov.sarif": "SARIF",
        "reports/hadolint.sarif": "SARIF",
        "reports/gitleaks.sarif": "SARIF",
    },
    "dast": {
        # нативный парсер ZAP ждёт traditional-json, НЕ sarif
        "reports/zap-baseline.json": "ZAP Scan",
        "reports/zap-full.json": "ZAP Scan",
        "reports/zap-auth-dojo.json": "ZAP Scan",
    },
}


def upload(url, token, product, engagement, file_path, scan_type):
    if not os.path.isfile(file_path):
        print(f"[dojo] нет файла {file_path} — пропуск")
        return
    endpoint = url.rstrip("/") + "/api/v2/import-scan/"
    data = {
        "scan_type": scan_type,
        "product_name": product,
        "product_type_name": "Research",
        "engagement_name": engagement,
        "auto_create_context": "true",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Low",
        "close_old_findings": "false",
    }
    with open(file_path, "rb") as fh:
        files = {"file": (os.path.basename(file_path), fh)}
        try:
            resp = requests.post(
                endpoint,
                headers={"Authorization": f"Token {token}"},
                data=data,
                files=files,
                timeout=120,
                verify=os.environ.get("DOJO_VERIFY_TLS", "true").lower() != "false",
            )
        except requests.RequestException as exc:
            print(f"[dojo] ошибка сети для {file_path}: {exc}")
            return
    if resp.status_code in (200, 201):
        print(f"[dojo] загружено {file_path} как '{scan_type}'")
    else:
        print(f"[dojo] {file_path}: HTTP {resp.status_code} — {resp.text[:300]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=list(REPORTS), required=True)
    args = ap.parse_args()

    url = os.environ.get("DOJO_URL")
    token = os.environ.get("DOJO_TOKEN")
    product = os.environ.get("DOJO_PRODUCT", "DefectDojo (self)")
    engagement = os.environ.get("DOJO_ENGAGEMENT", "CI")

    if not (url and token):
        print("[dojo] DOJO_URL/DOJO_TOKEN не заданы — выгрузка пропущена")
        sys.exit(0)

    for file_path, scan_type in REPORTS[args.stage].items():
        upload(url, token, product, engagement, file_path, scan_type)


if __name__ == "__main__":
    main()
