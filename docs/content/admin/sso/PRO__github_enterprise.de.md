---
title: GitHub Enterprise
description: Konfigurieren Sie GitHub Enterprise SSO in DefectDojo Pro
weight: 7
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über GitHub Enterprise. Open-Source-DefectDojo enthält kein SSO — siehe [Authorized Users](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in der Open-Source-Version.

## Voraussetzungen

Führen Sie die folgenden Schritte in GitHub Enterprise aus, bevor Sie DefectDojo konfigurieren:

1. [Erstellen Sie eine neue OAuth-App](https://docs.github.com/en/enterprise-server/developers/apps/building-oauth-apps/creating-an-oauth-app) in Ihrem GitHub Enterprise Server.

2. Wählen Sie einen Namen für die Anwendung, z. B. `DefectDojo`.

3. Legen Sie die **Redirect URI** fest:
   `https://your-instance.cloud.defectdojo.com/complete/github-enterprise/`

4. Notieren Sie sich **Client ID** und **Client Secret** der App.

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **GitHub Enterprise** aus und füllen Sie das Formular aus:

- **GitHub Enterprise OAuth Key** — geben Sie Ihre **Client ID** ein
- **GitHub Enterprise OAuth Secret** — geben Sie Ihr **Client Secret** ein
- **GitHub Enterprise URL** — geben Sie die GitHub-URL Ihrer Organisation ein, z. B. `https://github.yourcompany.com/`
- **GitHub Enterprise API URL** — geben Sie die GitHub-API-URL Ihrer Organisation ein, z. B. `https://github.yourcompany.com/api/v3/`

Aktivieren Sie **Enable GitHub Enterprise OAuth** und senden Sie das Formular ab. Auf der Anmeldeseite erscheint eine Schaltfläche **Login With GitHub**.
