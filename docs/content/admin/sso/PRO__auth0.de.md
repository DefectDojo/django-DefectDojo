---
title: Auth0
description: Konfigurieren Sie Auth0 SSO in DefectDojo Pro
weight: 3
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über Auth0. Open-Source-DefectDojo enthält kein SSO — siehe [Authorized Users](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in der Open-Source-Version.

## Voraussetzungen

Führen Sie die folgenden Schritte in Ihrem Auth0-Dashboard aus, bevor Sie DefectDojo konfigurieren:

1. Erstellen Sie eine neue Anwendung: **Applications > Create Application > Single Page Web Application**.

2. Konfigurieren Sie die Anwendung:
   - **Name:** `DefectDojo`
   - **Allowed Callback URLs:** `https://your-instance.cloud.defectdojo.com/complete/auth0/`

3. Notieren Sie sich die folgenden Werte — Sie benötigen sie in DefectDojo:
   - **Domain**
   - **Client ID**
   - **Client Secret**

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **Auth0** aus und füllen Sie das Formular aus:

- **Auth0 OAuth Key** — geben Sie Ihre **Client ID** ein
- **Auth0 OAuth Secret** — geben Sie Ihr **Client Secret** ein
- **Auth0 Domain** — geben Sie Ihre **Domain** ein

Aktivieren Sie **Enable Auth0 OAuth**, um der DefectDojo-Anmeldeseite eine Schaltfläche **Login With Auth0** hinzuzufügen.
