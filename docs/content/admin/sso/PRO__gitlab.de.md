---
title: GitLab
description: Konfigurieren Sie GitLab SSO in DefectDojo Pro
weight: 9
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über GitLab. Open-Source-DefectDojo enthält kein SSO — siehe [Authorized Users](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in der Open-Source-Version.

## Voraussetzungen

Führen Sie die folgenden Schritte in GitLab aus, bevor Sie DefectDojo konfigurieren:

1. Navigieren Sie zur Applications-Seite Ihres GitLab-Profils:
   - GitLab.com: `https://gitlab.com/profile/applications`
   - Selbst gehostet: `https://your-gitlab-host/profile/applications`

2. Erstellen Sie eine neue Anwendung:
   - **Name:** `DefectDojo`
   - **Redirect URI:** `https://your-dojo-instance.cloud.defectdojo.com/complete/gitlab/`

3. Notieren Sie sich **Application ID** und **Secret** der Anwendung.

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **GitLab** aus und füllen Sie das Formular aus:

- **GitLab OAuth Key** — geben Sie Ihre **Application ID** ein
- **GitLab OAuth Secret** — geben Sie Ihr **Secret** ein
- **GitLab API URL** — geben Sie die Basis-URL Ihrer GitLab-Instanz ein, z. B. `https://gitlab.com`

Aktivieren Sie **Enable GitLab OAuth** und senden Sie das Formular ab. Auf der Anmeldeseite erscheint eine Schaltfläche **Login With GitLab**.
