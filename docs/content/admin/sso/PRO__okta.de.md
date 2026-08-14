---
title: Okta
description: Okta SSO in DefectDojo Pro konfigurieren
weight: 15
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über Okta. Open-Source-DefectDojo enthält kein SSO — siehe [Autorisierte Benutzer](/admin/user_management/os__authorized_users/) für die Open-Source-Zugriffskontrolle.

## Voraussetzungen

Führen Sie die folgenden Schritte in Okta aus, bevor Sie DefectDojo konfigurieren:

1. Melden Sie sich bei [Okta](https://www.okta.com/developer/signup/) an oder erstellen Sie ein Konto.

2. Gehen Sie zu **Applications** und klicken Sie auf **Add Application**.

   ![image](images/okta_1.png)

3. Wählen Sie **Web Applications**.

   ![image](images/okta_2.png)

4. Fügen Sie unter **Login Redirect URLs** Ihre DefectDojo-Callback-URL hinzu. Aktivieren Sie außerdem das Kontrollkästchen **Implicit**.

   ![image](images/okta_3.png)

5. Klicken Sie auf **Done**.

6. Notieren Sie sich im **Dashboard** die **Org-URL**.

   ![image](images/okta_4.png)

7. Öffnen Sie die neu erstellte Anwendung und notieren Sie sich **Client ID** und **Client Secret**.

   ![image](images/okta_5.png)

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **Okta** und füllen Sie das Formular aus:

- **Okta OAuth Key** — geben Sie Ihre **Client ID** ein
- **Okta OAuth Secret** — geben Sie Ihr **Client Secret** ein
- **Okta Tenant ID** — geben Sie Ihre Org-URL im Format `https://your-org-url/oauth2` ein

Aktivieren Sie **Enable Okta OAuth** und senden Sie das Formular ab. Auf der Anmeldeseite erscheint dann eine Schaltfläche **Login With Okta**.
