---
title: Google Auth
description: Konfigurieren Sie Google OAuth in DefectDojo Pro
weight: 11
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über Google-Konten. Neue Benutzer werden bei der ersten Anmeldung automatisch erstellt, sofern sie noch nicht existieren. Bestehende DefectDojo-Benutzer werden anhand des Benutzernamens (dem Teil vor dem `@` in ihrer Google-E-Mail-Adresse) mit Google-Konten abgeglichen. Open-Source-DefectDojo enthält kein SSO — siehe [Authorized Users](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in der Open-Source-Version.

## Voraussetzungen

Führen Sie die folgenden Schritte in der Google Cloud Console aus, bevor Sie DefectDojo konfigurieren:

1. Melden Sie sich bei der [Google Developers Console](https://console.developers.google.com) an.

2. Gehen Sie zu **Credentials > Create Credentials > OAuth Client ID**.

   ![image](images/google_1.png)

3. Wählen Sie **Web Application** aus und vergeben Sie einen aussagekräftigen Namen (z. B. `DefectDojo`).

4. Fügen Sie unter **Authorized Redirect URIs** Folgendes hinzu:
   `https://your-instance.cloud.defectdojo.com/complete/google-oauth2/`

5. Notieren Sie sich **Client ID** und **Client Secret Key**.

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **Google** aus und füllen Sie das Formular aus:

- **Google OAuth Key** — geben Sie Ihre **Client ID** ein
- **Google OAuth Secret** — geben Sie Ihren **Client Secret Key** ein
- **Whitelisted Domains** — geben Sie die Domain Ihrer Organisation ein (z. B. `yourcompany.com`), um jedem Benutzer mit dieser Domain die Anmeldung zu erlauben
- **Whitelisted Email Addresses** — geben Sie alternativ bestimmte zulässige E-Mail-Adressen ein (z. B. `user1@yourcompany.com, user2@yourcompany.com`)

Sie müssen mindestens eine zugelassene Domain oder E-Mail-Adresse festlegen, sonst kann sich kein Benutzer über Google anmelden.

Aktivieren Sie **Enable Google OAuth** und senden Sie das Formular ab. Auf der Anmeldeseite erscheint eine Schaltfläche **Login With Google**.
