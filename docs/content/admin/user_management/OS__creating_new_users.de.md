---
title: Einen neuen Benutzer erstellen
description: Wie Sie einen neuen Benutzer in Ihrer DefectDojo-Instanz onboarden
audience: opensource
weight: 1
---

Diese Seite beschreibt den empfohlenen Onboarding-Ablauf für das Hinzufügen neuer Benutzer zu einer DefectDojo-Instanz. DefectDojo-Benutzer können sowohl als reguläre, von Menschen bediente Konten als auch als Service-Konten verwendet werden.

Der Admin, der das Konto erstellt, ist dafür verantwortlich, die anfänglichen Zugangsdaten (Benutzername und Passwort) an den neuen Benutzer zu übermitteln.

## Empfohlener Ablauf

1. **Erstellen Sie das Benutzerkonto** in DefectDojo (nur Superuser):
   * Navigieren Sie zu **👤 Users → Users**, um die Tabelle „Alle Benutzer“ zu öffnen.
   * Klicken Sie auf das 🛠️-Symbol (gekreuzter Schraubenschlüssel und Schraubenzieher).
   * Geben Sie den Namen und die E-Mail-Adresse des neuen Benutzers ein.
   * Legen Sie ein temporäres Passwort fest.
   * Senden Sie das Formular ab.

2. **Gewähren Sie Zugriff** nach Bedarf. Fügen Sie den Benutzer zur Authorized-Users-Liste jedes benötigten Assets oder jeder benötigten Organization hinzu, oder markieren Sie ihn als Staff oder Superuser. Details finden Sie unter [Open-Source-Berechtigungen](../os__authorized_users/). Ein neuer Benutzer ohne Zuweisungen kann keine Assets oder Befunde sehen.

3. **Senden Sie die Zugangsdaten außerhalb des Systems (out-of-band) an den neuen Benutzer** (per E-Mail, über das Chat-Tool Ihres Teams oder wie Sie sonst Geheimnisse teilen). Fügen Sie Folgendes bei:
   * Die URL der DefectDojo-Instanz.
   * Den Benutzernamen (in der Regel die E-Mail-Adresse).
   * Das gerade festgelegte temporäre Passwort.
   * Einen Hinweis, dass der Benutzer beim ersten Login das Passwort ändern sollte.

4. **Der neue Benutzer meldet sich an und ändert die Zugangsdaten.** Er kann entweder:
   * sich mit dem temporären Passwort anmelden und es anschließend über sein Profilmenü ändern, oder
   * über den Link **I forgot my password** auf der Login-Seite direkt ein neues Passwort festlegen, ohne das temporäre zu verwenden. Das temporäre Passwort wird weiterhin benötigt, damit der anfängliche Kontodatensatz existiert, aber der Benutzer muss es sich nicht merken, wenn er den Passwort-Reset-Ablauf nutzt.

## Benutzer, die sich mit SSO angemeldet haben

Open-Source-DefectDojo unterstützt ausschließlich lokale Konten. SSO (SAML, OIDC, OAuth), LDAP und MFA sind in [DefectDojo Pro](/admin/sso/) verfügbar.

Wenn Sie auf Open-Source-DefectDojo 3.x umgestellt haben und sich bestehende SSO-Benutzer nicht mehr anmelden können, lesen Sie [Login für SSO-Benutzer wieder aktivieren](../os__sso_user_local_login_fallback/).
