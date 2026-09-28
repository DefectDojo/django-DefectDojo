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

2. **Weisen Sie passende Berechtigungen zu** – Produkt-/Produkttyp-Mitgliedschaft, Configuration Permissions, Global Role oder Superuser-Status. Details finden Sie unter [Berechtigungen eines Benutzers festlegen](../set_user_permissions/). Ein neuer Benutzer ohne Zuweisungen kann keine Produkte oder Befunde sehen.

3. **Senden Sie die Zugangsdaten außerhalb des Systems (out-of-band) an den neuen Benutzer** (per E-Mail, über das Chat-Tool Ihres Teams oder wie Sie sonst Geheimnisse teilen). Fügen Sie Folgendes bei:
   * Die URL der DefectDojo-Instanz.
   * Den Benutzernamen (in der Regel die E-Mail-Adresse).
   * Das gerade festgelegte temporäre Passwort.
   * Einen Hinweis, dass der Benutzer beim ersten Login das Passwort ändern und MFA aktivieren sollte (falls Ihre Instanz MFA verwendet).

4. **Der neue Benutzer meldet sich an und ändert die Zugangsdaten.** Er kann entweder:
   * sich mit dem temporären Passwort anmelden und es anschließend über sein Profilmenü ändern, oder
   * über den Link **I forgot my password** auf der Login-Seite direkt ein neues Passwort festlegen, ohne das temporäre zu verwenden. Das temporäre Passwort wird weiterhin benötigt, damit der anfängliche Kontodatensatz existiert, aber der Benutzer muss es sich nicht merken, wenn er den Passwort-Reset-Ablauf nutzt.

5. **Der neue Benutzer richtet MFA ein** über sein Profilmenü. Wir empfehlen dringend, MFA für alle Benutzer auf Instanzen zu verlangen, die nicht hinter SSO liegen.

## SSO-Benutzer

Wenn Ihre Instanz mit [SSO](../configure_sso/) konfiguriert ist, sieht der Ablauf anders aus – Benutzer werden in der Regel beim ersten Login über den Identity Provider erstellt, und Sie müssen ihnen anschließend nur noch Gruppenmitgliedschaften oder Rollen zuweisen.

Wenn Sie zu Open-Source-DefectDojo gewechselt sind (wo SSO nur in Pro verfügbar ist) und sich bestehende SSO-Benutzer nicht mehr anmelden können, lesen Sie [Login für SSO-Benutzer wieder aktivieren](../os__sso_user_local_login_fallback/).

## Wiederherstellung nach einem verlorenen MFA-Token

Wenn ein Benutzer den Zugriff auf sein MFA-Gerät verliert, lesen Sie den [Abschnitt zur MFA-Wiederherstellung](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes) im Leitfaden zur Fehlerbehebung bei der Konnektivität. Derzeit gibt es keine Möglichkeit, MFA ohne einen MFA-Code von einem Konto zu entfernen – der Workaround besteht darin, ein neues Konto für den Benutzer zu erstellen und dieselben Berechtigungen erneut zu vergeben.
