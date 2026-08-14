---
title: Einen neuen Benutzer erstellen
description: So binden Sie einen neuen Benutzer in Ihre DefectDojo-Instanz ein
audience: pro
weight: 1
---

Diese Seite beschreibt den empfohlenen Onboarding-Workflow zum Hinzufügen neuer Benutzer zu einer DefectDojo-Instanz.  DefectDojo-Benutzer können sowohl als reguläre, von Menschen bediente Konten als auch als Servicekonten verwendet werden.

Der Administrator, der das Konto erstellt, ist dafür verantwortlich, dem neuen Benutzer die anfänglichen Zugangsdaten (Benutzername und Passwort) zu übermitteln.

## Empfohlener Workflow

1. **Erstellen Sie das Benutzerkonto** in DefectDojo (nur Superuser):
   * Navigieren Sie zu **👤 Benutzer → ➕ Neuer Benutzer**.
   * Geben Sie den Namen und die E-Mail-Adresse des neuen Benutzers ein.
   * Legen Sie ein temporäres Passwort fest.
   * Senden Sie das Formular ab.

2. **Weisen Sie passende Berechtigungen zu** — Produkt-/Produkttyp-Mitgliedschaft, Konfigurationsberechtigungen, globale Rolle oder Superuser-Status. Details finden Sie unter [Berechtigungen eines Benutzers festlegen](../set_user_permissions/). Ein neuer Benutzer ohne Zuweisungen kann keine Produkte oder Befunde sehen.

3. **Senden Sie die Zugangsdaten out-of-band an den neuen Benutzer** (per E-Mail, über das Chat-Tool Ihres Teams oder auf die Art, wie Sie normalerweise Geheimnisse teilen). Fügen Sie hinzu:
   * Die URL der DefectDojo-Instanz.
   * Den Benutzernamen (in der Regel die E-Mail-Adresse).
   * Das soeben festgelegte temporäre Passwort.
   * Einen Hinweis, dass sie beim ersten Login das Passwort ändern und MFA aktivieren sollten (falls Ihre Instanz MFA verwendet).

4. **Der neue Benutzer meldet sich an und wechselt die Zugangsdaten.** Dabei kann er entweder:
   * sich mit dem temporären Passwort anmelden und es anschließend über das Profilmenü ändern, oder
   * den Link **I forgot my password** auf der Login-Seite verwenden, um direkt ein Passwort festzulegen, ohne das temporäre zu verwenden. Das temporäre Passwort ist weiterhin erforderlich, damit der anfängliche Kontodatensatz existiert, aber der Benutzer muss es sich nicht merken, wenn er den Passwort-Zurücksetzen-Ablauf nutzt.

5. **Der neue Benutzer konfiguriert MFA** über sein Profilmenü. Wir empfehlen dringend, MFA für alle Benutzer auf Instanzen zu verlangen, die nicht hinter SSO liegen.

## SSO-Benutzer

Wenn Ihre Instanz mit [SSO](../configure_sso/) konfiguriert ist, unterscheidet sich der Workflow — Benutzer werden in der Regel beim ersten Login durch den Identity Provider erstellt, und Sie müssen ihnen anschließend nur noch Gruppenmitgliedschaften oder Rollen zuweisen.

## Wiederherstellung nach einem verlorenen MFA-Token

Wenn ein Benutzer den Zugriff auf sein MFA-Gerät verliert, kann er sich mit einem der bei der Registrierung ausgestellten Wiederherstellungscodes anmelden. Sind auch diese nicht mehr verfügbar, kann ein Administrator mit Serverzugriff MFA für das Konto mit `python manage.py remove_mfa --username <username>` zurücksetzen, woraufhin sich der Benutzer mit seinem Passwort anmeldet und sich erneut registriert — seine Berechtigungen und seine Historie bleiben erhalten, sodass kein Ersatzkonto erstellt werden muss.

Die vollständigen Wiederherstellungsoptionen finden Sie unter [Multi-Faktor-Authentifizierung](../pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device); beachten Sie außerdem, dass der Zugriff auf den **Cloud Manager** selbst eine separate Angelegenheit ist — siehe den [Leitfaden zur Fehlerbehebung bei der Konnektivität](/get_started/pro/cloud/connectivity-troubleshooting/#ive-lost-access-to-my-mfa-codes).
