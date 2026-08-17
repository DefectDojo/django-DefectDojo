---
title: Azure Active Directory
description: Konfigurieren Sie Azure AD SSO und Gruppenzuordnung in DefectDojo Pro
weight: 5
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über Azure Active Directory (Azure AD), einschließlich der automatischen Synchronisierung von Benutzergruppen. Open-Source-DefectDojo enthält kein SSO — siehe [Authorized Users](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in der Open-Source-Version.

## Voraussetzungen

Führen Sie die folgenden Schritte im Azure-Portal aus, bevor Sie DefectDojo konfigurieren:

1. [Registrieren Sie eine neue App](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app) in Azure Active Directory.

2. Notieren Sie sich die folgenden Werte aus der registrierten App:
   - **Application (client) ID**
   - **Directory (tenant) ID**
   - Erstellen Sie unter **Certificates & Secrets** ein neues **Client Secret** und notieren Sie dessen Wert
   - **Application ID URI**

3. Fügen Sie unter **Authentication > Redirect URIs** eine URI vom Typ **Web** hinzu:
   `https://your-instance.cloud.defectdojo.com/complete/azuread-tenant-oauth2/`

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **Azure AD** aus und füllen Sie das Formular aus:

- **Azure AD OAuth Key** — geben Sie Ihre **Application (client) ID** ein
- **Azure AD OAuth Secret** — geben Sie Ihr **Client Secret** ein
- **Azure AD Resource** — Standardwert ist `https://graph.microsoft.com/`. Dies ist die URI, über die DefectDojo zusätzliche Informationen (wie Gruppennamen) aus der [Microsoft Graph Web API](https://docs.azure.cn/en-us/entra/identity-platform/security-best-practices-for-app-registration#application-id-uri) liest. Ändern Sie dies nur, wenn Ihre Gruppennamen auf einer anderen API-Ressource gespeichert sind.
- **Azure AD Tenant ID** — geben Sie Ihre **Directory (tenant) ID** ein
- **Azure AD Groups Filter** — geben Sie optional einen Regex-String ein, um einzuschränken, welche Benutzergruppen importiert werden (siehe [Group Mapping](#group-mapping) unten)

Aktivieren Sie **Enable Azure AD OAuth** und senden Sie das Formular ab. Auf der Anmeldeseite erscheint eine Schaltfläche **Login With Azure AD**.

## Group Mapping

Group Mapping ermöglicht es DefectDojo, die [Benutzergruppen](../../user_management/create_user_group/)-Mitgliedschaft aus Azure AD zu importieren. Benutzergruppen steuern in DefectDojo den Zugriff auf Produkte und Produkttypen über [RBAC](../../user_management/set_user_permissions/).

Aktivieren Sie **Enable Azure AD OAuth Grouping**, um diese Funktion zu aktivieren. Bei der Anmeldung gleicht DefectDojo die Azure-AD-Gruppen des Benutzers mit bestehenden DefectDojo-Gruppen ab. Gruppen, die in DefectDojo nicht gefunden werden, werden automatisch erstellt.

Um nur eine Teilmenge der Gruppen zu importieren, geben Sie einen Regex in das Feld **Azure AD Groups Filter** ein. Zum Beispiel:
- `^team-.*` — entspricht jeder Gruppe, die mit `team-` beginnt
- `teamA|teamB|groupC` — entspricht bestimmten benannten Gruppen

### Azure AD für das Senden von Gruppen konfigurieren

Das Azure-AD-Token muss so konfiguriert werden, dass es Gruppen-IDs enthält. Ohne dies sind im Token keine Gruppeninformationen vorhanden.

So konfigurieren Sie dies:
1. Fügen Sie in der Azure-AD-Token-Konfiguration einen [Group Claim](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims) hinzu. Wählen Sie im Zweifelsfall, welcher Gruppentyp ausgewählt werden soll, **All Groups**.
2. Aktivieren Sie **nicht** die Option **Emit groups as role claims**.
3. Aktualisieren Sie die API-Berechtigungen der Anwendung so, dass sie `GroupMember.Read.All` oder `Group.Read.All` enthalten. `GroupMember.Read.All` wird empfohlen, da es weniger Berechtigungen gewährt.

### Group Cleaning

Wenn **Enable Azure AD OAuth Group Cleaning** aktiviert ist, werden über die Azure-AD-Synchronisierung erstellte DefectDojo-Gruppen automatisch entfernt, sobald sie keine Mitglieder mehr haben. Wird ein Benutzer in Azure AD aus einer Gruppe entfernt, wird er auch aus der entsprechenden Gruppe in DefectDojo entfernt.
