---
title: OIDC
description: OpenID Connect (OIDC) SSO in DefectDojo Pro konfigurieren
weight: 17
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über einen generischen OpenID-Connect-Anbieter (OIDC). Open-Source-DefectDojo enthält kein SSO — siehe [Autorisierte Benutzer](/admin/user_management/os__authorized_users/) für die Open-Source-Zugriffskontrolle.

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OIDC Settings**.

![image](images/oidc_pro.png)

Füllen Sie das Formular aus:

1. **Endpoint** — die Basis-URL Ihres OIDC-Anbieters. Fügen Sie `/.well-known/openid-configuration` nicht hinzu.
2. **Client ID** — Ihre OIDC-Client-ID.
3. **Client Secret** — Ihr OIDC-Client-Secret.
4. Konfigurieren Sie optional **Claim Mapping** und **Group Mapping** — siehe unten.
5. Aktivieren Sie **Enable OIDC**.

Senden Sie das Formular ab. Auf der DefectDojo-Anmeldeseite erscheint dann eine Schaltfläche **Log In With OIDC**.

Verwenden Sie jederzeit **Validate Config**, um die Einstellungen zu überprüfen, ohne sie zu speichern. Dabei wird das Discovery-Dokument abgerufen, werden die Signaturschlüssel und der Aussteller überprüft, die exakte Redirect-URI angezeigt, die bei Ihrem Anbieter registriert werden muss, und Ihre Claim- und Gruppen-Zuordnungen mit den vom Anbieter angebotenen Claims abgeglichen.

## Claim Mapping

Jede Zeile ordnet einen **OIDC Claim** dem **DefectDojo-Feld** zu, das er befüllen soll. Verwenden Sie **Add Claim Mapping**, um weitere Zeilen hinzuzufügen, und das Papierkorb-Symbol, um eine zu entfernen.

![image](images/sso_oidc_claim_mapping.png)

Ein Feld ohne Zeile behält seinen Standard-Claim, daher ist dieser Abschnitt nur nötig, wenn Ihr Anbieter Dinge anders benennt. Die Standard-Claims sind:

| DefectDojo-Feld | Standard-Claim |
| --- | --- |
| Username | `preferred_username` |
| Email | `email` |
| First Name | `given_name` |
| Last Name | `family_name` |

Hinweise:

- Eine nicht konfigurierte Instanz startet mit diesen vier bereits ausgefüllten Zeilen, sodass Sie sehen können, was OIDC tut, bevor Sie etwas ändern.
- Derselbe Claim kann mehr als ein Feld befüllen. Jedes DefectDojo-Feld kann nur von einem Claim zugeordnet werden.
- Claims werden sowohl aus dem ID-Token als auch aus der Userinfo-Antwort gelesen, sodass ein Claim, den Ihr Anbieter nur in einem der beiden bereitstellt, trotzdem funktioniert.
- Fehlt ein zugeordneter Claim für einen bestimmten Benutzer oder ist er leer, behält das Feld seinen Standardwert, anstatt geleert zu werden.

## Group Mapping

DefectDojo kann die von Ihrem Anbieter gemeldeten Gruppen bei jeder Anmeldung in DefectDojo-Gruppen spiegeln. Aktivieren Sie **Enable Group Mapping**, um die Einstellungen anzuzeigen.

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** — der Claim, der die Gruppen des Benutzers enthält. **Die meisten Anbieter geben standardmäßig keinen aus** und benötigen einen explizit konfigurierten Mapper; in Keycloak fügen Sie beispielsweise dem Client einen *Group Membership*-Mapper hinzu. Beachten Sie, dass ein *User Realm Role*-Mapper Realm-**Rollen** sendet, keine Gruppen.
- **Group Limiter Regex Expression** — nur Gruppen, die diesem Ausdruck entsprechen, werden gespiegelt. Verwenden Sie `.*`, um alle zuzulassen.
- **Remove Stale Group Memberships** — wenn aktiviert, werden Mitgliedschaften in von OIDC bereitgestellten Gruppen, die der Anbieter nicht mehr meldet, bei der nächsten Anmeldung entfernt. Nur von OIDC erstellte Gruppen sind betroffen; von Hand zugewiesene Gruppen sowie von einem anderen Anbieter wie SAML bereitgestellte Gruppen werden nie angetastet.

Gruppen werden bei der ersten Verwendung erstellt und genau so benannt, wie sie der Anbieter meldet. Wenn Ihr Anbieter vollständige Gruppenpfade sendet (Keycloaks *Group Membership*-Mapper tut dies, wenn **Full group path** aktiviert ist), wird die DefectDojo-Gruppe `/Group A` genannt statt `Group A`. Deaktivieren Sie diese Option, wenn die Namen mit Gruppen übereinstimmen sollen, die von einem anderen Anbieter kommen, da Sie sonst am Ende zwei DefectDojo-Gruppen für dieselbe logische Gruppe haben.

Wenn das Group Mapping scheinbar nichts bewirkt, führen Sie **Validate Config** aus: Es zeigt an, ob der von Ihnen benannte Claim einer ist, den der Anbieter anbietet.
