---
title: LDAP Authentication
description: Konfigurieren Sie die LDAP-Authentifizierung in DefectDojo Pro
weight: 20
audience: pro
aliases:
- /en/open_source/ldap-authentication
---

DefectDojo Pro unterstützt die LDAP-Authentifizierung über die Benutzeroberfläche der **Enterprise Settings** — es sind keine benutzerdefinierten Docker-Images oder Konfigurationsdateien erforderlich.

Anders als die übrigen Anbieter auf dieser Seite basiert LDAP nicht auf einem Redirect-Flow. Benutzer melden sich über das übliche DefectDojo-Formular für Benutzername und Passwort an, und ihre Anmeldedaten werden gegen Ihr Verzeichnis geprüft. Es gibt keine zusätzliche Anmeldeschaltfläche.

## Konfiguration

Öffnen Sie **Enterprise Settings > LDAP Settings**.

![image](images/sso_ldap_settings.png)

1. **Server URI** — das Verzeichnis, mit dem eine Verbindung hergestellt wird, z. B. `ldaps://ldap.example.com:636`.
   Bevorzugen Sie `ldaps://`. Falls Sie ein einfaches `ldap://` verwenden müssen, aktivieren Sie unten **Use StartTLS**, damit die Verbindung verschlüsselt wird, bevor Anmeldedaten gesendet werden.
2. **Bind DN** — der Distinguished Name des Dienstkontos, das zur Suche nach Benutzern verwendet wird.
   Lassen Sie das Feld für einen anonymen Bind leer.
3. **Bind Password** — das Passwort für dieses Dienstkonto. Der gespeicherte Wert wird niemals an den Browser zurückgegeben; lassen Sie das Feld leer, um das bereits gespeicherte Passwort beizubehalten.
4. **User Search Base** — der DN, unterhalb dessen nach Benutzereinträgen gesucht wird, z. B.
   `ou=people,dc=example,dc=com`.
5. **User Search Filter** — der Filter, mit dem der Benutzer gefunden wird. Er **muss** den literalen Platzhalter `%(user)s` enthalten, der durch den eingegebenen Benutzernamen ersetzt wird. Übliche Werte sind `(uid=%(user)s)` für OpenLDAP und `(sAMAccountName=%(user)s)` für Active Directory.
6. **User Attribute Mapping** — siehe unten.
7. Aktivieren Sie **Enable LDAP**, um es zu aktivieren.

Verwenden Sie **Validate Config**, um die Einstellungen zu prüfen, ohne sie zu speichern. Es meldet, ob die Einstellungen vollständig sind, ob der Server erreichbar ist, ob der Bind erfolgreich ist, ob sich die Such-Basen auflösen lassen und ob die Attributzuordnung brauchbar erscheint.

## User Attribute Mapping

Jede Zeile ordnet ein **LDAP Attribute** dem **DefectDojo Field** zu, das es befüllen soll. Verwenden Sie **Add Attribute Mapping** für weitere Zeilen und das Papierkorbsymbol, um eine zu entfernen.

![image](images/sso_ldap_attribute_mapping.png)

- **LDAP Attribute** ist Freitext und muss dem Attribut entsprechen, das Ihr Verzeichnis tatsächlich zurückgibt — zum Beispiel `uid`, `givenName`, `sn`, `mail` bei OpenLDAP oder `sAMAccountName`, `givenName`, `sn`, `mail` bei Active Directory.
- **DefectDojo Field** wird aus einer Liste ausgewählt: **Username**, **First Name**, **Last Name** und **Email**.
- Es wird dringend empfohlen, ein Attribut auf **Email** zu mappen: DefectDojo verwendet die E-Mail-Adresse für Benachrichtigungen.
- Dasselbe Attribut kann mehr als ein Feld befüllen. Jedes DefectDojo-Feld kann jedoch nur von einem einzigen Attribut befüllt werden.
- Ohne jegliche Zuordnung werden Konten ohne Namen oder E-Mail-Adresse erstellt.

**Always Update User** legt fest, wann die Zuordnung angewendet wird. Ist die Option aktiviert (Standard), werden die zugeordneten Attribute bei jeder Anmeldung aus dem Verzeichnis aktualisiert, sodass eine Namens- oder E-Mail-Änderung in LDAP auch DefectDojo erreicht. Ist sie deaktiviert, werden sie nur bei der erstmaligen Erstellung des Kontos angewendet.

## Group Mapping

DefectDojo kann die LDAP-Gruppen eines Benutzers bei der Anmeldung in DefectDojo-Gruppen spiegeln. Aktivieren Sie **Enable Group Mapping**, um die Einstellungen anzuzeigen.

![image](images/sso_ldap_group_mapping.png)

- **Group Search Base** — der DN, unterhalb dessen nach Gruppeneinträgen gesucht wird, z. B.
  `ou=groups,dc=example,dc=com`. Erforderlich, wenn Group Mapping aktiviert ist.
- **Group Type** — wie Ihr Verzeichnis Mitgliedschaften modelliert. Wählen Sie **groupOfNames** für OpenLDAP und Active Directory, **groupOfUniqueNames** oder **posixGroup**.
- **Group Limiter Regex Expression** — nur Gruppen, deren Name diesem Ausdruck entspricht, werden gespiegelt. Verwenden Sie `.*`, um alle zuzulassen, oder ein Präfix wie `^dd-`, um nur die Gruppen zu spiegeln, die DefectDojo verwalten soll.

Gruppen werden bei der ersten Verwendung erstellt, falls sie noch nicht existieren. Eine neu erstellte Gruppe hat keine Berechtigungen, bis ein Superuser diese konfiguriert — siehe
[User Groups](../../user_management/create_user_group/).

## Weitere Optionen

* **Use StartTLS** — verschlüsselt eine einfache `ldap://`-Verbindung mit TLS, bevor der Bind erfolgt. Nicht erforderlich, wenn die URI bereits `ldaps://` lautet.
* **Always Update User** — aktualisiert die zugeordneten Attribute bei jeder Anmeldung aus dem Verzeichnis.

## Fehlerbehebung

Führen Sie zuerst **Validate Config** aus — meist wird das Problem direkt benannt. Darüber hinaus:

**Jede Anmeldung schlägt fehl, obwohl das Verzeichnis erreichbar ist.** Prüfen Sie, ob der **User Search Filter** `%(user)s` enthält und ob das darin enthaltene Attribut dem entspricht, was Benutzer tatsächlich eingeben. Ein Filter wie `(uid=%(user)s)` passt niemals, wenn sich Ihre Benutzer mit einem Active-Directory-`sAMAccountName` anmelden.

**Anmeldungen gelingen, aber Konten haben keinen Namen oder keine E-Mail-Adresse.** Das **User Attribute Mapping** ist leer, oder die LDAP-Attributnamen auf der linken Seite entsprechen nicht dem, was Ihr Verzeichnis zurückgibt.

**Ein Name wurde in LDAP geändert, aber nicht in DefectDojo.** **Always Update User** ist deaktiviert, sodass die Zuordnung nur bei der Erstellung des Kontos angewendet wurde.

**Anmeldeversuche hängen oder sind langsam.** Verbindungen und Suchvorgänge sind durch ein Timeout begrenzt, sodass ein nicht erreichbares Verzeichnis fehlschlägt, statt unbegrenzt zu blockieren. Prüfen Sie **Server Reachability** in **Validate Config** und stellen Sie sicher, dass der Port vom DefectDojo-Host aus erreichbar ist.
