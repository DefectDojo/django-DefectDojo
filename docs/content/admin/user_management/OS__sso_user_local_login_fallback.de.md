---
title: Login für SSO-Benutzer wieder aktivieren
description: Vergeben Sie über SSO bereitgestellten Benutzern ein lokales Passwort,
  nachdem Sie zu Open Source gewechselt sind, wo SSO eine reine Pro-Funktion ist
audience: opensource
weight: 2
---

## Wann das relevant ist

SSO (SAML, OIDC, OAuth) ist eine Funktion von [DefectDojo Pro](https://defectdojo.com). Wenn Sie auf Open-Source-DefectDojo 3.x aktualisieren (oder anderweitig von Pro wegwechseln), werden die SSO-Login-Optionen entfernt, und Benutzer, die über SSO bereitgestellt wurden, können sich nicht mehr anmelden. Ihre Konten haben nie ein lokales Passwort erhalten, und die Benutzeroberfläche und die API lassen Sie kein Passwort für sie festlegen: DefectDojo erkennt sie als SSO-Konten und blockiert die Änderung.

Sie müssen diese Benutzer **nicht** löschen und neu anlegen (wodurch deren Verlauf, Berechtigungen und Objekteigentümerschaft verloren gingen). Vergeben Sie stattdessen für jedes Konto im Backend ein lokales Passwort und erzwingen Sie beim nächsten Login einen Passwort-Reset.

Hintergrundinformationen dazu, dass SSO nur in Pro verfügbar ist, finden Sie im [SSO-Abschnitt](/admin/sso/) und in den [Upgrade-Hinweisen zu 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only).

## Warum das passiert

Open-Source-DefectDojo authentifiziert ausschließlich gegen die lokale Benutzerdatenbank von Django. Ob ein Konto ein „SSO-Benutzer“ ist, wird ausschließlich daran entschieden, ob das Konto ein nutzbares Passwort hat. Über SSO bereitgestellte Konten wurden mit einem *nicht nutzbaren* Passwort erstellt, daher:

* schlägt der lokale Login fehl (es gibt kein Passwort zum Prüfen), und
* wird das Bedienelement **Force password reset** in der Benutzeroberfläche und der API blockiert, mit einer Meldung, dass der Benutzer über SSO autorisiert ist.

Das Setzen eines echten Passworts hebt beide Bedingungen gleichzeitig auf: Das Konto kann sich lokal anmelden, und das Flag für den erzwungenen Reset kann gesetzt werden.

## Der Workaround

Führen Sie diese Schritte über die Django-Shell im Container `uwsgi` aus:

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### Beispiel für einen einzelnen Benutzer

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## Was der Benutzer als Nächstes tut

Übermitteln Sie jedem Benutzer das temporäre Passwort außerhalb des Systems (E-Mail, Team-Chat, oder wie Sie sonst Geheimnisse teilen). Beim nächsten Login leitet DefectDojo den Benutzer auf die Seite **Change Password** um und lässt ihn nirgendwo anders hin, bis er sein eigenes Passwort festgelegt hat. Das Flag für den erzwungenen Reset wird danach automatisch zurückgesetzt.

Wenn auf Ihrer Instanz der Ablauf „I forgot my password“ aktiviert ist (`DD_FORGOT_PASSWORD`, standardmäßig aktiv) und E-Mail konfiguriert ist, können Benutzer stattdessen den Link **I forgot my password** auf der Login-Seite verwenden, sobald ihr Konto ein nutzbares Passwort hat, und ein Passwort festlegen, ohne das temporäre zu benötigen.

## Hinweise

* **Kubernetes:** Führen Sie die Shell stattdessen im Django-Pod aus, z. B. `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell` (passen Sie Deployment- und Containernamen an Ihr Release an).
* Wählen Sie ein starkes Wegwerf-Passwort. Da `force_password_reset = True` gesetzt ist, kann der Benutzer es nicht behalten – es muss also nur einen Login überstehen.
* Behalten Sie mindestens ein funktionierendes lokales Admin-Konto, damit Sie niemals ausgesperrt werden.
