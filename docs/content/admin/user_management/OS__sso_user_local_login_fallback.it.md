---
title: Riattivare l'accesso per gli utenti SSO
description: Assegna una password locale agli utenti creati tramite SSO dopo il passaggio
  a Open Source, dove SSO è una funzionalità disponibile solo in Pro
audience: opensource
weight: 2
---

## Quando si applica

SSO (SAML, OIDC, OAuth) è una funzionalità di [DefectDojo Pro](https://defectdojo.com). Se esegui l'aggiornamento a DefectDojo open source 3.x (o in altro modo abbandoni Pro), le opzioni di accesso SSO vengono rimosse e gli utenti creati tramite SSO non possono più accedere. Ai loro account non è mai stata assegnata una password locale, e l'interfaccia utente e l'API non ti permetteranno di impostarne una: DefectDojo li rileva come account SSO e blocca la modifica.

**Non** è necessario eliminare e ricreare questi utenti (il che farebbe perdere la loro cronologia, i permessi e la proprietà degli oggetti). Assegna invece a ciascun account una password locale sul backend e forza una reimpostazione della password al successivo accesso.

Per maggiori informazioni sul fatto che SSO sia disponibile solo in Pro, consulta la [sezione SSO](/admin/sso/) e le [note di aggiornamento della 3.0](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only).

## Perché succede

DefectDojo open source si autentica solo rispetto al database utenti locale di Django. Decide se un account è un "utente SSO" esclusivamente in base al fatto che l'account abbia una password utilizzabile. Gli account creati tramite SSO sono stati creati con una password *non utilizzabile*, quindi:

* l'accesso locale fallisce (non c'è alcuna password da verificare), e
* il controllo **Force password reset** nell'interfaccia utente e nell'API è bloccato, con un messaggio che indica che l'utente è autorizzato tramite SSO.

Impostare una password reale risolve entrambe le condizioni contemporaneamente: l'account può accedere localmente e il flag di reimpostazione forzata diventa impostabile.

## La soluzione alternativa

Esegui questi passaggi dalla shell Django all'interno del container `uwsgi`:

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### Esempio per un singolo utente

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## Cosa fa l'utente successivamente

Consegna la password temporanea a ciascun utente fuori banda (email, la chat del tuo team, o comunque tu condivida normalmente i segreti). Al successivo accesso, DefectDojo li reindirizza alla pagina **Change Password** e non permetterà loro di andare altrove finché non impostano la propria password. Il flag di reimpostazione forzata si azzera automaticamente una volta fatto.

Se la tua istanza ha il flusso "I forgot my password" abilitato (`DD_FORGOT_PASSWORD`, attivo per impostazione predefinita) e l'email configurata, gli utenti possono invece usare il link **I forgot my password** nella pagina di accesso una volta che il loro account ha una password utilizzabile, e impostare una password senza bisogno di quella temporanea.

## Note

* **Kubernetes:** esegui invece la shell nel pod Django, ad esempio `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell` (adatta i nomi di deployment e container alla tua release).
* Scegli una password robusta e usa e getta. Con `force_password_reset = True` l'utente non può mantenerla, quindi deve solo sopravvivere a un accesso.
* Mantieni almeno un account amministratore locale funzionante, così da non restare mai bloccato fuori.
