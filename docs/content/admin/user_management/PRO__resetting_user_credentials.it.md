---
title: Reimpostazione in blocco delle credenziali utente
description: Ruota i token API e forza il reset della password per molti utenti contemporaneamente
  dall'elenco Utenti
audience: pro
weight: 2
---

L'elenco **Utenti** di DefectDojo Pro consente di ruotare i token API e forzare il reset della password per molti utenti contemporaneamente — utile per l'igiene periodica delle credenziali o per rispondere a un sospetto di esposizione di credenziali.

Queste azioni in blocco sono disponibili solo per i **Superuser** e per gli utenti con il ruolo **Global Owner**. Se non si dispone di uno di questi ruoli, le caselle di selezione e i pulsanti per le azioni in blocco non vengono visualizzati.

## Selezione degli utenti

Nell'elenco **Utenti**, utilizzare le caselle di selezione per selezionare uno o più utenti. Viene visualizzata una barra delle azioni in blocco con i pulsanti di reset. Ogni azione richiede una conferma in una finestra di dialogo prima di essere eseguita.

L'azione si applica agli utenti selezionati esplicitamente. **Non è possibile includere il proprio account** in un reset in blocco: se il proprio account è tra le righe selezionate, i pulsanti per le azioni in blocco vengono disabilitati e viene mostrato un avviso.

## Reimposta token API

**Reimposta token API** ruota il token API di ciascun utente selezionato: DefectDojo elimina il token esistente dell'utente e ne emette uno nuovo. **Il token attuale dell'utente smette di funzionare immediatamente**, quindi eventuali script o integrazioni che utilizzano il vecchio token devono essere aggiornati con quello nuovo.

* I nuovi valori del token **non** vengono mostrati all'amministratore. Ogni utente interessato riceve una notifica **"API Token Reset"** che lo invita a recuperare il nuovo token dall'interfaccia utente (recapitata in base alle impostazioni di notifica di quell'utente).

## Forza il reset della password

**Forza il reset della password** imposta il flag *force-password-reset-on-next-login* su ciascun utente selezionato. Alla successiva richiesta effettuata da quell'utente, DefectDojo lo reindirizza alla pagina **Change Password** e non gli consente di proseguire finché non imposta una nuova password. Il flag viene rimosso automaticamente una volta fatto ciò.

Tenere presente cosa questa azione **non** fa:

* Non imposta né genera casualmente una password temporanea, e non restituisce alcuna credenziale all'amministratore.
* Non invia agli utenti interessati alcuna email o notifica. Poiché non viene inviato alcun avviso automatico, informare gli utenti interessati tramite un altro canale che verrà loro richiesto di cambiare la password al prossimo accesso.

> **Utenti SSO:** a differenza del modulo di modifica per il singolo utente (che disabilita il flag di reset forzato per gli account autorizzati tramite SSO), l'azione in blocco applica il flag a **tutti** gli utenti selezionati, indipendentemente dal metodo di autenticazione utilizzato. Poiché gli utenti SSO accedono tramite il proprio Identity Provider anziché con una password DefectDojo, forzare un reset della password per loro generalmente non ha senso — evitare di includere nella selezione utenti che utilizzano esclusivamente SSO.
