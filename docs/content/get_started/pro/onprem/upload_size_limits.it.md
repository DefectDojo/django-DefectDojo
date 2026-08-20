---
title: Limiti di dimensione per il caricamento di file di scansione di grandi dimensioni
description: Perché il caricamento di un file di scansione di grandi dimensioni fallisce,
  e quale limite aumentare nei deployment Kubernetes e Docker Compose
draft: false
weight: 10
audience: pro
---

Un file di scansione di grandi dimensioni può essere rifiutato da più di un limite, in punti diversi del percorso della richiesta, e l'errore che ricevi indica quale limite hai raggiunto. Questa pagina descrive dove si trovano questi limiti e come aumentarli in un deployment self-hosted.

## Quale limite sto raggiungendo

| Cosa vedi | Da dove proviene |
| --- | --- |
| Un semplice `413 Request Entity Too Large`, senza stile, senza alcuna pagina DefectDojo intorno | L'ingress controller ha rifiutato la richiesta prima che raggiungesse l'applicazione |
| `Report file is too large. Maximum supported size is N MB` | Il limite dell'applicazione, segnalato da DefectDojo stesso |
| Il caricamento procede per un po' e poi fallisce, invece di essere rifiutato immediatamente | Un timeout piuttosto che un limite di dimensione |

Procedi dall'esterno verso l'interno. Non ha senso aumentare il limite dell'applicazione se l'ingress controller sta già rifiutando la richiesta.

## Il limite dell'applicazione

DefectDojo applica un proprio limite massimo per la dimensione del file di scansione e rifiuta tutto ciò che lo supera con un messaggio che indica il limite attuale. Il valore predefinito è 100 MB.

Nel chart Helm, impostalo nei tuoi values:

```yaml
dojo:
  scanMaxFileSize: 100
```

Per i deployment Docker Compose, imposta invece `DD_SCAN_FILE_MAX_SIZE`, in megabyte.

## Il limite dell'ingress

Questo è quello che produce un semplice `413` senza lo stile di DefectDojo, perché la richiesta non raggiunge mai l'applicazione.

Il chart imposta un limite massimo per il corpo della richiesta sull'ingress, con valore predefinito di 2400 MB:

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

Questo valore viene emesso come annotazione `nginx.ingress.kubernetes.io/proxy-body-size`. Viene emesso su ogni piattaforma e non solo su Kubernetes generico, perché l'ingress controller nginx viene spesso usato davanti a una piattaforma gestita. Impostarlo su una stringa vuota omette l'annotazione, e richiede `django.ingress.platformAnnotations.enabled`, che è attivo per impostazione predefinita.

I controller diversi da nginx ignorano tale annotazione, quindi su di essi il limite va aumentato tramite il meccanismo proprio del controller:

| Controller predefinito della piattaforma | Dove si trova il limite |
| --- | --- |
| EKS con AWS Load Balancer Controller | Configurazione dell'ALB |
| GKE con il GCE ingress controller | Configurazione del load balancer |
| AKS con Application Gateway | Il limite del corpo della richiesta di Application Gateway |
| OpenShift Route | `tuningOptions` di HAProxy sul router |

### Timeout quando nginx è davanti a una piattaforma gestita

Il chart emette timeout di proxy nginx generosi, 1800 secondi per read, send e connect, insieme al buffering del proxy disabilitato. Queste annotazioni vengono emesse solo quando la piattaforma è Kubernetes generico. Su EKS, GKE, AKS e OpenShift il chart emette invece le annotazioni proprie di quella piattaforma, perché è ciò che legge il suo controller predefinito.

Questo è rilevante se esegui l'ingress controller nginx su una di queste piattaforme. Ottieni l'annotazione della dimensione del corpo, poiché quella viene emessa ovunque, ma non i timeout. Un caricamento di grandi dimensioni può quindi superare il controllo della dimensione ed essere comunque interrotto a metà dal timeout predefinito del controller, il che è da dove proviene la terza riga della tabella sopra. Fornisci tu stesso i timeout:

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## Il limite della route di importazione

I deployment Kubernetes eseguono le importazioni di scansione tramite pod dedicati, e il nginx davanti alle route di importazione ha un proprio limite per la dimensione del corpo. Questo limite è derivato piuttosto che fisso:

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

Lasciato a `null`, viene calcolato come `dojo.scanMaxFileSize` più 5 MB, un margine che copre l'overhead della codifica multipart. Aumentare il limite dell'applicazione aumenta quindi anche questo, e la maggior parte dei deployment non ha mai bisogno di impostarlo. Imposta un valore intero solo se vuoi sovrascrivere il valore derivato.

## Deployment Docker Compose

I deployment Compose non hanno un ingress controller, quindi il limite dell'ingress non si applica. Il nginx incluso nel deployment limita il corpo delle richieste a 800 MB, che rappresenta il tetto pratico, e il limite dell'applicazione si applica in aggiunta, come ovunque.

Aumentare il limite di nginx significa modificare un file incluso nel deployment, e questi file vengono sostituiti quando esegui l'aggiornamento, invece di essere preservati come la tua directory delle personalizzazioni. Contatta il supporto prima di modificarlo, in modo che la modifica non scompaia al successivo aggiornamento.

## Domande o supporto

Se i caricamenti continuano a fallire dopo aver aumentato il limite corrispondente al tuo sintomo, raccogli la risposta ricevuta dal tuo client e i log di nginx o del controller relativi al tentativo, quindi contatta [support@defectdojo.com](mailto:support@defectdojo.com).
