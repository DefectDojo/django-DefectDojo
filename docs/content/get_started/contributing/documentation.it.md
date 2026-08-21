---
title: Modificare la documentazione
description: Come modificare la documentazione
draft: false
weight: 4
audience: opensource
aliases:
- /it/en/open_source/contributing/documentation
---

La documentazione è realizzata con [Hugo](https://gohugo.io/) e utilizza una variante del tema [Doks](https://getdoks.org/).

I file statici del sito web vengono creati con GitHub Actions e pubblicati nel branch gh-pages.

## Come eseguire un'anteprima locale

1. [Installa Hugo](https://gohugo.io/getting-started/installing/). Assicurati di aver installato la versione extended con supporto Sass/SCSS. Nota che sono disponibili vari pacchetti Linux su [Hugo GitHub](https://github.com/gohugoio/hugo/releases)
2. Installa il tema richiesto utilizzando Node.js: `cd docs` e poi `npm install`.
3. Per eseguire il server locale dei Docs, esegui `cd docs` per passare alla cartella docs, e avvia il server di sviluppo di Hugo eseguendo `npm run dev`.  L'hot reloading è supportato - le pagine si aggiorneranno automaticamente con le modifiche mentre il server è in esecuzione.
4. Visita [http://localhost:1313](http://localhost:1313).

## Linee guida per contribuire

In questa fase, la nostra documentazione è in gran parte mantenuta dal team DefectDojo Pro, ma accogliamo comunque con favore i contributi alla documentazione da parte della community.

* Nota che la nostra funzionalità di ricerca utilizza un indice esterno che punta a **docs.defectdojo.com** - quindi non sarai in grado di utilizzare la ricerca per trovare pagine che si trovano in dev.  Consulta invece il tuo file sitemap.xml locale per trovare eventuali nuovi URL che hai creato: `http://localhost:1313/sitemap.xml`
* La nostra documentazione è attualmente scritta per due pubblici: Open Source e Pro, quindi includi un'etichetta appropriata nel tuo front matter di Hugo, in questo modo:

```
---
title: "Your great article"
audience: opensource
---
```

* Non utilizzare percorsi di link relativi: `[link](../your_article/)`.  Sebbene sia tecnicamente 'legale' in Hugo, non supererai i nostri unit test.

## Unit test per la documentazione

La documentazione di DefectDojo utilizza Lychee per verificare la presenza di errori 404 e altri errori nei link.  La CI esegue due controlli: il sito di documentazione renderizzato, e qualsiasi URL `docs.defectdojo.com` hardcoded nell'app Django (template e settings).  Entrambi utilizzano un `--remap` in modo che gli URL assoluti `docs.defectdojo.com` vengano risolti rispetto al sito appena creato.  Per eseguire entrambi localmente dalla radice del repository:

```
cd docs && rm -rf public/ && hugo --minify --gc --config config/production/hugo.toml && cd ..

lychee --offline --no-progress \
  --root-dir "$PWD/docs/public" \
  --remap "https://docs.defectdojo.com file://$PWD/docs/public" \
  './docs/public/**/*.html'

lychee --offline --no-progress \
  --root-dir "$PWD/docs/public" \
  --remap "https://docs.defectdojo.com file://$PWD/docs/public" \
  --exclude '%7[BD]' \
  $(grep -rl 'docs\.defectdojo\.com' dojo/ --include='*.html' --include='*.py' --include='*.tpl')
```

### Override del tema

Utilizziamo significativi override CSS, descritti in dettaglio in `docs/layouts`.
