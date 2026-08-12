---
title: Dokumentation ändern
description: So ändern Sie die Dokumentation
draft: false
weight: 4
audience: opensource
aliases:
- /de/en/open_source/contributing/documentation
---

Die Dokumentation wird mit [Hugo](https://gohugo.io/) erstellt und verwendet eine Variante des [Doks](https://getdoks.org/)-Themes.

Statische Dateien für die Website werden mit GitHub Actions erstellt und im gh-pages-Branch veröffentlicht.

## So führen Sie eine lokale Vorschau aus

1. [Installieren Sie Hugo](https://gohugo.io/getting-started/installing/). Achten Sie darauf, dass Sie die erweiterte Version mit Sass/SCSS-Unterstützung installiert haben. Beachten Sie, dass verschiedene Linux-Pakete auf [Hugo GitHub](https://github.com/gohugoio/hugo/releases) verfügbar sind
2. Installieren Sie das erforderliche Theme mit Node.js: `cd docs` und anschließend `npm install`.
3. Um den lokalen Docs-Server auszuführen, wechseln Sie mit `cd docs` in den Docs-Ordner und starten Sie den Hugo-Entwicklungsserver mit `npm run dev`.  Hot Reloading wird unterstützt - Seiten werden automatisch mit Änderungen aktualisiert, während der Server läuft.
4. Besuchen Sie [http://localhost:1313](http://localhost:1313).

## Richtlinien für Beiträge

Derzeit wird unsere Dokumentation größtenteils vom DefectDojo Pro-Team gepflegt, aber wir freuen uns weiterhin über Beiträge zur Dokumentation aus der Community.

* Beachten Sie, dass unsere Suchfunktion einen externen Index verwendet, der auf **docs.defectdojo.com** verweist - Sie können die Suche daher nicht verwenden, um Seiten zu finden, die sich in der Entwicklung befinden.  Konsultieren Sie stattdessen Ihre lokale sitemap.xml-Datei, um neu erstellte URLs zu finden: `http://localhost:1313/sitemap.xml`
* Unsere Dokumentation richtet sich derzeit an zwei Zielgruppen: Open Source und Pro, bitte geben Sie daher ein entsprechendes Label in Ihrem Hugo-Frontmatter an, etwa so:

```
---
title: "Your great article"
audience: opensource
---
```

* Verwenden Sie keine relativen Link-Pfade: `[link](../your_article/)`.  Auch wenn dies in Hugo technisch 'zulässig' ist, werden Sie damit unsere Unit-Tests nicht bestehen.

## Unit-Tests für die Dokumentation

Die Dokumentation von DefectDojo verwendet Lychee, um auf 404-Fehler und andere Link-Fehler zu prüfen.  Die CI führt zwei Prüfungen aus: die gerenderte Docs-Site sowie alle `docs.defectdojo.com`-URLs, die fest in der Django-App (Templates und Settings) codiert sind.  Beide verwenden ein `--remap`, damit absolute `docs.defectdojo.com`-URLs gegen die frisch gebaute Site aufgelöst werden.  So führen Sie beide lokal vom Root des Repos aus:

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

### Theme-Overrides

Wir verwenden umfangreiche CSS-Overrides, die in `docs/layouts` beschrieben sind.
