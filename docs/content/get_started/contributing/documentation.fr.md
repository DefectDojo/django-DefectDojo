---
title: Modifier la documentation
description: Comment modifier la documentation
draft: false
weight: 4
audience: opensource
aliases:
- /fr/en/open_source/contributing/documentation
---

La documentation est construite avec [Hugo](https://gohugo.io/) et utilise une variante du thème [Doks](https://getdoks.org/).

Les fichiers statiques du site sont générés par des Github actions et publiés dans la branche gh-pages.

## Comment lancer un aperçu local

1. [Installez Hugo](https://gohugo.io/getting-started/installing/). Assurez-vous d'avoir installé la version étendue (extended) avec le support Sass/SCSS. Notez que différents paquets Linux sont disponibles sur [Hugo GitHub](https://github.com/gohugoio/hugo/releases)
2. Installez le thème requis avec Node.js : `cd docs` puis `npm install`.
3. Pour lancer le serveur local de la documentation, faites `cd docs` pour passer dans le dossier docs, puis démarrez le serveur de développement Hugo en exécutant `npm run dev`.  Le rechargement à chaud (hot reloading) est pris en charge - les pages se mettent à jour automatiquement pendant que le serveur tourne.
4. Rendez-vous sur [http://localhost:1313](http://localhost:1313).

## Directives de contribution

À ce stade, notre documentation est en grande partie maintenue par l'équipe DefectDojo Pro, mais nous accueillons volontiers les contributions de la communauté aux docs.

* Notez que notre fonctionnalité de recherche utilise un index externe qui pointe vers **docs.defectdojo.com** - vous ne pourrez donc pas utiliser la recherche pour trouver des pages qui sont en dev.  Consultez plutôt votre fichier sitemap.xml local pour trouver les nouvelles URL que vous avez créées : `http://localhost:1313/sitemap.xml`
* Notre documentation est actuellement rédigée pour deux publics : Open Source et Pro. Merci d'inclure donc l'étiquette appropriée dans votre en-tête Hugo (front matter), comme ceci :

```
---
title: "Your great article"
audience: opensource
---
```

* N'utilisez pas de chemins de lien relatifs : `[link](../your_article/)`.  Bien que techniquement « légal » dans Hugo, cela fera échouer nos tests unitaires.

## Tests unitaires pour la documentation

La documentation de DefectDojo utilise Lychee pour détecter les erreurs 404 et autres erreurs de lien.  La CI exécute deux vérifications : le site de documentation généré, et toute URL `docs.defectdojo.com` codée en dur dans l'application Django (templates et settings).  Les deux utilisent un `--remap` afin que les URL absolues `docs.defectdojo.com` soient résolues par rapport au site fraîchement généré.  Pour exécuter les deux localement depuis la racine du dépôt :

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

### Substitutions de thème

Nous utilisons des substitutions CSS importantes, détaillées dans `docs/layouts`.
