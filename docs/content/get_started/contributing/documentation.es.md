---
title: Modificar la documentación
description: Cómo modificar la documentación
draft: false
weight: 4
audience: opensource
aliases:
- /es/en/open_source/contributing/documentation
---

La documentación se construye con [Hugo](https://gohugo.io/) y utiliza una variación del tema [Doks](https://getdoks.org/).

Los archivos estáticos del sitio web se generan con Github Actions y se publican en la rama gh-pages.

## Cómo ejecutar una vista previa local

1. [Instale Hugo](https://gohugo.io/getting-started/installing/). Asegúrese de haber instalado la versión extendida con soporte para Sass/SCSS. Tenga en cuenta que hay varios paquetes de Linux disponibles en [Hugo GitHub](https://github.com/gohugoio/hugo/releases)
2. Instale el tema necesario con Node.js: `cd docs` y luego `npm install`.
3. Para ejecutar el servidor local de Docs, `cd docs` para pasar a la carpeta docs, y arranque el servidor de desarrollo de Hugo ejecutando `npm run dev`.  Se admite la recarga en caliente: las páginas se actualizarán automáticamente con los cambios mientras el servidor esté en ejecución.
4. Visite [http://localhost:1313](http://localhost:1313).

## Pautas de contribución

En esta etapa, nuestra documentación la mantiene principalmente el equipo de DefectDojo Pro, pero seguimos dando la bienvenida a las contribuciones de la comunidad a los docs.

* Tenga en cuenta que nuestra función de búsqueda utiliza un índice externo que apunta a **docs.defectdojo.com** - por lo que no podrá usar la búsqueda para encontrar páginas que estén en dev.  En su lugar, consulte su archivo sitemap.xml local para encontrar cualquier URL nueva que haya creado: `http://localhost:1313/sitemap.xml`
* Nuestros docs se escriben actualmente para dos audiencias: Open Source y Pro, así que incluya una etiqueta adecuada en su front matter de Hugo, así:

```
---
title: "Your great article"
audience: opensource
---
```

* No utilice rutas de enlace relativas: `[link](../your_article/)`.  Aunque técnicamente son 'legales' en Hugo, no pasará nuestras pruebas unitarias.

## Pruebas unitarias para los docs

Los docs de DefectDojo usan Lychee para comprobar errores 404 y otros errores de enlaces.  CI ejecuta dos comprobaciones: el sitio de docs renderizado, y cualquier URL de `docs.defectdojo.com` codificada en la aplicación Django (plantillas y ajustes).  Ambas usan un `--remap` para que las URL absolutas de `docs.defectdojo.com` se resuelvan contra el sitio recién construido.  Para ejecutar ambas localmente desde la raíz del repositorio:

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

### Anulaciones de tema

Usamos anulaciones de CSS significativas que se detallan en `docs/layouts`.
