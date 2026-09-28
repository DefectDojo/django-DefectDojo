---
title: Idiomas y líneas de código
description: Importe datos de composición de idiomas para un Producto usando la herramienta
  cloc
weight: 3
audience: opensource
aliases:
- /es/en/open_source/languages
---

DefectDojo puede mostrar un desglose de los lenguajes de programación y las líneas de código de un Producto, que se completa importando un informe de la herramienta [cloc](https://github.com/AlDanial/cloc) (Count Lines of Code) a través de la API.

## Generating the cloc Report

Ejecute `cloc` sobre su base de código usando el flag `--json` para producir un archivo JSON con el formato correcto:

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importing via the API

Suba el informe JSON a DefectDojo a través de la API. Al importar, todos los datos de idiomas existentes del Producto se reemplazan con el contenido del nuevo archivo.

El endpoint de importación está documentado en la [documentación de la API v2 de DefectDojo](../api-v2-docs/).

## Viewing Results

Después de la importación, el desglose de idiomas se muestra en el lado izquierdo de la página de detalles del Producto, mostrando cada idioma y su recuento de líneas. Los colores de cada idioma se definen mediante entradas en la tabla `Language_Type`, previamente completada con datos de GitHub.

## Updating Language Colors

GitHub actualiza periódicamente los colores de los idiomas a medida que surgen nuevos lenguajes. Para obtener los datos de color más recientes, ejecute el siguiente comando de administración:

```bash
./manage.py import_github_languages
```

Esto lee desde [ozh/github-colors](https://github.com/ozh/github-colors) y agrega nuevos idiomas o actualiza los colores existentes.
