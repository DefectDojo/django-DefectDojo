---
title: Plantilla de documentación de parser
toc_hide: true
weight: 2
audience: opensource
aliases:
- /es/en/open_source/contributing/parser-documentation-template
---

Esta plantilla está diseñada para documentar un parser nuevo o existente. Siéntase libre de mejorarla con cualquier información adicional que pueda ayudar a otros profesionales de seguridad.

* Copie este archivo .md y añádalo a `/docs/content/supported_tools/file` en el repositorio de GitHub.
* Actualice el título para que coincida con el nombre de su parser nuevo o existente.
* Complete todas las secciones indicadas a continuación. Elimine las instrucciones o ejemplos que encuentre dentro de cada sección o ejemplos.

### File Types
_Especifique todos los tipos de archivo aceptados por su parser (por ejemplo, CSV, JSON, XML)._
_Incluya instrucciones sobre cómo crear o exportar el formato de archivo aceptable desde la herramienta de seguridad relacionada._

### Total Fields in [File Format]
Total data fields:  _Número total de campos contenidos en el archivo de exportación de la herramienta de seguridad._
Total data fields parsed:  _Número total de campos analizados (parseados) en el hallazgo de DefectDojo._
Total data fields NOT parsed: _Número total de campos NO analizados en el hallazgo de DefectDojo._

_Usando el formato siguiente, proporcione una breve descripción de cada campo y cómo se corresponde con el modelo de datos de DefectDojo._
_Incluya todos los campos que aparecen en el archivo de exportación de la herramienta de seguridad, en orden de aparición, indicando los campos que no se analizan._

Fields in order of appearance:
1. **Field 1** - _Descripción de cómo se corresponde este campo (por ejemplo, se corresponde con el título del hallazgo, el host del endpoint.)_
2. **Field 2** - _Descripción de cómo se corresponde / no se corresponde este campo._
3. **Field 3** - _Descripción de cómo se corresponde / no se corresponde este campo._
4. **Field 4** - _Descripción de cómo se corresponde / no se corresponde este campo._
_(continuar para cada campo del archivo.)_

### Field Mapping Details
_Para cada hallazgo creado, incluya detalles de cómo el parser analiza datos específicos. Por ejemplo:_
- Cómo se crean los endpoints (por ejemplo, combinando los campos IP, dominio, puerto y protocolo).
- Cómo se gestionan las repeticiones (por ejemplo, `nb_occurences` predeterminado en 1, incrementado en caso de duplicados).
- Cómo se gestiona la deduplicación (por ejemplo, mediante un hash de severidad + título + descripción).
- Describe la severidad predeterminada si no coincide ninguna correspondencia.

### Sample Scan Data or Unit Tests
_Añada un enlace a la carpeta de pruebas unitarias o de datos de escaneo de ejemplo en el repositorio de GitHub. Por ejemplo:_
- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/[parser-name])

### Link To Tool
_Proporcione un enlace a la propia herramienta o escáner (por ejemplo, repositorio de GitHub, sitio web del proveedor o documentación). Por ejemplo:_
- [Tool Name](https://www.example.com/)
