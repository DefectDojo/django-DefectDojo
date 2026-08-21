---
title: Búsqueda global
description: Busque en Hallazgos, Activos y objetos relacionados desde la barra superior
  de DefectDojo Pro
audience: pro
weight: 3
---

DefectDojo Pro incluye una **búsqueda global** que examina sus Hallazgos y objetos relacionados desde un único cuadro en la barra superior. Está respaldada por la búsqueda de texto completo nativa de Postgres, con coincidencia difusa y tolerante a errores tipográficos, para que pueda encontrar un objeto sin recordar su redacción exacta.

## Realizar una búsqueda

- **Cuadro de búsqueda de la barra superior** — haga clic en el cuadro **Search** en la navegación superior y comience a escribir. A medida que escribe, un menú desplegable muestra una vista previa de las mejores coincidencias **agrupadas por tipo de objeto**, con un contador junto a cada tipo y un enlace **See all *N* results** en la parte inferior.
- **Página de resultados completa** — presione **Enter**, o haga clic en **See all *N* results**, para abrir la página de resultados completa. Se trata de una única tabla ordenable y filtrable con todas las coincidencias en todos los tipos de objeto.

Los resultados siempre están **limitados a lo que usted está autorizado a ver** — la búsqueda global nunca muestra objetos a los que de otro modo no tendría acceso. (Las Finding Templates son la única excepción: como en el resto de DefectDojo, son visibles para cualquier usuario que haya iniciado sesión.)

## Qué puede buscar

La búsqueda global cubre estos tipos de objeto:

| Tipo de objeto | Notas |
| --- | --- |
| **Findings** | |
| **Assets** | (Products) |
| **Organizations** | (Product Types) |
| **Engagements** | |
| **Tests** | |
| **Endpoints** *o* **Locations** | Lo que use su instancia — las instancias con [Locations](/asset_modelling/locations/pro__locations_overview/) habilitado buscan en Locations; las demás buscan en Endpoints. |
| **Finding Templates** | |
| **Technologies** | |
| **Vulnerability IDs** | p. ej., CVE |

En la mayoría de los tipos, la búsqueda coincide con el **nombre/título y la descripción** del objeto. Para Findings, Assets, Engagements y Tests, también coincide con las **etiquetas** (por prefijo). Los Vulnerability IDs coinciden con el propio valor del ID.

## Sintaxis de consulta

### Texto libre

Escriba cualquier palabra clave para buscar en todo a la vez. Las coincidencias se ordenan por relevancia, con las coincidencias de título/nombre por encima de las de descripción. La coincidencia difusa (vea más abajo) hace que términos cercanos pero no exactos también coincidan.

### Frases entre comillas

Envuelva una frase entre comillas dobles para mantenerla unida — `"space inside"` se trata como un único término en lugar de dos palabras clave.

### Operadores

Anteponga un operador a un término (`operator:value`) para acotar la búsqueda. Operadores admitidos:

| Operador | Qué hace |
| --- | --- |
| `finding:` `product:` `engagement:` `test:` `template:` `technology:` | Limita la búsqueda a un único tipo de objeto y busca el valor dentro de él (p. ej., `finding:sqli`). |
| `id:` | Busca un Finding por su ID numérico (p. ej., `id:12345`). |
| `endpoint:` | Encuentra Findings cuyo host de endpoint/location contiene el valor. |
| `vulnerability_id:` | Coincidencia exacta con un Vulnerability ID. Acepta una lista separada por comas, y se puede repetir (p. ej., `vulnerability_id:CVE-2020-1234,CVE-2018-7489`). |
| `tag:` / `tags:` | Coincide con objetos por etiqueta. `tag:` coincide con una única etiqueta por subcadena; `tags:` coincide con cualquier etiqueta de una lista. |
| `test-tag:` `engagement-tag:` `product-tag:` (y sus plurales `-tags`) | Coincide por una etiqueta en el Test, Engagement o Asset relacionado, en lugar de en el propio objeto. |
| `not-tag:` `not-tags:` (y las variantes de relación `not-…-tag`) | Niega cualquiera de los operadores de etiqueta anteriores para **excluir** coincidencias. |

Puede combinar operadores con palabras clave de texto libre en la misma consulta.

### Coincidencia difusa

Para consultas de **tres o más caracteres**, la búsqueda global también realiza una coincidencia por trigramas (similitud de palabras). Esto tolera errores tipográficos y encuentra términos **dentro** de valores más largos con puntos o guiones — por ejemplo, `internal` coincide con `api.internal.example.com`.

## Filtrar y ordenar la página de resultados

En la página de resultados completa, las columnas se pueden filtrar y ordenar de forma independiente al texto de la consulta — filtre por **tipo de objeto**, **severidad**, **título** o **contexto**, y ordene por cualquier columna. Esto es independiente de la sintaxis `operator:` mencionada arriba y se aplica a la tabla de resultados combinados.

## Límites de resultados

- La página de resultados completa está **paginada** (25 filas por página de forma predeterminada).
- Cada tipo de objeto aporta hasta un **número máximo de coincidencias** por búsqueda — **100** de forma predeterminada. Cuando existen más coincidencias de las que se muestran, los resultados se marcan como truncados; acote su consulta para ver las coincidencias más relevantes.
- El menú desplegable de la barra superior muestra una vista previa más pequeña (las primeras coincidencias de cada tipo) junto con los totales, por lo que **See all *N* results** siempre refleja los totales reales.
