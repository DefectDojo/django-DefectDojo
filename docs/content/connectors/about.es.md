---
title: Acerca de los Conectores
description: El hogar unificado para los Conectores Upstream y Downstream en la interfaz
  de Pro
summary: ''
date: 2026-07-14 00:00:00+00:00
lastmod: 2026-07-14 00:00:00+00:00
draft: false
weight: 1
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Los Conectores son una función exclusiva de DefectDojo Pro.</span>

**Conectores** es el único lugar en la interfaz de DefectDojo Pro para todas las herramientas con las que DefectDojo se comunica, en cualquier dirección. Combina dos funciones que antes se configuraban en lugares separados:

* Los **Conectores Upstream** (antes **Conectores API**) traen hallazgos e inventario de activos *hacia* DefectDojo desde sus escáneres y herramientas de seguridad.
* Los **Conectores Downstream** (antes **Integraciones**) envían hallazgos *hacia fuera*, a sus sistemas de seguimiento de incidencias y de tickets.

Si piensa en DefectDojo como el centro de sus datos de seguridad, los Conectores Upstream son la forma en que llegan los datos, y los Conectores Downstream son la forma en que sale el trabajo de remediación.

## Dónde encontrar los Conectores

En la barra lateral de la interfaz de Pro, abra el grupo **Conectores** bajo el encabezado **Importar**:

* **Conectores > Conectores Upstream** — reemplaza la antigua entrada **Conectores API** (anteriormente bajo Importar).
* **Conectores > Conectores Downstream** — reemplaza la antigua entrada **Integraciones** (anteriormente bajo Configuración). Esta dirección está actualmente en **Beta**.

Los marcadores y enlaces directos antiguos siguen funcionando: las URL heredadas de **Conectores API** e **Integraciones** redirigen automáticamente a las nuevas páginas **Conectores Upstream** y **Conectores Downstream**.

## Quién puede ver qué

* **Conectores Upstream** es visible para los usuarios con un Rol Global de Lector o superior.
* **Conectores Downstream** es visible solo para los superusuarios, y actualmente está en **Beta** para las instancias de DefectDojo Pro alojadas en la nube.

El grupo **Conectores** aparece en la barra lateral si al menos una de las dos páginas es visible para usted.

## Las páginas de Conectores

Ambas direcciones comparten el mismo diseño renovado:

* Cada herramienta se muestra como un **mosaico** de ancho completo: el logotipo a la izquierda, el nombre de la herramienta y una breve descripción en el medio, y un botón de acción a la derecha.
* Cada sección tiene un **cuadro de búsqueda** que filtra los mosaicos por nombre de herramienta a medida que escribe.

En la página de **Conectores Upstream**:

* **Conectores configurados** enumera los conectores que ya ha configurado. Cada mosaico muestra un resumen del estado operativo (estado de salud, última operación y recuentos totales / de registros asignados) y un menú **Administrar configuración** con las acciones **Administrar registros y operaciones**, **Editar configuración** y **Eliminar configuración**.
* **Conectores disponibles** enumera las herramientas compatibles que aún no ha configurado, cada una con un botón **Agregar configuración**.
* Un filtro en el encabezado de la página reduce ambas secciones por tipo de conector: **Todos**, **Activo** (o **Producto**, según el vocabulario de su instancia) para los conectores que importan inventario de activos, y **Hallazgo** para los conectores que importan datos de vulnerabilidades.

En la página de **Conectores Downstream**:

* **Integraciones disponibles** enumera todos los sistemas de seguimiento de incidencias compatibles. Los mosaicos de las integraciones que ha configurado muestran un recuento de las instancias de integración existentes.

## Próximos pasos

* Lea [Acerca de los Conectores Upstream](/connectors/upstream/about/) y [agregue su primer Conector Upstream](/connectors/upstream/add_edit/) para empezar a importar hallazgos automáticamente.
* Lea la [guía de Conectores Downstream](/connectors/downstream/about/) para enviar hallazgos a sus sistemas de seguimiento de incidencias.
