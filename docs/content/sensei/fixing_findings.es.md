---
title: Corrección de hallazgos con Sensei
description: Escanee, clasifique candidatos de autocorrección y abra pull requests
  de corrección
draft: false
audience: pro
weight: 3
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei es una función exclusiva de DefectDojo Pro y actualmente está en BETA.</span>

Una vez que se incorpora un repositorio, Sensei aparece directamente en sus hallazgos y en el hub de Sensei. Esta página cubre el escaneo de un repositorio, la clasificación de candidatos de autocorrección y la corrección de hallazgos individuales. Necesita al menos acceso de **Writer** al Producto de un hallazgo para activar una corrección.

## Escanear un repositorio

Los escaneos importan hallazgos en un Compromiso con el nombre de la rama. Puede activar un escaneo a demanda desde el hub de Sensei: abra las acciones de fila de un repositorio y elija **Scan now**.

![Diálogo de escaneo con Sensei](images/scan_dialog.png)

Elija la rama a escanear (por defecto es la rama predeterminada del repositorio) y seleccione **Start scan**. En el modo alojado por DefectDojo, los escaneos también se ejecutan automáticamente cuando se abre un pull request.

## La columna Sensei en los hallazgos

Los repositorios incorporados agregan una columna **Sensei** a la tabla de hallazgos. Cada hallazgo muestra un botón **Fix** (o su estado de corrección actual), de modo que puede corregir sin salir de su vista de clasificación.

![Columna Sensei en la tabla de hallazgos](images/findings_sensei_column.png)

El botón tiene dos estados:

- **Fix:** el Producto del hallazgo está incorporado a Sensei. Al hacer clic se inicia una corrección.
- **Configure Product:** el Producto del hallazgo **no** está incorporado todavía. Al hacer clic lo lleva a Sensei para incorporar un repositorio para ese Producto; una vez incorporado, el botón pasa a ser **Fix**.

## Corregir un solo hallazgo

Al hacer clic en **Fix** (en la tabla de hallazgos o en el encabezado de detalle de un hallazgo) se abre el diálogo **Fix with Sensei**. Elija la rama base a la que debe apuntar el pull request de corrección y luego haga clic en **Fix**.

![Diálogo Fix with Sensei](images/fix_with_sensei_dialog.png)

Sensei genera una corrección y abre un pull request. El estado de corrección del hallazgo se muestra como una insignia que avanza por *en curso* → *PR abierto* (o *fallido*). Una vez que el pull request está abierto, la insignia enlaza directamente a él.

![Detalle del hallazgo con insignia de estado de corrección](images/finding_detail_fix.png)

> **💡 Una corrección, un PR:** cada corrección aprobada consume una corrección de su cuota y abre un pull request. Revise y fusione el PR en GitHub como lo haría con cualquier otro.

## Clasificación de candidatos de autocorrección

Cuando un repositorio tiene las correcciones automáticas habilitadas, cada escaneo prepara los hallazgos coincidentes como **candidatos** en la pestaña **Auto-fix Candidates** del hub de Sensei. Este es el modelo de vista previa primero de Sensei: los hallazgos se preparan, pero **nada se ejecuta (sin costo de LLM) hasta que usted aprueba**. Aprobar abre pull requests de corrección y consume correcciones.

![Clasificación de candidatos de autocorrección](images/auto_fix_candidates.png)

Cada candidato muestra el hallazgo, su estado, Severidad, riesgo, prioridad, repositorio de destino y rama del PR. Para corregir:

- **Aprobar uno:** haga clic en **Approve** en una fila para abrir el selector de ramas e iniciar esa corrección.
- **Aprobar varios:** seleccione varias filas y use la acción de aprobación masiva.

Los hallazgos aprobados permanecen listados como **In Progress** (o **Failed**) hasta que se adjunta su pull request, de modo que una corrección en curso o fallida nunca desaparece antes de producir un PR.

> **🔎 Corrección sin intervención:** si habilitó *Automatically remediate candidates* en el repositorio, una verificación en segundo plano abre PRs de corrección para los candidatos preparados automáticamente, hasta su cuota de correcciones, sin aprobación manual.

## Seguimiento de escaneos e impacto

Dos lugares en el hub de Sensei le ayudan a seguir lo que Sensei ha hecho:

- **Scan Activity:** un registro de cada escaneo y ejecución de corrección, con su modo (Branch Scan, PR Scan, Fix (Finding)), disparador (Manual, Webhook, Auto Remediated), estado, tiempo de ejecución y enlaces al Compromiso o al pull request que produjo.

  ![Registro de Scan Activity](images/scan_activity.png)

- **Fix Impact:** un resumen de las correcciones aplicadas, con los activos corregidos con más frecuencia, en la parte superior del hub.

  ![Panel de Fix Impact](images/fix_impact.png)

Use las acciones de fila **Scan now**, **Scan history**, **Configure** y **Re-stage candidates** para gestionar cada repositorio incorporado con el tiempo (consulte [Referencia](/sensei/sensei_reference/#repository-row-actions)).
