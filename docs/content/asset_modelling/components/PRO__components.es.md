---
title: Componentes
description: Seguimiento de bibliotecas de terceros y componentes de software en DefectDojo
  Pro
audience: pro
weight: 1
---

En DefectDojo, los Componentes representan bibliotecas de terceros, componentes de software y módulos que potencialmente presentan vulnerabilidades.


## Vistas de componentes

DefectDojo Pro incluye una vista de tabla dedicada para Componentes, que se encuentra en la barra lateral.  Esta vista muestra los Hallazgos activos, los Hallazgos duplicados y el total de Hallazgos de cada Componente.  Estas cifras incluyen todos los Activos de la instancia de DefectDojo.

Los Componentes de un Activo individual se pueden ver en la vista del Activo.

## La tabla de componentes

La tabla de componentes muestra las siguientes columnas:

* **Componente** — el nombre del componente, obtenido de los datos del escaneo.
* **Versión** — la versión del componente, obtenida de los datos del escaneo.
* **Hallazgos activos** — cantidad de Hallazgos activos asociados con el componente.
* **Hallazgos duplicados** — cantidad de Hallazgos duplicados asociados con el componente.
* **Total de hallazgos** — cantidad total de todos los Hallazgos asociados con el componente.

Al hacer clic en el nombre del componente o en los valores de Hallazgos activos, Hallazgos duplicados o Total de hallazgos se abre una lista filtrada de Hallazgos para el campo correspondiente.

En la tabla se muestra un Componente **None**, que agrupa todos los Hallazgos que no están asociados con ningún Componente.

Los Componentes importados permanecen en la tabla incluso si todos sus Hallazgos asociados están Mitigados. Cuando se importan Hallazgos para un Componente específico, la tabla de componentes se actualiza para reflejar con precisión los nuevos totales de Hallazgos.


### Ejemplo

Un Componente importado de un escaneo de Dependency-Check contra una aplicación con una dependencia `lodash` vulnerable podría aparecer en la tabla de la siguiente manera:

| Componente | Versión | Hallazgos activos | Hallazgos duplicados | Total de hallazgos |
| --- | --- | --- | --- | --- |
| npm:lodash | 4.17.15 | 3 | 1 | 5 |

Al hacer clic en `npm:lodash` se abre la lista de todos los Hallazgos que hacen referencia a este Componente. Al hacer clic en `3` se abre la misma lista filtrada solo a Hallazgos activos.

## Agregar componentes

Los Componentes se pueden analizar a partir de la importación de un escaneo o editando manualmente un Hallazgo. Una vez que un Nombre de componente se asocia con un Hallazgo, se agregará automáticamente una entrada correspondiente a la tabla de componentes. Si el Componente ya está asociado con otros Hallazgos en DefectDojo, los totales de Hallazgos activos, Hallazgos duplicados y Total de hallazgos se actualizan en consecuencia.

### Cómo se analizan los componentes a partir de los datos del escaneo

Cuando se importa un escaneo, los parsers completan los campos **Component Name** y **Component Version** de cada Hallazgo a partir de la salida del escaneo. La tabla de componentes se construye luego a partir de esos valores. El nivel de detalle y la convención de nomenclatura dependen de la herramienta que generó el escaneo:

* Las herramientas de **Análisis de composición de software (SCA)** generalmente informan un nombre de paquete y una versión exacta. Por ejemplo, OWASP Dependency-Check obtiene el Componente a partir de la [Package URL](https://github.com/package-url/purl-spec) de su identificador — un purl `pkg:npm/lodash@4.17.15` se convierte en `Component Name: npm:lodash`, `Component Version: 4.17.15`.
* Los **escáneres de contenedores y paquetes del SO**, como Trivy, Anchore Grype y Anchore Engine, informan el paquete de SO o de lenguaje afectado — por ejemplo, `Component Name: curl`, `Component Version: 7.68.0`.
* Los **escáneres de dependencias específicos de lenguaje**, como npm Audit, pip-audit, bundler-audit, Retire.js, Govulncheck y OSV-Scanner, completan el paquete y la versión responsables a partir de los manifiestos de su respectivo ecosistema.

Los escáneres enfocados en configuración, infraestructura o lógica del código fuente (como las herramientas SAST e IaC) generalmente no completan los campos de Componente, y sus Hallazgos aparecen bajo el Componente **None**.

Para agregar o cambiar un Componente manualmente, edite el Hallazgo y establezca directamente los campos **Nombre del componente** y **Versión del componente**. La tabla de componentes se actualiza en cuanto se guarda el Hallazgo.

## Actualizar componentes

Para actualizar el nombre o la versión de un Componente, se debe actualizar el campo Nombre del componente o Versión del componente de todos los Hallazgos asociados con ese Componente.

## Quitar componentes

Para quitar un Componente de la tabla de componentes, se deben actualizar todos los Hallazgos asociados con el Componente para eliminar sus campos Nombre del componente y Versión del componente. Los Componentes también se eliminan si se eliminan todos sus Hallazgos asociados.

Si todos los Hallazgos de un Componente están Mitigados, el Componente permanece en la tabla, pero su valor de Hallazgos activos se establece en 0.
