---
title: Acerca de Sensei
description: Qué es Sensei y cómo funciona el escaneo y corrección alojado por DefectDojo
draft: false
audience: pro
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei es una función exclusiva de DefectDojo Pro y actualmente está en BETA.</span>

**Sensei** es la capacidad de **escaneo y corrección** basada en IA de DefectDojo para repositorios de código fuente. Conecte un repositorio (mediante una **GitHub App**, **GitLab**, **Bitbucket** o **Azure DevOps**) y Sensei lo escanea, importa los resultados como hallazgos de DefectDojo y luego usa un modelo de lenguaje de gran tamaño para **corregir esos hallazgos abriendo pull requests o merge requests**, todo sin salir de DefectDojo.

> **🔀 Múltiples proveedores:** Sensei admite **GitHub** (github.com y GitHub Enterprise Server), **GitLab** (gitlab.com y autoalojado), **Bitbucket** (Cloud y Server/Data Center) y **Azure DevOps**, todos con el mismo flujo de escaneo y corrección. Donde esta guía dice *pull request*, GitLab usa un **merge request**; el *status check* del PR se publica como un **commit status** de GitLab/Azure o un **build status** de Bitbucket. La conexión difiere según el proveedor (consulte [Configurar Sensei](/sensei/setup_sensei/)); todo lo posterior a la incorporación es idéntico.

- **Escaneo y corrección en un solo lugar:** los repositorios se escanean y corrigen desde la página de Sensei y desde sus hallazgos, usando los mismos datos de hallazgos normalizados y deduplicados que el resto de DefectDojo.
- **Vista previa primero:** Sensei prepara *candidatos* de corrección para su revisión. No se envía nada a un LLM ni se abre ningún pull request hasta que usted lo aprueba, por lo que no hay costos sorpresa ni PR inesperados.
- **Credenciales de corta duración:** Sensei se ejecuta completamente a través de una GitHub App y usa tokens de instalación de corta duración. No hay nada que pegar ni que rotar.
- **Medido y sujeto a licencia:** Sensei es una función de Pro con cuotas por instancia para correcciones y repositorios incorporados.

> **🧠 Antes de que exista el código:** Sensei también genera un modelo de amenazas, rutas de ataque y requisitos de seguridad a partir del *diseño* de una funcionalidad, sin necesidad de un repositorio — consulte [Modelado de amenazas](/sensei/threat_modeling/).

> **🔎 BETA:** Sensei está en desarrollo activo y aparece etiquetado como **BETA** en toda la interfaz. El comportamiento y las pantallas pueden cambiar entre versiones.

> **📍 Dónde encontrarlo:** abra **Sensei** desde la navegación izquierda.

![Hub de Sensei](images/hub_overview.png)

## Cómo funciona el escaneo alojado por DefectDojo

El escaneo alojado por DefectDojo es la forma recomendada de ejecutar Sensei. Los escaneos se ejecutan **dentro de DefectDojo** y no se agrega nada a su repositorio:

1. **Conecte una GitHub App** e instálela en la organización (o cuenta) propietaria de sus repositorios.
2. **Incorpore un repositorio** para el escaneo alojado y elija cómo se reportan los hallazgos y (opcionalmente) cómo se corrigen automáticamente.
3. **Sensei escanea el repositorio** (a demanda, o automáticamente cuando se abre un pull request) e importa los resultados en un Compromiso con el nombre de la rama.
4. **Sensei corrige los hallazgos** generando una corrección y abriendo un pull request contra la rama predeterminada del repositorio.

Cada repositorio incorporado está vinculado a un **activo** (Producto) de DefectDojo, de modo que sus hallazgos, Compromisos y correcciones conviven con el resto de sus datos.

## Las tres formas de iniciar una corrección

Sensei puede corregir un hallazgo de tres maneras:

- **El botón Fix en un hallazgo:** active una corrección puntual directamente desde la tabla de hallazgos o la página de detalle de un hallazgo. Consulte [Corrección de hallazgos con Sensei](/sensei/fixing_findings/).
- **Candidatos de autocorrección:** después de cada escaneo, Sensei prepara como candidatos los hallazgos que coinciden con sus criterios. Usted los revisa y aprueba los que desea corregir (o deja que Sensei los corrija automáticamente). Consulte [Candidatos de autocorrección](/sensei/fixing_findings/#auto-fix-candidate-triage).
- **Un comentario `/fix` en un pull request:** comente `/fix` en un pull request y Sensei enviará una corrección a ese PR.

## Requisitos

- Una licencia de **DefectDojo Pro** que incluya la función **Sensei**.
- Un proveedor de control de código fuente conectado (consulte [Configurar Sensei](/sensei/setup_sensei/)): una **GitHub App** (github.com o Enterprise Server), un token de acceso de proyecto/grupo de **GitLab** (gitlab.com o autoalojado), una conexión de **Bitbucket** (Cloud o Server/Data Center — OAuth, token de API o token de acceso), o un token de acceso personal (PAT) de **Azure DevOps**.
- Para **configurar** Sensei (conectar aplicaciones, incorporar repositorios): un rol global de **Maintainer** u **Owner**.
- Para **activar una corrección** en un hallazgo: al menos acceso de **Writer** al Producto de ese hallazgo.

## Cuotas

Sensei se mide contra su licencia. El hub de Sensei muestra dos medidores de uso en la parte superior de la página:

- **Fixes:** el número de correcciones aplicadas frente a su límite prepagado. Aprobar un candidato o activar una corrección consume esta cuota.
- **Onboarded Repositories:** el número de repositorios incorporados frente a su límite de repositorios.

Cuando se alcanza una cuota, Sensei bloquea nuevas correcciones (o incorporaciones) hasta que se aumente. Consulte [Referencia](/sensei/sensei_reference/#quotas-and-metering) para más detalles.
