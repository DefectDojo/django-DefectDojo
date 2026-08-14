---
title: Referencia de Sensei
description: Estados, acciones de fila, cuotas y solución de problemas
draft: false
audience: pro
weight: 5
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei es una función exclusiva de DefectDojo Pro y actualmente está en BETA.</span>

Una referencia rápida de los estados, acciones y límites que encontrará al usar Sensei.

## Estados del repositorio

El estado que se muestra para un repositorio incorporado en el hub de Sensei:

| Estado | Significado |
|--------|---------|
| **Active** | Incorporado y listo para escanear. |
| **Pull Request Open** | Sensei tiene un pull request abierto contra el repositorio. |
| **Pull Request Closed** | Se cerró un pull request de Sensei. |
| **Error** | La última operación falló: consulte Scan Activity para conocer la causa raíz. |
| **Not Configured** | El repositorio está conectado pero aún no configurado. |

## Estados de candidatos y correcciones

Los candidatos de autocorrección y los registros de corrección pasan por estos estados:

| Estado | Significado |
|--------|---------|
| **Candidate** | Preparado por los criterios de autocorrección de un escaneo. Nada se ejecuta hasta que usted aprueba. |
| **In Progress** | Aprobado: Sensei está generando la corrección y abrirá un pull request. |
| **PR Open** | Hay un pull request de corrección abierto; la insignia enlaza a él. |
| **Failed** | La corrección no pudo completarse; permanece listada para que no desaparezca silenciosamente. |

## Acciones de fila del repositorio

Cada repositorio incorporado tiene un menú de acciones de fila en el hub de Sensei:

![Acciones de fila del repositorio](images/repo_row_menu.png)

- **Scan now:** inicia un escaneo a demanda (abre el selector de ramas).
- **Scan history:** muestra los escaneos anteriores de este repositorio.
- **Configure:** reabre el formulario de configuración (reporte de PR, correcciones automáticas, vinculación de Producto).
- **Re-stage candidates:** reevalúa los hallazgos del repositorio con los criterios de autocorrección y prepara candidatos nuevos.
- **Delete:** elimina el repositorio de Sensei. Esto detiene su escaneo; no elimina el activo ni los hallazgos subyacentes.

## Cuotas y medición

Sensei se mide contra su licencia de DefectDojo Pro, mostrada como medidores en la parte superior del hub:

- **Fixes:** correcciones aplicadas frente a su límite prepagado. Aprobar un candidato o activar una corrección consume esta cuota; cuando se agota, se bloquean nuevas correcciones (aparece un banner de advertencia) hasta que se aumente el límite.
- **Onboarded Repositories:** repositorios incorporados frente a su límite de repositorios. Cuando se alcanza, se bloquea la incorporación de nuevos repositorios.

Para aumentar un límite, contacte a su equipo de cuenta de DefectDojo.

## Particularidades de GitLab

GitLab es compatible junto con GitHub (gitlab.com y autoalojado). El comportamiento de escaneo y corrección es idéntico; estos son los detalles específicos de GitLab:

- **Conexión:** un **token de acceso de proyecto o grupo** (rol **Developer**, o **Maintainer** si las reglas de push lo requieren) con los alcances **`api`** y **`write_repository`**, no una GitHub App. Consulte [Configurar Sensei](/sensei/setup_sensei/#connect-gitlab).
- **Webhook:** cada proyecto incorporado necesita un webhook a `…/sensei/gitlab/webhooks` (con el secreto de la conexión) suscrito a los eventos **Push**, **Merge request** y **Comment**. Agregar un webhook requiere **Maintainer**/**Owner** en el proyecto.
- **Merge requests, no pull requests:** las correcciones abren un **merge request** contra la rama predeterminada; el comentario `/fix` funciona en las notas del merge request.
- **Compuerta de commit status:** el status check del PR es un **commit status** de GitLab en el commit de cabecera del merge request: `running` mientras escanea, luego `success` o `failed` (fail-on-new). GitLab no tiene un estado *neutral*, por lo que un escaneo **no bloqueante** que aún tiene hallazgos muestra un estado **verde**; la nota de resumen lleva los detalles del hallazgo.
- **Autoalojado:** apunte la **GitLab Base URL** a su instancia; DefectDojo clona y llama a la API contra ese host.

## Particularidades de Bitbucket

Se admiten Bitbucket **Cloud** y **Server/Data Center**. El comportamiento de escaneo y corrección es idéntico; estos son los detalles específicos de Bitbucket:

- **Conexión:** **OAuth** (recomendado), un **token de API** de Atlassian (usado con el correo electrónico de su cuenta), o un **token de acceso** de repositorio/workspace. Consulte [Configurar Sensei](/sensei/setup_sensei/#connect-bitbucket). Las contraseñas de aplicación están obsoletas y no son compatibles.
- **Alcance por workspace (Cloud):** los tokens de API/acceso están vinculados a un workspace, por lo que se requiere un **workspace** para Cloud; OAuth es de contexto de usuario y descubre automáticamente los workspaces accesibles.
- **Webhook:** cada repositorio incorporado necesita un webhook a `…/sensei/bitbucket/webhooks` (con el secreto de la conexión, verificado mediante HMAC-SHA256 `X-Hub-Signature`) suscrito a los eventos **Push**, **Pull request** (created/updated/merged/declined) y **Pull request comment**.
- **Compuerta de build status:** el status check del PR se publica como un **build status** de Bitbucket en el commit de cabecera (`INPROGRESS` → `SUCCESSFUL`/`FAILED`). Bitbucket no tiene un estado *neutral*, por lo que un escaneo no bloqueante se asigna a `SUCCESSFUL` y el comentario de resumen lleva el detalle. El enlace de build status debe ser una URL pública, por lo que usa su host de DefectDojo.
- **Nombres de repositorio:** `workspace/repo` (Cloud) o `PROJECTKEY/repo` (Server/Data Center).
- **Server/Data Center:** configure la **Base URL** a su host; DefectDojo usa la API REST v1.0 y las rutas git `/scm/…`.

## Particularidades de Azure DevOps

Azure DevOps Repos se admite mediante un **Personal Access Token**. El comportamiento de escaneo y corrección es idéntico; estos son los detalles específicos de Azure:

- **Conexión:** un **PAT** con el alcance **Code (Read, Write, & Manage)**, más la **organización**. Las apps OAuth de Azure DevOps están siendo retiradas, por lo que un PAT es la credencial recomendada. Consulte [Configurar Sensei](/sensei/setup_sensei/#connect-azure-devops).
- **Webhook:** los **Service Hooks** de Azure se autentican con HTTP **Basic** (no un HMAC) y usan **una suscripción por evento**. Cree suscripciones a `…/sensei/azure/webhooks` para **Code pushed** y **Pull request created/updated/merged**, con el nombre de usuario/contraseña Basic de la conexión.
- **Compuerta de commit status:** el status check del PR se publica como un **commit status** de Git en el commit de cabecera.
- **Nombres de repositorio:** `project/repo` (la organización se almacena en la conexión).
- **Azure DevOps Server:** configure la **Base URL** a la URL de su colección on-premises.

## Particularidades de GitHub Enterprise Server

GitHub Enterprise Server usa el **mismo modelo de GitHub App** que github.com; solo cambia el host:

- **Conexión:** dado que el flujo de creación automática por manifiesto de App es exclusivo de github.com, cree la App **manualmente** en su host de GHES e ingrese sus credenciales más el **Enterprise host** mediante **Set up manually**. Consulte [Conectar GitHub Enterprise Server](/sensei/setup_sensei/#connect-github-enterprise-server). DefectDojo deriva la API (`/api/v3`) y los orígenes web a partir del host.
- **Coexistencia:** una conexión de App de github.com y una conexión de App de GHES pueden configurarse en la misma instancia; cada repositorio se resuelve a la conexión mediante la cual fue incorporado.
- **Alcanzabilidad:** DefectDojo debe poder alcanzar el host de la API de GHES, y GHES debe poder alcanzar el endpoint `…/sensei/webhooks` de DefectDojo (los hosts internos están bien si ambos lados pueden conectarse).

## Solución de problemas

- **El botón de Sensei en un hallazgo dice "Configure Product."** El Producto del hallazgo no está incorporado. Haga clic en él para incorporar un repositorio para ese Producto y luego vuelva al hallazgo.
- **Una corrección muestra "Failed" en Auto-fix Candidates o Scan Activity.** Abra **Scan Activity** y revise el **Root Cause** / **Details** de esa ejecución. Las correcciones fallidas permanecen listadas para que no desaparezcan antes de producir un PR; puede volver a prepararlas y reintentar.
- **Un repositorio no aparece listado al incorporar.** Solo se muestran los repositorios a los que la conexión tiene acceso. En **GitHub**, confirme que la App está instalada en la organización correcta y que su acceso a repositorios incluye el repositorio. En **GitLab**, confirme que el alcance del token de acceso cubre el proyecto. En **Bitbucket Cloud**, confirme que el **workspace** está configurado (los tokens están limitados por workspace). En **Azure DevOps**, confirme que la organización del PAT coincide y que se otorgó su alcance **Code**.
- **Los escaneos o correcciones nunca se inician después de un webhook.** Confirme que el webhook del repositorio apunta al receptor del proveedor (`…/sensei/{gitlab,bitbucket,azure}/webhooks`, o `…/sensei/webhooks` para GitHub) con el secreto/credenciales correctos, y que está suscrito a los eventos de push + pull request (+ comment). Las **entregas recientes** del proveedor deberían mostrar `HTTP 200`. Las ejecuciones activadas por webhook solo se disparan para repositorios incorporados en modo **hosted**; un push a una rama que no es la predeterminada se escanea a través de su pull request, no por sí solo.
- **No pasa nada después de un escaneo.** Verifique que las correcciones automáticas estén habilitadas (y que sus umbrales de severidad/riesgo coincidan con los hallazgos) en la configuración del repositorio, y que su cuota de **Fixes** no esté agotada.

> **🔎 Aún en BETA:** Sensei evoluciona rápidamente. Si el comportamiento no coincide con esta guía, consulte el [changelog de Pro](/releases/pro/changelog/) para ver cambios recientes.
