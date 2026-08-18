---
title: Configurar Sensei
description: Conecte GitHub, GitLab, Bitbucket o Azure DevOps, e incorpore un repositorio
  para el escaneo alojado
draft: false
audience: pro
weight: 2
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Sensei es una función exclusiva de DefectDojo Pro y actualmente está en fase BETA.</span>

Configurar Sensei consta de dos partes: **conectar un proveedor de control de código fuente** y luego **incorporar los repositorios** que desea escanear. Para hacerlo necesita un rol global de **Maintainer** o **Owner**. Sensei admite:

- **GitHub**: una GitHub App (github.com o **GitHub Enterprise Server**).
- **GitLab**: un token de acceso (gitlab.com o autoalojado).
- **Bitbucket**: Cloud o Server/Data Center, mediante OAuth (recomendado), un token de API de Atlassian o un token de acceso.
- **Azure DevOps**: un Personal Access Token.

La incorporación, la configuración, el escaneo y la corrección son iguales para todos los proveedores; solo difiere la conexión inicial. Esta página cubre [conectar una GitHub App](#connect-a-github-app), [GitHub Enterprise Server](#connect-github-enterprise-server), [GitLab](#connect-gitlab), [Bitbucket](#connect-bitbucket) y [Azure DevOps](#connect-azure-devops); a partir del paso [Seleccionar repositorios](#select-repositories) el proceso es compartido.

**Add Repositories** en el hub de Sensei es el punto de entrada para ambos casos. Abre un menú que lista cada conexión por su nombre: elija una para seleccionar repositorios desde ella, o elija **Connect a new source** para configurar un proveedor que aún no haya conectado. Si no hay nada conectado, se pasa directamente al flujo de conexión.

![El menú Add Repositories](images/add_repositories_menu.png)

## Conexiones

Una **conexión** es una identidad de control de código fuente configurada: un registro de GitHub App, un token de GitLab, un workspace de Bitbucket o una organización de Azure DevOps. Desde una conexión se incorporan repositorios, y se administra o desconecta desde la página **Connections** (el botón **Connections** en el hub de Sensei).

![Conexiones de Sensei](images/connections.png)

La tabla muestra la etiqueta, la identidad, el número de repositorios incorporados, la fecha de creación y el proveedor de cada conexión. Use las acciones de fila (el menú a la izquierda de cada fila) para administrar la conexión en su proveedor, agregar repositorios desde esa conexión, abrirla para editarla (**Update credentials**, o **Manage App & installations** para GitHub), o desconectarla.

![Acciones de la fila de una conexión](images/connection_row_menu.png) **Add a connection** nunca muestra los detalles de una conexión existente. Todo lo relativo a una conexión que ya tiene está en su propia pantalla, a la que se llega desde su fila.

### Varias organizaciones por proveedor

Una instancia puede tener **tantas conexiones como necesite, para cada proveedor**, una por organización, grupo o workspace:

- **GitHub:** instale la App en cada organización o cuenta de usuario (**Install on another account**). Un único registro de App cubre todas ellas. Para mantener registros separados, por ejemplo un host de GitHub Enterprise Server junto con github.com, use **Register another GitHub App**. El estado propio de una App (sus instalaciones, las aprobaciones de permisos, **Install on another account** y **Disconnect this App**) vive en la pantalla de esa conexión, a la que se accede con **Manage App & installations** en su fila. Con más de un registro, un selector allí permite alternar entre ellos.
- **GitLab:** una conexión por token de grupo o de proyecto, incluidas varias en el mismo host (`gitlab.com` más autoalojado).
- **Bitbucket:** una conexión por workspace.
- **Azure DevOps:** una conexión por organización, ya que un PAT tiene alcance a nivel de organización.

Cada vez que pasa por **Connect** en la página Connections se **agrega** una conexión, de modo que conectar un segundo grupo o workspace nunca reemplaza al primero. Asigne a cada una una **Connection Label** para distinguirlas en la tabla. Cada repositorio registra la conexión mediante la cual se incorporó, y sus escaneos, pull requests y correcciones usan la credencial de esa conexión. Cuando existe más de una conexión para un proveedor, la incorporación pregunta cuál usar en lugar de elegir una por usted.

Para rotar un token, un PAT o una contraseña de aplicación, use **Update credentials** en la fila de esa conexión. La pantalla que se abre corresponde a una única conexión: se titula **Edit connection: \<label\>**, y al guardar se actualiza esa conexión en lugar de agregar otra. Si se accede en cambio desde **Connect**, se titula **Add a connection**. (Las credenciales de la GitHub App se administran en GitHub.)

La **URL del webhook de un proveedor es compartida por todas sus conexiones**, y cada conexión verifica su propio secreto, por lo que no necesita una URL distinta por grupo, workspace u organización.

> **⚠️ Desconectar es destructivo:** desconectar una conexión la elimina **junto con todos los repositorios incorporados a través de ella**. Esta acción no se puede deshacer.

## Elegir un proveedor de control de código fuente

Desde el hub de Sensei, elija **Add Repositories → Connect a new source** (o **Connect** en la página Connections) para abrir **Add a connection**, y luego elija su proveedor de control de código fuente: **GitHub** (incluido GitHub Enterprise Server), **GitLab**, **Bitbucket** o **Azure DevOps**. El flujo de conexión de cada proveedor se describe a continuación.

![Add a connection, con el proveedor de control de código fuente elegido aquí](images/setup_providers.png)

## Conectar una GitHub App

Sensei funciona enteramente a través de una GitHub App. Instálela en su organización o cuenta y DefectDojo usará tokens de corta duración para abrir PRs, escanear y aplicar correcciones. No hay nada que pegar ni que rotar.

Desde el hub de Sensei, elija **Add Repositories → Connect a new source** (o **Connect** en la página Connections) para abrir **Add a connection**.

### Paso 1: Crear la App

Introduzca la **organización** propietaria de los repositorios que desea escanear (déjelo en blanco para crear la App en su cuenta personal) y luego haga clic en **Create GitHub App**. GitHub rellena automáticamente el nombre de la app, las URLs y los permisos; revíselos y confirme.

![Crear la GitHub App](images/setup_create_app.png)

GitHub abre una página de confirmación. Haga clic en **Create GitHub App for `<org>`** para registrar la app bajo esa organización.

![Confirmar la creación de la app en GitHub](images/github_create_app.png)

> **🔑 Consejo:** cree la App en la misma organización propietaria de los repositorios que planea escanear. El propietario de la App se establece en el momento de la creación.

### Paso 2: Instalar la App

De vuelta en DefectDojo, la app aparece como *configured*. Haga clic en **Install on GitHub** para instalarla en su organización.

![La propia pantalla de la conexión, donde se instala y administra la App](images/setup_install_app.png)

En GitHub, confirme la ubicación de la instalación (su organización), elija **All repositories** u **Only select repositories**, y revise los permisos solicitados. Sensei necesita acceso de lectura a actions, issues y metadata, y acceso de lectura/escritura a checks, code, pull requests, secrets y workflows para poder escanear y abrir PRs de corrección. Haga clic en **Install**.

![Instalar la App en su organización](images/github_install_app.png)

## Conectar GitLab

Sensei también admite **GitLab**, tanto instancias de **gitlab.com** como **autoalojadas**. En lugar de una GitHub App, GitLab se conecta con un **token de acceso de proyecto o de grupo** más un webhook; Sensei usa ese token para escanear, abrir merge requests y aplicar correcciones.

Desde el hub de Sensei, elija **Add Repositories → Connect a new source** (o **Connect** en la página Connections) para abrir **Add a connection**, y luego seleccione **GitLab** como proveedor de control de código fuente.

### Paso 1: Crear un token de acceso

En GitLab, abra el proyecto (o grupo) que desea escanear y vaya a **Settings → Access tokens → Add new token**:

- **Role:** **Developer**, suficiente para hacer push de ramas de corrección y abrir merge requests. Elija **Maintainer** si las reglas de push del proyecto lo exigen.
- **Scopes:** **`api`** y **`write_repository`**.

Cree el token y copie el valor `glpat-…` generado (GitLab lo muestra solo una vez).

> **🔑 Consejo:** un token de acceso de **group** permite incorporar cualquier proyecto de ese grupo; un token de acceso de **project** está limitado a ese único proyecto.

### Paso 2: Conectar

De vuelta en **Add a connection** con **GitLab** seleccionado, complete:

- **GitLab Base URL:** `https://gitlab.com`, o la URL de su instancia autoalojada (por ejemplo `https://gitlab.example.com`).
- **Access Token:** el token `glpat-…` del Paso 1.
- **Webhook Secret:** déjelo en blanco para generarlo automáticamente (recomendado). Agregará este secreto al webhook en el siguiente paso.

Haga clic en **Add GitLab connection**. DefectDojo valida el token, lo almacena cifrado y a partir de ahí puede listar proyectos, abrir merge requests y ejecutar escaneos.

### Paso 3: Agregar el webhook

Para que DefectDojo reciba eventos de push, merge request y comentarios, agregue un webhook a **cada** proyecto de GitLab que planee incorporar (**Settings → Webhooks → Add new webhook**):

- **URL:** la URL del webhook mostrada en la pantalla de la conexión (`https://<your-defectdojo-host>/sensei/gitlab/webhooks`).
- **Secret token:** el secreto del webhook del Paso 2.
- **Trigger events:** habilite **Push events**, **Merge request events** y **Comments**.

Deje habilitada la verificación SSL, haga clic en **Add webhook** y luego use **Test → Push events** para confirmar que DefectDojo responde con **HTTP 200**.

Después de conectar, haga clic en **Choose projects** y continúe con [Seleccionar repositorios](#select-repositories); la incorporación, la configuración y el escaneo funcionan igual que con GitHub.

> **Equivalencias en GitLab:** donde esta guía dice *pull request*, GitLab usa un **merge request**; el **status check** del pull request se publica como un **commit status** de GitLab en el commit de cabecera del merge request.

## Conectar GitHub Enterprise Server

Sensei funciona con **GitHub Enterprise Server (GHES)** usando el mismo modelo de GitHub App que github.com. Solo cambia el host. Dado que el flujo de creación automática mediante App-manifest solo existe en github.com, en GHES **debe crear la App manualmente** en su host empresarial y luego introducir sus credenciales, junto con el host, en DefectDojo.

### Paso 1: Crear la App en su host de GHES

En su instancia de GitHub Enterprise Server, vaya a **Settings → Developer settings → GitHub Apps → New GitHub App** y cree una App con los mismos permisos que Sensei usa en github.com: lectura para actions, issues y metadata, y lectura/escritura para checks, code, pull requests, secrets y workflows. Apunte su webhook a `https://<your-defectdojo-host>/sensei/webhooks`. Genere y descargue una **private key**, y anote el **App ID** (y el **Client ID/Secret** de OAuth si los configura).

### Paso 2: Conectar manualmente

En la pantalla de la conexión con **GitHub** seleccionado, haga clic en **Set up manually instead** y complete:

- **App ID** y **Private Key (PEM)** del Paso 1 (además de Client ID/Secret y Webhook Secret si están configurados).
- **GitHub Enterprise host:** el host de su instancia, por ejemplo `https://github.example.com`. DefectDojo deriva de él los orígenes de la API (`/api/v3`) y web. Déjelo en blanco para github.com.

Haga clic en **Save App credentials**. DefectDojo las valida contra su host empresarial; luego instale la App y continúe con [Seleccionar repositorios](#select-repositories).

> **🔑 Consejo:** el host debe ser accesible desde DefectDojo (y DefectDojo debe ser accesible desde GHES para los webhooks). Los hosts de uso interno son válidos siempre que ambos puedan comunicarse entre sí en su red.

## Conectar Bitbucket

Sensei admite **Bitbucket Cloud** (`bitbucket.org`) y **Bitbucket Server / Data Center** (autoalojado). Se ofrecen tres métodos de autenticación no obsoletos; **se recomienda OAuth**.

Desde el hub de Sensei, elija **Add Repositories → Connect a new source** (o **Connect** en la página Connections), y luego seleccione **Bitbucket** y su **deployment** (Cloud o Server/Data Center) y el tipo de **authentication**.

### Paso 1: Crear la credencial

**OAuth (recomendado):** en Bitbucket, abra **Workspace settings → OAuth consumers → Add consumer**:

- **Callback URL:** la que se muestra en la pantalla de la conexión (`https://<your-defectdojo-host>/sensei/bitbucket/oauth/callback`).
- **Permissions:** **Account: Read**, **Repositories: Read + Write**, **Pull requests: Read + Write** (agregue **Webhooks: Read + Write** si va a administrar webhooks mediante la API).

Guárdelo y luego copie el **Key** (Client ID) y el **Secret** del consumer.

**API token**: cree un **API token** de Atlassian en `id.atlassian.com` (Account settings → Security → API tokens). Úselo junto con su **email de cuenta de Atlassian**.

**Access token**: cree un **Access Token** de repositorio o de workspace en Bitbucket y úselo como credencial bearer.

### Paso 2: Conectar

De vuelta en la pantalla de la conexión con **Bitbucket** seleccionado:

- **OAuth:** pegue el **Client ID** y el **Client Secret**, y luego haga clic en **Connect with Bitbucket**. Apruebe la pantalla de consentimiento; DefectDojo almacena los tokens resultantes cifrados y los renueva automáticamente.
- **API token / Access token:** introduzca su **Workspace** (Cloud), su **email** (solo para autenticación con API token) y el **token**. Para Server/Data Center, introduzca la **Base URL** de su host.

DefectDojo valida la credencial y a partir de ahí puede listar repositorios, abrir pull requests y ejecutar escaneos.

### Paso 3: Agregar el webhook

Agregue un webhook a **cada** repositorio de Bitbucket (**Repository settings → Webhooks → Add webhook**):

- **URL:** la URL del webhook mostrada en la pantalla de la conexión (`https://<your-defectdojo-host>/sensei/bitbucket/webhooks`).
- **Secret:** el secreto del webhook mostrado en la página (usado para la verificación HMAC-SHA256 `X-Hub-Signature`).
- **Triggers:** **Repository push**, **Pull request** (created, updated, merged, declined) y **Pull request comment created** (para comentarios `/fix`).

Después de conectar, haga clic en **Choose repositories** y continúe con [Seleccionar repositorios](#select-repositories).

> **Particularidades de Bitbucket:** los repositorios se identifican como `workspace/repo` (Cloud) o `PROJECTKEY/repo` (Server). El **status check** del pull request se publica como un **build status** de Bitbucket en el commit de cabecera. OAuth es el método recomendado porque funciona en el contexto del usuario (sin las peculiaridades de workspace/username) y se renueva automáticamente; las app passwords están obsoletas y no son compatibles.

## Conectar Azure DevOps

Sensei admite **Azure DevOps Repos** mediante un **Personal Access Token (PAT)**. Los repositorios existen dentro de una jerarquía de **organization → project → repository**.

Desde el hub de Sensei, elija **Add Repositories → Connect a new source** (o **Connect** en la página Connections), y luego seleccione **Azure DevOps**.

### Paso 1: Crear un PAT

En Azure DevOps, abra **User settings → Personal access tokens → New Token**:

- **Organization:** la organización cuyos repositorios desea escanear.
- **Scopes:** **Code (Read, Write, & Manage)**, que cubre clonar, hacer push de ramas de corrección y abrir pull requests.

Cree el token y cópielo (Azure DevOps lo muestra solo una vez).

### Paso 2: Conectar

De vuelta en la pantalla de la conexión con **Azure DevOps** seleccionado, complete:

- **Base URL:** `https://dev.azure.com`, o la URL de la colección de su **Server** de Azure DevOps.
- **Organization:** el nombre de su organización.
- **Personal Access Token:** el token del Paso 1.

Haga clic en **Connect**. DefectDojo valida el PAT contra `…/_apis/projects`, lo almacena cifrado y a partir de ahí puede listar repositorios, abrir pull requests y ejecutar escaneos.

### Paso 3: Agregar el service hook

Azure DevOps autentica sus **Service Hooks** con HTTP Basic, y usa **una subscription por tipo de evento**. En **Project settings → Service hooks → Create subscription → Web Hooks**, cree una subscription para cada uno de **Code pushed**, **Pull request created**, **Pull request updated** y **Pull request merged**, todas con:

- **URL:** la URL del webhook mostrada en la pantalla de la conexión (`https://<your-defectdojo-host>/sensei/azure/webhooks`).
- **Basic authentication username / password:** los valores mostrados en la página.

Después de conectar, haga clic en **Choose repositories** y continúe con [Seleccionar repositorios](#select-repositories).

> **Particularidades de Azure DevOps:** los repositorios se identifican como `project/repo` (la organización se almacena en la conexión). El **status check** del pull request se publica como un **commit status** de Git en el commit de cabecera.

## Seleccionar repositorios

Una vez instalada la App, DefectDojo muestra los repositorios a los que tiene acceso. Solo se listan los repositorios a los que Sensei tiene **push access**; la remediación funciona haciendo push de una rama y abriendo un pull request, por lo que los repositorios sin acceso de push quedan ocultos. Se abre un pull request contra la **default branch** de cada repositorio.

![Seleccionar los repositorios a incorporar](images/setup_repo_picker.png)

Use **Add** para seleccionar uno o más repositorios, y luego haga clic en **Configure N repo(s)**. Los repositorios ya incorporados se marcan como **Configured** y no se pueden agregar dos veces.

### Un repositorio no aparece en la lista

El selector solo muestra los repositorios a los que se le concedió acceso a la conexión. Un repositorio al que nunca le dio acceso a Sensei no aparecerá. Si la conexión cubre un único repositorio que ya está incorporado, la lista parecerá no tener nada para agregar. Amplíe lo que la conexión puede ver y luego vuelva a este paso:

- **GitHub:** use **Manage repository access for \<account\>** para abrir la página de esa instalación en GitHub, donde puede agregar repositorios a la instalación. Use **Install on another account** para instalar la App en una segunda organización o cuenta de usuario.
- **GitLab, Bitbucket, Azure DevOps:** la lista está limitada por la credencial que conectó. Otorgue al token, app password o PAT acceso al proyecto (un token de **group** de GitLab cubre todos los proyectos del grupo), o agregue una segunda conexión para otro grupo, workspace u organización.

## Configurar un repositorio

El formulario **Configure Repository** controla cómo Sensei escanea e informa sobre el repositorio.

![Configurar un repositorio](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted):** los escaneos se ejecutan en DefectDojo. No se agrega nada a su repositorio; los escaneos se pueden disparar bajo demanda o automáticamente a través de la GitHub App.
- **PR Reporting:** elija qué publica Sensei de vuelta en los pull requests:
  - Publicar un status check en el pull request.
  - Marcar el check como fallido cuando se introducen hallazgos net-new.
  - Publicar un comentario con el resumen de resultados en cada commit.
  - Crear automáticamente el baseline de la base branch en el primer PR.
- **Automated Fixes:** habilite *Stage matching findings for one-click auto-fix after each scan* para que Sensei prepare candidatos automáticamente (ver más abajo).

### Criterios de corrección automatizada

Cuando las correcciones automatizadas están habilitadas, los hallazgos que cumplen sus criterios se preparan como **candidates** en la página de Sensei después de cada escaneo. Nada se ejecuta (ni se incurre en costo de LLM) hasta que usted lo aprueba, a menos que habilite la remediación automática.

![Criterios de corrección automatizada y opciones avanzadas](images/repo_config_advanced.png)

- **Severity threshold:** califican los hallazgos con esta severidad o superior (elija *Any* para filtrar solo por riesgo).
- **Risk threshold:** también califican los hallazgos con este nivel de riesgo o superior (combinado con la severidad mediante OR).
- **Open fix PRs against branch:** la rama contra la que apuntan los pull requests de corrección automática; se puede anular por corrección individual al aprobarla.
- **Exclude findings tagged:** omite los hallazgos que llevan las etiquetas que indique (por ejemplo, `no-fix`).
- **Automatically remediate candidates:** cuando está habilitado, una verificación en segundo plano (aproximadamente cada 5 minutos) abre pull requests de corrección para los candidates preparados de este repositorio sin esperar aprobación, hasta alcanzar su cuota de correcciones. Déjelo desactivado para revisar y aprobar cada candidate usted mismo.

En **Advanced options** puede vincular el repositorio a un producto/activo existente o crear uno nuevo, establecer la organización, y definir una severidad mínima por debajo de la cual los hallazgos no se informan ni se usan en el merge gate.

## Incorporar

Haga clic en **Onboard for hosted scanning**. El repositorio aparece en el hub de Sensei con estado **Activo**, listo para escanear. Desde aquí, continúe con [Corregir hallazgos con Sensei](/sensei/fixing_findings/).
