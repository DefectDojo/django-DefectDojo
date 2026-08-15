---
title: Referencia de herramientas de Conectores Upstream
description: Nuestra lista de herramientas de Conector compatibles y cómo configurarlas
  con DefectDojo
aliases:
- /es/import_data/pro/connectors/connectors_tool_reference/
- /es/en/connecting_your_tools/connectors/connectors_tool_reference
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los Conectores Upstream son una función exclusiva de DefectDojo Pro.</span>

Al configurar un Conector para una herramienta compatible, deberá proporcionar a DefectDojo información específica relacionada con la API de la herramienta. Como mínimo, necesitará:

* **Location** \-un campo que generalmente hace referencia a la URL de su herramienta dentro de su red,
* **Secret** \- generalmente, una clave de API.

Algunas herramientas requerirán campos adicionales relacionados con la API además de **Location** y **Secret**. También pueden requerir que realice cambios de su lado para admitir un Conector entrante desde DefectDojo.

![imagen](images/connectors_tool_reference.png)

Cada herramienta tiene una configuración de API diferente, y esta guía está diseñada para ayudarlo a configurar la API de la herramienta para que DefectDojo pueda conectarse.

Siempre que sea posible, recomendamos crear una nueva cuenta 'DefectDojo Bot' dentro de su herramienta de seguridad, que solo será utilizada por el Conector. Esto le ayudará a diferenciar mejor entre las acciones realizadas manualmente por su equipo y las acciones automatizadas realizadas por el Conector.

# **Conectores de activos**

La mayoría de los Conectores importan **hallazgos** desde una herramienta de seguridad. Los **Conectores de activos** funcionan de forma diferente: en su lugar, importan su **inventario de activos**. Un Conector de activos enumera los activos que existen en una plataforma externa (por ejemplo, los repositorios de un grupo de GitLab) y crea y mantiene automáticamente los **Productos** (Activos) y **Tipos de producto** (Organizaciones) correspondientes en DefectDojo. Un Conector de activos no importa hallazgos.

* Tanto **Discover** como **Sync** concilian la lista de activos. Los activos nuevos aparecen como Registros `NEW`; una vez asignados (automáticamente, si la asignación automática está habilitada), DefectDojo crea el Producto y lo agrupa bajo un Tipo de producto derivado de la herramienta — por ejemplo, el namespace de GitLab o el proyecto de Azure DevOps.
* Si más adelante se elimina un activo en el origen (por ejemplo, se elimina un repositorio), su Registro asignado se marca como `MISSING` en la siguiente Sync para que su equipo pueda triarlo. DefectDojo nunca elimina un Producto de forma silenciosa.

Azure DevOps, Backstage, Bitbucket, GitHub, GitLab, Jira Service Management Assets y ServiceNow CMDB son Conectores de activos. runZero es principalmente un Conector de activos, pero opcionalmente puede importar vulnerabilidades como hallazgos. Todos los demás Conectores listados a continuación importan hallazgos.

# **Conectores compatibles**

## **Acunetix 360**

El conector de Acunetix 360 importa **hallazgos de vulnerabilidades DAST** desde la plataforma en la nube de Acunetix 360 (la plataforma Invicti). DefectDojo descubre los sitios web escaneados de su cuenta y crea un Registro para cada **sitio web**; los hallazgos de un sitio web provienen de su último análisis completado.

**Tenga en cuenta:** este conector es para **Acunetix 360** (el producto en la nube en `online.acunetix360.com`). No es para el escáner local Acunetix Standard/Premium, que tiene una API diferente.

#### Requisitos previos

Una cuenta de Acunetix 360 y una **credencial de API**: en Acunetix 360, abra el menú de su cuenta \> **API Settings**, anote el **API User ID** y genere un **API Token**. El conector se autentica con estos valores como credenciales HTTP Basic, por lo que se recomienda una cuenta de servicio dedicada para distinguir la actividad automatizada de las acciones manuales del equipo.

#### Asignaciones del conector

1. Ingrese la URL de su Acunetix 360 en el campo **Location**: `https://online.acunetix360.com`.
2. Ingrese el API User ID en el campo **API User ID**.
3. Ingrese el API Token en el campo **API Token**.
4. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

Cada sitio web escaneado se convierte en un Registro. Los hallazgos provienen del último análisis completado del sitio web; las vulnerabilidades que Acunetix 360 ha marcado como **Riesgo aceptado** o **Falso positivo** igualmente se importan, pero se marcan como inactivas (riesgo aceptado o falso positivo) para que el producto de DefectDojo refleje la clasificación del proveedor.

## **Akamai API Security**

El conector de Akamai API Security usa una clave de API para extraer hallazgos de seguridad desde la API de Akamai. DefectDojo descubrirá su entorno de Akamai y creará Registros independientes para cada **Application** y **Host** configurados en su cuenta.

#### Prerrequisitos

Necesitará una clave de API con acceso a la API de Akamai. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que se distinga claramente la actividad automatizada de las acciones manuales del equipo.

#### Asignaciones del conector

1. Ingrese la URL base de la API de Akamai en el campo **Location**. Esta URL es específica de su instancia de Akamai: por ejemplo
2. Ingrese una **API Key** válida en el campo **Secret**.

DefectDojo asignará las **Applications** y los **Hosts** como Registros independientes. Cada Application aparecerá como `{name} (application)` y cada Host como `{name} (host)` en su lista de Registros.

## **Anchore**

El conector de Anchore usa el token de API de un usuario para extraer datos de Anchore Enterprise.  Los Productos se asignarán y descubrirán en función de las "Applications", que se componen de varias Images en Anchore - consulte la [documentación de Anchore Enterprise](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) para obtener más información.

#### Asignaciones del conector

1. La URL de Anchore en el campo **Location**: esta es la URL donde accede a Anchore.
2. Ingrese una API Key válida en el campo Secret. Esta es la clave de API asociada con su cuenta de servicio de Burp.

Consulte la [documentación oficial de Anchore](https://docs.anchore.com/current/docs/) para obtener más información sobre cómo crear un token para Anchore.

## **AWS Security Hub**

El conector de AWS Security Hub usa una clave de acceso de AWS para interactuar con las API de Security Hub.

#### Prerrequisitos

En lugar de usar la clave de acceso de AWS de un miembro del equipo, recomendamos crear un IAM User en su cuenta de AWS específicamente para DefectDojo, con los permisos de ese usuario limitados a los necesarios para interactuar con Security Hub.

La política "**[AWSSecurityHubReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSSecurityHubReadOnlyAccess.html)**" de AWS proporciona el nivel de acceso necesario para un conector. Si desea escribir una política personalizada para un Conector, deberá incluir los siguientes permisos:

* [DescribeHub](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DescribeHub.html)
* [GetFindingAggregator](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingAggregator.html)
* [GetFindings](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindings.html)
* [ListFindingAggregators](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_ListFindingAggregators.html)

Una definición de política funcional podría verse de la siguiente manera:

```
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Sid": "AWSSecurityHubConnectorPerms",  
            "Effect": "Allow",  
            "Action": [  
                "securityhub:DescribeHub",  
                "securityhub:GetFindingAggregator",  
                "securityhub:GetFindings",  
                "securityhub:ListFindingAggregators"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```

**Tenga en cuenta:** es posible que en el futuro necesitemos usar acciones de API adicionales para ofrecer la mejor experiencia posible, lo que requerirá actualizaciones de esta política.

Una vez que haya creado su usuario de IAM y le haya asignado los permisos necesarios mediante una política/rol adecuado, deberá generar una clave de acceso, que luego podrá usar para crear un Conector.

#### Asignaciones del conector

1. Ingrese el [AWS API Endpoint correspondiente a su región](https://docs.aws.amazon.com/general/latest/gr/sechub.html#sechub_region) en el campo **Location****:**  por ejemplo, para obtener resultados de la región `us-east-1`, debería usar

`https://securityhub.us-east-1.amazonaws.com`
2. Ingrese una **AWS Access Key** válida en el campo **Access Key**.
3. Ingrese una **Secret Key** correspondiente en el campo **Secret Key**.

DefectDojo puede extraer Hallazgos de más de una región mediante la función de **agregación entre regiones** de Security Hub. Si la [agregación entre regiones](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) está habilitada, debe proporcionar el endpoint de la API de su "**Aggregation Region**". Para las regiones adicionales vinculadas se crearán ProductRecords en DefectDojo según el ID de su cuenta de AWS y el nombre de la región.

## **Azure DevOps**

El conector de Azure DevOps es un **Conector de activos**: enumera los repositorios git de cada proyecto de su organización de Azure DevOps y crea un Activo de DefectDojo para cada repositorio, agrupados en Organizaciones según el proyecto de Azure DevOps. No se importa ningún hallazgo.

#### Prerrequisitos

Necesitará un Personal Access Token (PAT) para la organización. Recomendamos generar el token desde una cuenta de servicio dedicada. Solo se requieren ámbitos de lectura:

1. En Azure DevOps, abra **User settings \> Personal access tokens \> New Token**.
2. Haga clic en **Show all scopes** y, a continuación, seleccione **Code: Read** y **Project and Team: Read**.

Solo se admite Azure DevOps Services (dev.azure.com); actualmente no se admite Azure DevOps Server on-premise.

#### Asignaciones del conector

1. Ingrese la URL de su organización en el campo **Location**: `https://dev.azure.com/{your-organization}`. También se aceptan las URL heredadas `https://{your-organization}.visualstudio.com`, y cualquier segmento de ruta adicional (por ejemplo, un enlace a un proyecto específico) se ignora.
2. Ingrese el PAT en el campo **Secret**.

Cada repositorio se convierte en un Registro con el nombre del repositorio, agrupado por su **proyecto** de Azure DevOps. Los repositorios deshabilitados se omiten, por lo que deshabilitar o eliminar un repositorio marca su Registro como `MISSING` en la siguiente Sync.

## **Backstage**

El conector de Backstage es un **conector de activos**: en lugar de importar Hallazgos, extrae su Software Catalog de [Backstage](https://backstage.io) hacia DefectDojo y mantiene sincronizada su jerarquía de Productos y la propiedad de los equipos con ella. Está diseñado para organizaciones que mantienen su inventario de servicios y su estructura organizativa en Backstage y desean que DefectDojo refleje esa estructura en lugar de mantenerla manualmente.

#### Qué se asigna

| Backstage | DefectDojo |
|---|---|
| **System** | Tipo de producto (los Components sin System se agrupan bajo un Tipo de producto configurable "Backstage / Uncategorized") |
| **Component** | Producto — con el nombre tomado de la entidad `title` (o de `name` si no existe), junto con la descripción del catálogo |
| **Owning Group** (relación `ownedBy`) | Un Grupo de DefectDojo vinculado al Producto (rol predeterminado: Maintainer, configurable) |
| **Owner email** (correo del perfil del Group, o correo del propietario User) | Un miembro del Producto, cuando ya existe un usuario de DefectDojo con ese correo (nunca se crean usuarios) |
| `metadata.tags`, `spec.type`, `spec.lifecycle`, namespace, domain | Etiquetas de Producto con el prefijo `backstage:` |
| `metadata.annotations` | Se almacena en el Registro (con límite); ciertas anotaciones seleccionadas pueden promoverse a atributos de primera clase o a etiquetas mediante **Annotation Mappings** |

Los Registros se identifican mediante el `metadata.uid` asignado por el servidor de la entidad, por lo que los cambios de nombre en Backstage actualizan el Producto asignado **en el mismo lugar** en la siguiente sincronización — sin duplicados. El nombre del Producto siempre sigue al catálogo: para cambiar el nombre de un Producto gestionado por este conector, cambie el nombre del Component en Backstage (un cambio de nombre realizado del lado de DefectDojo, o un nombre personalizado asignado durante la asignación manual, se concilia con el nombre del catálogo en la siguiente sincronización a menos que colisione con otro Producto). Los cambios de propiedad mueven la asignación de grupo del Producto. Los Components que desaparecen del catálogo (o que están marcados con la anotación `backstage.io/orphan`) se marcan como **MISSING** — DefectDojo nunca elimina un Producto por sí mismo. La jerarquía de Domain y Group (equipos superiores) se registra únicamente como etiquetas/metadatos; no crea niveles de jerarquía adicionales.

#### Prerrequisitos

El conector se autentica con un **token de acceso externo estático** frente al backend de Backstage. En la configuración de su aplicación Backstage, defina un token y (recomendado) restríjalo al plugin de catálogo:

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

Genere un token aleatorio robusto (por ejemplo `openssl rand -hex 32`) y guárdelo en el entorno de su implementación de Backstage. Consulte la [documentación de autenticación servicio a servicio de Backstage](https://backstage.io/docs/auth/service-to-service-auth) para obtener más detalles.

#### Asignaciones del conector

1. Ingrese la **URL raíz del backend de Backstage** en el campo **Location**: por ejemplo `https://backstage.example.com` (el conector añade `/api/catalog`). Debe ser la URL del **backend**, no la de la interfaz web frontend.
2. Ingrese el token de acceso externo estático en el campo **Secret**.

Campos opcionales (déjelos en blanco para usar los valores predeterminados):

* **Namespaces** — namespaces del catálogo a importar, separados por comas; en blanco se importan todos los namespaces.
* **Component Types** — valores de `spec.type` separados por comas (p. ej. `service,website`); en blanco se importan todos los tipos.
* **Page Size** — tamaño de página para las consultas al catálogo (1\-500, valor predeterminado 250).
* **TLS Verification** — establézcalo en `false` solo si Backstage sirve un certificado que DefectDojo no puede verificar (CA interna); no se recomienda.
* **Uncategorized Product Type** — el Tipo de producto usado para los Components sin System (valor predeterminado `Backstage / Uncategorized`).
* **Owner Group Role** — el rol otorgado al equipo propietario en los Productos asignados (valor predeterminado `Maintainer`).
* **Annotation Mappings** — un objeto JSON que asigna claves de anotación a nombres de atributos del Registro, o a `"tag"` para importar una anotación como etiqueta de Producto, p. ej. `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`.

Con **Auto\-Map** habilitado, un único Discover \+ Sync genera toda la estructura de Tipo de producto / Producto / propiedad sin pasos manuales. Con Auto\-Map deshabilitado, los Components descubiertos aparecen como Registros a la espera de su decisión de asignación.

#### Limitaciones (v1)

* La **pertenencia a Group de Backstage no se sincroniza**: el conector crea/vincula el equipo propietario como un Grupo de DefectDojo, pero completar los usuarios de ese grupo queda a cargo de su proveedor de identidad o de los administradores.
* Solo los Components se convierten en Productos; las APIs, Resources y Domains no se importan como activos (los domains aparecen como etiquetas).
* Las etiquetas y anotaciones se normalizan y se limitan para ajustarse a los límites de campo de DefectDojo (los valores demasiado grandes se truncan).

**Una nota sobre la dirección inversa:** mostrar los hallazgos y las calificaciones de DefectDojo *dentro* de Backstage (en las páginas de entidad) es una extensión natural que se implementaría como un plugin de frontend de Backstage que consume la REST API de DefectDojo — queda deliberadamente fuera del alcance de este conector, que solo extrae datos del catálogo hacia DefectDojo.

## **Black Duck**

El conector de Black Duck importa hallazgos de **análisis de composición de software (SCA)** desde una instancia de Black Duck Hub (Synopsys / Black Duck). DefectDojo descubre todos los proyectos de la instancia y crea un Registro para cada **proyecto**; los hallazgos de un proyecto provienen de los componentes de la BOM vulnerables de su versión seleccionada.

#### Prerrequisitos

Un **token de API** de Black Duck para un usuario que pueda ver los proyectos que desea importar. En Black Duck, abra el menú de usuario \> **My Access Tokens** \> **Create New Token**, otórguele (como mínimo) acceso de lectura y copie el token cuando se muestre — solo se exhibe una vez. El conector intercambia este token por un bearer de corta duración en cada sincronización; nunca se almacena en texto claro más allá del campo secreto del conector.

#### Asignaciones del conector

1. Ingrese la URL de su hub de Black Duck en el campo **Location** — por ejemplo `https://your-company.app.blackduck.com`.
2. Ingrese el token de API en el campo **Secret**.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

Cada proyecto de Black Duck se convierte en un Registro. Por defecto el conector importa la versión **released** del proyecto (recurriendo a su primera versión si no existe); cada componente de la BOM vulnerable de esa versión se convierte en un hallazgo, titulado `{vulnerability} in {component}:{version}`.

Este conector es distinto de los parsers de Black Duck basados en archivos — sus hallazgos usan el tipo de análisis dedicado **Black Duck - Connectors Import**.

## **Bitbucket**

El conector de Bitbucket es un **Conector de activos**: enumera los repositorios de los workspaces de Bitbucket Cloud que usted indique y crea un Activo de DefectDojo para cada repositorio, agrupados en Organizaciones según el proyecto de Bitbucket. No se importa ningún hallazgo.

#### Prerrequisitos

Bitbucket Cloud requiere un token de API de Atlassian **con ámbitos (scoped)** — los tokens de API de Atlassian clásicos (sin ámbitos) son rechazados por Bitbucket con un error "API Token provided has no Bitbucket scopes".

1. Vaya a [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens) y elija **Create API token with scopes**.
2. Seleccione la aplicación **Bitbucket** y, a continuación, otorgue los ámbitos de lectura: `read:account:bitbucket`, `read:workspace:bitbucket`, `read:repository:bitbucket` y `read:project:bitbucket`.

Solo se admite Bitbucket Cloud (bitbucket.org). Bitbucket Server llegó a su fin de vida en 2024, y Bitbucket Data Center no es compatible.

#### Asignaciones del conector

1. Ingrese `https://bitbucket.org` en el campo **Location**.
2. Ingrese el correo de la cuenta de Atlassian a la que pertenece el token en el campo **Email**.
3. Ingrese el token de API con ámbitos en el campo **Secret**.
4. Ingrese uno o más slugs de workspace (separados por comas) en el campo **Workspace Slugs**. Este campo es obligatorio: los tokens de API con ámbitos de Bitbucket no pueden listar workspaces automáticamente, por lo que hay que indicarle a DefectDojo qué workspaces leer.

Cada repositorio se convierte en un Registro con el nombre del repositorio, agrupado por su **proyecto** de Bitbucket.

## **Bugcrowd**

El conector de Bugcrowd usa la REST API de Bugcrowd para importar submissions de sus programas de bug bounty y de divulgación de vulnerabilidades. DefectDojo descubre los programas a los que su token de API tiene acceso y crea un Registro para cada uno, importando las submissions de ese programa como hallazgos.

#### Prerrequisitos

Necesitará un **token de API** de Bugcrowd con acceso a los programas que desea importar. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada se distinga fácilmente de las acciones manuales del equipo. Genere el token en Bugcrowd en **Organization settings \> API credentials**; basta con acceso de lectura a submissions, programs y targets.

#### Asignaciones del conector

1. Ingrese `https://api.bugcrowd.com` en el campo **Location**.
2. Ingrese su token de API de Bugcrowd en el campo **Secret**. Se envía como encabezado `Authorization: Token`.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

Cada **program** de Bugcrowd se convierte en un Registro, y sus submissions se importan como hallazgos conservando la severidad de Bugcrowd. Las submissions duplicadas se excluyen, por lo que volver a importar no crea hallazgos repetidos para el mismo problema.

## **Bright Security**

El conector de Bright Security usa la API de [Bright](https://brightsec.com) (anteriormente NeuraLegion) para importar **hallazgos DAST**. DefectDojo descubre todos los scans a los que el token tiene acceso y crea un Registro para cada scan completado, e importa luego los issues de ese scan como hallazgos.

#### Prerrequisitos

Necesitará una **API key** de Bright, creada en la aplicación Bright en **User settings → API keys** (una clave `Org` o personal). La clave se envía en el encabezado `Authorization: Api-Key` y nunca se registra en logs.

#### Asignaciones del conector

1. Deje el campo **Location** en blanco para usar `https://app.brightsec.com`, o ingrese explícitamente su host de Bright.
2. Ingrese la API key de Bright en el campo **Secret**.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **scan** completado a un Registro y cada **issue** a un hallazgo: la severidad proviene de la propia calificación de Bright (Crítica/Alta/Media/Baja), se trasladan el puntaje CVSS, el CWE y la remediación, el punto de entrada afectado se convierte en el endpoint, y la evidencia de la solicitud/respuesta se incluye en la descripción. Los hallazgos se registran como hallazgos dinámicos y se deduplican según el id de issue de Bright.

Consulte la [documentación de la API de Bright](https://docs.brightsec.com/) para obtener más información.

## **BurpSuite**

El conector de Burp de DefectDojo llama a la GraphQL API de Burp para obtener datos. 

#### Prerrequisitos

Antes de configurar este conector, necesitará una clave de API de una Burp Service Account. Las cuentas de usuario de Burp no tienen claves de API de forma predeterminada, por lo que quizás deba crear un nuevo usuario específicamente para este fin. 

Consulte la [documentación de Burp](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) para obtener una guía sobre cómo configurar un usuario Service Account con una clave de API.

#### Asignaciones del conector

1. Ingrese la URL raíz de Burp en el campo **Location**: esta es la URL donde accede a la herramienta Burp.
2. Ingrese una API Key válida en el campo Secret. Esta es la clave de API asociada con su cuenta de Burp Service.

Consulte la [documentación oficial de Burp](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) para obtener más información sobre la API de Burp.

## **Censys**

El conector de Censys lee activos de tipo host desde Censys Platform e importa los servicios expuestos de cada host como hallazgos. Usa la API de búsqueda global de Censys Platform para enumerar los hosts a los que lo delimite.

#### Prerrequisitos

Necesitará una cuenta de Censys **Platform** con acceso a la API:

* Un **Personal Access Token**, creado en Censys Platform Console, en Personal Access Tokens.
* Su **Organization ID**, que se muestra en la misma página de configuración bajo "Current Organization". El acceso de la API al endpoint de búsqueda requiere una organización, por lo que se necesita un plan Starter o superior. Los tokens del plan gratuito no tienen Organization ID y no pueden usar la API de búsqueda.

Los datos de CVE y riesgo por host solo están disponibles en los planes Censys Core (enterprise), por lo que en planes inferiores los hallazgos representan servicios expuestos en lugar de vulnerabilidades.

Consulte la [documentación de la API de Censys Platform](https://docs.censys.com/reference/get-started) para obtener más información.

#### Asignaciones del conector

1. Ingrese `https://api.platform.censys.io` en el campo **Location**.
2. Ingrese su Personal Access Token en el campo **API Key**.
3. Ingrese su **Organization ID**.
4. Ingrese una **Search Query** que delimite la importación a sus propios activos, por ejemplo `host.autonomous_system.asn: <your ASN>` o `host.ip: 203.0.113.0/24`.
5. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo crea un Registro para cada host e importa sus servicios expuestos como hallazgos.

## **Checkmarx ONE**

El conector de Checkmarx ONE de DefectDojo llama a la API de Checkmarx para obtener datos.

#### **Asignaciones del conector**

1. Ingrese su **Tenant Name** en el campo **Checkmarx Tenant**. Este nombre debería ser visible en la página de inicio de sesión de Checkmarx ONE, en la esquina superior derecha:   
" Tenant: \<**su nombre de tenant**\> "  
​
![imagen](images/connectors_tool_reference_2.png)

2. Ingrese una clave de API válida. Es posible que deba generar una nueva: consulte la [documentación de la API de Checkmarx](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) para obtener más detalles.
3. Ingrese la ubicación de su tenant en el campo **Location**. Esta URL tiene el siguiente formato:  
​`https://<your-region>.ast.checkmarx.net/` . Su Región se encuentra al comienzo de la URL de Checkmarx cuando usa la aplicación Checkmarx. **<https://ast.checkmarx.net>** es el servidor principal de EE. UU. (que no tiene prefijo de región).

#### **Manejo de branches**

Por defecto, cada sincronización importa los hallazgos del **único scan completado más reciente de un proyecto, sin importar el branch**. Si su CI escanea muchos branches, el branch que resulte haber escaneado en último lugar "gana" esa sincronización: los hallazgos que solo existen en otros branches no se importan, y la conciliación de cierre de antiguos de la sincronización puede hacer que los hallazgos se abran y cierren alternadamente a medida que distintos branches se turnan como el scan más reciente.

Dos campos opcionales controlan este comportamiento:

- **Branch**: fija cada proyecto a un único nombre de branch — solo se importan los scans de ese branch. Es un valor global único para todo el conector, por lo que se adapta a flotas donde cada proyecto usa el mismo branch de larga duración (p. ej. `main`).
    - Se admite un **comodín `*`**. Un valor de Branch que contenga `*` selecciona *todos* los branches coincidentes en lugar de uno solo — por ejemplo `release/*` importa cada branch de release, y `*` coincide con todos los branches. Combinado con **Track Scanned Branches**, esta es la forma de rastrear una familia de branches sin rastrearlos todos.
    - Si un comodín no coincide con **ningún** branch dentro de la ventana de escaneo, esa sincronización se **omite** en lugar de tratarse como "el branch no tiene hallazgos" — de este modo, un patrón que temporalmente no coincide con nada no puede cerrar todos los hallazgos del activo.
- **Track Scanned Branches**: cuando está habilitado, cada sincronización encuentra todos los branches con un scan completado en el historial reciente de scans del proyecto e importa **el scan completado más reciente de cada branch**, con una reimportación por branch. Los hallazgos de cada branch residen en su propio Compromiso en el activo asignado, llamado "\<Compromiso predeterminado\> \- \<branch\>", por lo que el cierre de hallazgos obsoletos está delimitado por branch: una corrección fusionada en un branch nunca puede cerrar los hallazgos de otro branch. El branch principal del proyecto (según lo informado por Checkmarx) se importa primero, de modo que las reapariciones del mismo hallazgo en otros branches se deduplican contra el original del branch principal.

Notas sobre **Track Scanned Branches**:

- **Verifique qué valor predeterminado se aplica en su caso.** El seguimiento de branches está **habilitado por defecto para las instalaciones nuevas**. Las instalaciones anteriores al cambio conservan su comportamiento previo, por lo que la opción permanece deshabilitada para ellas hasta que alguien la active.
- Cuando ambos campos están configurados, solo se rastrea el **Branch** fijado — incluso cuando ese valor de Branch es un patrón comodín, en cuyo caso se rastrea cada branch que coincida con el patrón.
- Un branch que deja de escanearse (fusionado o eliminado) deja de recibir actualizaciones: su Compromiso permanece visible con sus últimos hallazgos conocidos, que puede revisar y cerrar en bloque.
- Deshabilitar la opción más adelante es seguro: los Compromisos por branch simplemente dejan de recibir importaciones y el Compromiso predeterminado se reanuda en la siguiente sincronización.
- Los Conectores concilian el estado según el programa de sincronización. El seguimiento de branches hace que cada sincronización sea completa entre branches; no hace que los datos sean en tiempo real entre sincronizaciones.

## **Cloudflare**

El conector de Cloudflare importa **Security Center insights** — problemas de postura de seguridad que Cloudflare identifica sobre su cuenta y sus zonas, como un registro DMARC faltante, DNSSEC no habilitado o un problema de certificado. DefectDojo crea un Registro para cada zona (dominio) que tenga insights abiertos, además de un Registro a nivel de cuenta para los insights que no están asociados a una zona específica.

#### Prerrequisitos

Necesitará un **API token** de Cloudflare (no la Global API Key heredada). Cree uno en **My Profile > API Tokens > Create Token** dentro del panel de Cloudflare. La opción más rápida es la plantilla **"Read all resources"**; para un token con privilegios mínimos, otorgue **Zone > Zone > Read** (todas las zonas) más acceso de lectura a nivel de cuenta para Security Center.

#### Asignaciones del conector

1. Ingrese `https://api.cloudflare.com/client/v4` en el campo **Location**.
2. Ingrese el API token en el campo **Secret**.
3. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo autodescubre las cuentas y zonas a las que el token tiene acceso — no se requiere un ID de cuenta. Solo se importan los insights abiertos (activos, no descartados), por lo que los insights que resuelva o descarte en Cloudflare se marcan automáticamente como Mitigado en DefectDojo en la siguiente sincronización.

## **Cobalt.io**

El conector de Cobalt.io utiliza la API de Cobalt.io (v2) para extraer los hallazgos de pentest de su organización de Cobalt.io. DefectDojo detecta todas las organizaciones a las que su token de API tiene acceso y crea un Registro independiente para cada **activo** (la unidad que Cobalt somete a pentest).

#### Requisitos previos

Necesitará un **token de API personal** de Cobalt.io. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada se distinga claramente de las acciones manuales del equipo. Genere un token desde **Settings \> API Tokens** en la interfaz de Cobalt.io. Los tokens de organización se detectan automáticamente \- no es necesario proporcionarlos.

#### Asignaciones del conector

1. Introduzca la URL base de la API de Cobalt.io en el campo **Location**: `https://api.cobalt.io` (o el host de su región, por ejemplo `https://api.us.cobalt.io`).
2. Introduzca su **token de API personal** en el campo **Secret**.
3. De forma opcional, introduzca un **Organization Token** para fijar la sincronización a una sola organización. Si se deja en blanco, DefectDojo sincroniza todas las organizaciones a las que el token de API personal tiene acceso.

DefectDojo asigna cada **activo** de Cobalt.io como un Registro independiente. Los hallazgos se importan para cada activo asignado, y su estado en Cobalt.io (por ejemplo, `valid_fix`, `wont_fix`, `invalid`) determina el estado del hallazgo en DefectDojo.

## **Contrast**

El conector de Contrast utiliza la API REST de Contrast Assess para importar vulnerabilidades de aplicaciones. DefectDojo detecta las aplicaciones de su organización de Contrast y crea un Registro para cada una.

#### Requisitos previos

Necesitará cuatro valores de Contrast. Recomendamos crear una cuenta de servicio dedicada para que la actividad automatizada se distinga fácilmente de las acciones manuales de su equipo. En la interfaz de Contrast, en **User Settings > Profile > Your Keys**, encontrará:

* La **API Key** de su organización.
* Su **Service Key** personal.
* El **username** al que pertenecen las credenciales (el correo electrónico de inicio de sesión de la cuenta).
* Su **Organization ID**: el UUID de la organización desde la que importar, que también se muestra en **Organization Settings**.

#### Asignaciones del conector

1. Introduzca la URL base que utiliza para acceder a Contrast en el campo **Location**; para el producto alojado, suele ser `https://app.contrastsecurity.com` (o la URL de su Team Server regional o autoalojado).
2. Introduzca el correo electrónico de inicio de sesión de la cuenta en el campo **Username**.
3. Introduzca la **API Key** de la organización en el campo **API Key**.
4. Introduzca la **Service Key** personal en el campo **Service Key**.
5. Introduzca el **Organization ID** (UUID) en el campo **Organization ID**.
6. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada aplicación de Contrast se convierte en un Registro, y sus vulnerabilidades se importan como hallazgos.

## **Coverity**

El conector de Coverity importa hallazgos desde un servidor **Coverity Connect**. DefectDojo crea un Registro para cada **proyecto** de Coverity.

#### Asignaciones del conector

1. Introduzca la URL de su servidor Coverity Connect en el campo **Location**.
2. Introduzca el **username** de Coverity Connect en el campo **Username**.
3. Introduzca la contraseña o la clave de autenticación del usuario en el campo **Secret**.
4. De forma opcional, defina un **View Name** para seleccionar qué vista de incidencias guardada lee el conector. Déjelo en blanco para usar la opción predeterminada, **Outstanding Issues**.
5. De forma opcional, defina **Import All Issue Kinds** en `true` para ampliar la importación más allá del filtro predeterminado de incidencias de Security y Quality (`RESOURCE_LEAK`).

## **CrowdStrike Falcon**

El conector de CrowdStrike Falcon importa **vulnerabilidades de Spotlight** y **detecciones de EDR** de la plataforma Falcon, como dos tipos de hallazgo independientes (`CrowdStrike:Spotlight` y `CrowdStrike:Detections`). DefectDojo crea un Registro para cada **host** de Falcon.

#### Requisitos previos

Un **API client** de Falcon (Client ID y secret), creado en la consola de Falcon en **Support \> API Clients and Keys**. Otórguele los scopes correspondientes a los datos que desea importar: **Hosts: Read** (obligatorio, para la detección de hosts), **Vulnerabilities (Spotlight): Read** (para los hallazgos de Spotlight) y **Alerts: Read** (para las detecciones de EDR). Los dos tipos de hallazgo son independientes: si al cliente le falta un scope, ese tipo de hallazgo se omite en lugar de hacer fallar la sincronización, por lo que un cliente sin **Alerts: Read** sigue importando las vulnerabilidades de Spotlight.

#### Asignaciones del conector

1. Introduzca la URL base de la API de su nube de Falcon en el campo **Location**, según la región de su consola; por ejemplo, `https://api.crowdstrike.com` (US\-1), `https://api.us-2.crowdstrike.com` (US\-2), `https://api.eu-1.crowdstrike.com` (EU\-1) o `https://api.laggar.gcw.crowdstrike.com` (US\-GOV\-1).
2. Introduzca el Client ID del API client en el campo **Client ID**.
3. Introduzca el secret del API client en el campo **Client Secret**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada host de Falcon se convierte en un Registro, nombrado según su hostname, sistema operativo y tipo. Solo se importan las vulnerabilidades de Spotlight **open** y **reopened**, por lo que una nueva importación cierra los hallazgos ya remediados.

## **Deepfence ThreatMapper**

El conector de Deepfence ThreatMapper utiliza la API REST de la consola de administración de [ThreatMapper](https://github.com/deepfence/ThreatMapper) para importar resultados de **escaneos de vulnerabilidades**. DefectDojo detecta todos los nodos que ThreatMapper ha escaneado (una imagen de contenedor, un host o un contenedor) y crea un Registro para cada uno; a continuación, importa como hallazgos el escaneo completado más reciente de ese nodo.

#### Requisitos previos

Necesitará un **API token** de ThreatMapper, disponible en la consola en **Settings → User Management** (la clave de API de su usuario). El conector lo intercambia por un token de acceso de corta duración en cada sincronización; el API token nunca se registra en los logs.

#### Asignaciones del conector

1. Introduzca la URL de la consola de ThreatMapper en el campo **Location** (por ejemplo, `https://threatmapper.example.com`).
2. En el campo **Secret**, introduzca el API token de ThreatMapper.
3. Si su consola utiliza un certificado autofirmado, defina **Skip TLS Verification** en `true`.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **nodo** escaneado a un Registro y cada **CVE** de su escaneo de vulnerabilidades completado más reciente a un hallazgo. La severidad proviene de la propia calificación de ThreatMapper, y se trasladan el paquete afectado, la puntuación CVSS, la versión de corrección (como mitigación), los enlaces de referencia y un bloque de detalles. Los hallazgos se registran como hallazgos dinámicos y se deduplican según el nodo, el CVE, el paquete y la ruta del paquete.

Consulte la [documentación de ThreatMapper](https://community.deepfence.io/threatmapper/docs/v2.5/) para obtener más información.

## Dependency\-Track

Este conector obtiene datos de una instancia on\-premise de Dependency\-Track mediante la API REST.

​**Asignaciones del conector**

1. Introduzca la URL de su servidor local de Dependency\-Track en el campo **Location**.
2. Introduzca una clave de API válida en el campo **Secret**.

Para generar una clave de API de Dependency\-Track:

1. **Access Management**: navegue hasta Administration \> Access Management \> Teams en la interfaz de Dependency\-Track.
2. **Teams Setup**: puede crear un nuevo equipo o seleccionar uno existente. Los equipos permiten gestionar el acceso a la API según la pertenencia al grupo.
3. **Generate API Key**: en la página de detalles del equipo seleccionado, busque la sección "API Keys". Haga clic en el botón \+ para generar una nueva clave de API.
4. **Assign Permissions**: en la sección "Permissions" de la página del equipo, haga clic en el botón \+ para abrir el selector de permisos. Elija los permisos **VIEW\_PORTFOLIO** y **VIEW\_VULNERABILITY** para habilitar el acceso mediante API a los portafolios de proyectos y a los detalles de vulnerabilidades.
5. Haga clic en "**Select**" para confirmar y guardar estos permisos.

Para obtener más información, consulte la **[documentación de Dependency\-Track](https://docs.dependencytrack.org/integrations/rest-api/)**.

## **Docker Scout**

El conector de Docker Scout utiliza la API del exportador de métricas de Docker Scout para informar sobre la postura de vulnerabilidades de las imágenes de su organización. DefectDojo detecta cada stream de Docker Scout (sus entornos de ejecución) e importa un resumen de las vulnerabilidades y el cumplimiento de políticas de cada uno.

#### Requisitos previos

Necesitará un personal access token de Docker creado por un **owner** de una organización de Docker que esté **inscrita en Docker Scout**. El exportador de métricas es una función a nivel de organización, por lo que una cuenta personal, o una organización no inscrita en Docker Scout, no devolverá datos.

Cree el token desde la configuración de su cuenta de Docker, en **Personal access tokens**, y anote el **organization namespace** de Docker, que también necesitará.

#### Asignaciones del conector

1. Introduzca `https://api.scout.docker.com` en el campo **Location**.
2. Introduzca su personal access token de Docker en el campo **Secret**.
3. Introduzca su namespace de **Organization** de Docker.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

DefectDojo crea un Registro independiente para cada stream de Docker Scout, e importa un hallazgo por severidad para las vulnerabilidades que Docker Scout contabiliza en ese stream, además de un hallazgo por cada imagen que incumple su política de Docker Scout. La API de métricas de Docker Scout informa recuentos agregados en lugar de CVE individuales, por lo que estos hallazgos resumen la postura de un stream. Abra el stream en Docker Scout para ver el detalle por imagen y por CVE.

Consulte la [documentación de Docker Scout](https://docs.docker.com/scout/) para obtener más información.

## **Endor Labs**

El conector de Endor Labs utiliza la API REST de Endor Labs para sincronizar un **namespace** completo de Endor Labs. DefectDojo detecta cada **proyecto** de Endor como un Registro e importa los hallazgos de ese proyecto, trasladando el veredicto de **accesibilidad** de Endor para que pueda priorizar las vulnerabilidades cuyo código afectado sea realmente accesible.

#### Requisitos previos

Necesitará una **API key** de Endor Labs (un identificador de clave más su secret) y el **namespace** que desea sincronizar. Cree la clave en la plataforma de Endor Labs en **Settings \> Access \> API Keys**; la clave necesita acceso de lectura a los proyectos y hallazgos de ese namespace.

El conector se autentica intercambiando la API key y el secret por un bearer token de corta duración; el secret se utiliza únicamente para ese intercambio y nunca se almacena en texto plano.

#### Asignaciones del conector

1. Introduzca `https://api.endorlabs.com` en el campo **Location**. Si su tenant está alojado en una región distinta, utilice en su lugar la URL base de la API de esa región.
2. Introduzca el **Namespace** de Endor Labs que desea sincronizar (por ejemplo `your-org` o `your-org.team`).
3. Introduzca el identificador de **API Key**.
4. Introduzca el **API Secret** asociado a la clave.
5. De forma opcional, defina **Traverse Child Namespaces** en `true` para importar también los hallazgos de los namespaces hijos del namespace configurado.
6. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importan.

DefectDojo crea un Registro para cada proyecto de Endor Labs del namespace e importa sus hallazgos, asignando los niveles de severidad de Endor a las severidades de DefectDojo, los identificadores CVE/GHSA y la puntuación CVSS de cada vulnerabilidad, y las etiquetas de accesibilidad de Endor. El veredicto de accesibilidad (por ejemplo, *Reachable — vulnerable function is called* o *Unreachable*) se muestra como el Impact del hallazgo y como una etiqueta.

Para obtener más información, consulte la **[documentación de la API REST de Endor Labs](https://docs.endorlabs.com/rest-api/)**.

## **Edgescan**

El conector de Edgescan utiliza la API REST de Edgescan para importar las vulnerabilidades abiertas de toda su cuenta de Edgescan. DefectDojo enumera todos los **activos** de Edgescan y crea un Registro para cada uno; a continuación, importa las vulnerabilidades abiertas de ese activo como hallazgos. No existe configuración por activo.

#### Requisitos previos

Necesitará un token de API de Edgescan. Créelo desde su cuenta de Edgescan en **Account settings \> API tokens**: introduzca una etiqueta, haga clic en **Create** y copie el token generado (solo se muestra una vez). Recomendamos una cuenta dedicada para el conector, de modo que la actividad automatizada se distinga fácilmente.

#### Asignaciones del conector

1. Introduzca su URL de Edgescan en el campo **Location**: `https://live.edgescan.com` para la plataforma alojada estándar, o el host de su tenant si es distinto.
2. Introduzca su token de API de Edgescan en el campo **Secret**. Se envía en el encabezado `X-API-TOKEN`.
3. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada activo de Edgescan se convierte en un Registro, y cada vulnerabilidad abierta de ese activo se importa como un hallazgo. La severidad se asigna desde la escala numérica de Edgescan (1–5) a la escala Informativa–Crítica de DefectDojo, e incluye las referencias CVE, el CWE y un vector CVSS v3 cuando Edgescan los proporciona.

## **Escape**

El conector de Escape utiliza la API de [Escape](https://escape.tech) para importar **hallazgos de seguridad de API (DAST)**. DefectDojo enumera todas las organizaciones a las que el token tiene acceso y todas las aplicaciones de cada una, crea un Registro para cada aplicación que tenga un escaneo, e importa como hallazgos las incidencias del escaneo más reciente de esa aplicación. No existe configuración por aplicación.

#### Requisitos previos

Necesitará una **API key** de Escape, creada en la aplicación de Escape en **Settings → API keys**. La clave se envía en el encabezado `Authorization: Key` y nunca se registra en los logs.

#### Asignaciones del conector

1. Deje el campo **Location** en blanco para usar `https://public.escape.tech/v2`, o introduzca explícitamente el host de la API de Escape.
2. Introduzca la clave de API de Escape en el campo **Secret**.
3. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **aplicación** a un Registro y cada **issue** del escaneo a un hallazgo: la severidad proviene de la calificación de Escape (Crítica/Alta/Media/Baja), se traslada el CWE, la categoría OWASP y el método HTTP se convierten en etiquetas, la URL afectada se convierte en el endpoint, y se incluye la guía de remediación. Los hallazgos se registran como hallazgos dinámicos y se deduplican según el id de la issue de Escape.

Consulte la [documentación de la API de Escape](https://docs.escape.tech/) para obtener más información.

## **Fairwinds Insights**

El conector de Fairwinds Insights utiliza la API REST de [Fairwinds Insights](https://insights.fairwinds.com) para importar **hallazgos de seguridad de Kubernetes** de toda su organización. DefectDojo enumera todos los **clusters** activos y crea un Registro para cada uno; a continuación, importa como hallazgos los **action items** de seguridad de ese cluster \(de Polaris, Trivy, Kube\-bench, OPA y los demás informes de Insights\). No existe configuración por cluster.

#### Requisitos previos

Necesitará un nombre de **organización** de Fairwinds Insights y un **API token**. Cree el token en la aplicación de Insights en **Organization Settings \> Tokens**; basta con un token `read_only`. El token tiene alcance de organización y se envía como bearer token; nunca se registra en los logs.

#### Asignaciones del conector

1. Deje el campo **Location** en blanco para usar `https://insights.fairwinds.com`, o introduzca explícitamente el host de Insights.
2. Introduzca el nombre de **Organization** de Insights (el slug que aparece en la URL de su panel).
3. Introduzca el token de API de Insights en el campo **Secret**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **cluster** activo a un Registro y cada **action item** de Security a un hallazgo: la severidad proviene de la puntuación numérica de Fairwinds \(asignada a la escala Informativa–Crítica de DefectDojo\), el informe de Fairwinds que generó el elemento \(`polaris`, `trivy`, `kube-bench`, ...\) se convierte en una etiqueta de herramienta, se incluyen el recurso de Kubernetes afectado y la imagen del contenedor, y se extraen los identificadores CVE si los hay. Los hallazgos se registran como hallazgos estáticos y se deduplican según el id del action item de Fairwinds.

Consulte la [documentación de la API de Fairwinds Insights](https://insights.docs.fairwinds.com/technical-details/api/) para obtener más información.

## **Fortify**

El conector de Fortify importa resultados SAST/DAST de Fortify (OpenText/Micro Focus), abarcando las dos ediciones que comparten la plataforma: **SSC** (Software Security Center, autoalojado) y **Fortify on Demand (FoD)** (SaaS). Sincroniza toda la cuenta: DefectDojo detecta todas las aplicaciones (project version de SSC / release de FoD) y crea un Registro para cada una; a continuación, importa las incidencias de esa aplicación como hallazgos.

#### Requisitos previos

- **SSC**: un **FortifyToken**; créelo en la interfaz de SSC en **Administration → Token Management** (un CIToken/UnifiedLoginToken).
- **FoD**: una **OAuth2 API key**; un Client ID y un Client Secret desde **Settings → API** (con el scope `api-tenant`).

El token y el secret de OAuth nunca se registran en los logs.

#### Asignaciones del conector

1. Introduzca la URL base de Fortify en el campo **Location**: para SSC, el host de su servidor (el conector añade `/ssc/api/v1`); para FoD, el host de la API de su región, por ejemplo, `https://api.ams.fortify.com`.
2. Defina **Edition** en `SSC` o `FoD`.
3. Para **FoD**, introduzca el **Client ID** de OAuth; déjelo en blanco para SSC.
4. En **Token / Client Secret**, introduzca el FortifyToken de SSC o el client secret de OAuth de FoD.
5. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **aplicación** de Fortify a un Registro y cada **issue** a un hallazgo: la severidad proviene de la propia calificación de **friority** de Fortify (Crítica/Alta/Media/Baja), el título combina la categoría de la incidencia con su archivo y línea, y se trasladan la ruta del archivo, la línea, el kingdom, el analizador y el tipo de motor. Las incidencias de los motores de análisis estático (SCA) se registran como hallazgos estáticos y las incidencias de WebInspect (DAST) como hallazgos dinámicos; las incidencias suprimidas, eliminadas u ocultas se omiten, las incidencias auditadas como "Not an Issue" se marcan como falso positivo, y las incidencias "Exploitable" o revisadas se marcan como verificadas.

Consulte la documentación de la API de [Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/) y de [Fortify on Demand](https://api.ams.fortify.com/swagger/ui) para obtener más información.

## **GitGuardian**

El conector de GitGuardian utiliza la API REST de GitGuardian para importar **incidentes de secretos**: credenciales expuestas que GitGuardian ha detectado en sus fuentes monitorizadas. DefectDojo crea un Registro para cada fuente monitorizada (repositorio o perímetro) que actualmente tenga incidentes abiertos, e importa cada incidente abierto como un hallazgo.

Por su seguridad, el conector importa únicamente los **metadatos** del incidente: el detector, la severidad, la validez, el estado y un enlace de vuelta a GitGuardian. El propio valor del secreto expuesto nunca se recupera ni se almacena en DefectDojo; siga el enlace de cada hallazgo para revisar las ubicaciones afectadas en GitGuardian.

#### Requisitos previos

Necesitará una clave de API de GitGuardian. Recomendamos un **Service Account token** (en lugar de un personal access token) para que la actividad automatizada se distinga fácilmente. Créelo en **API** en el panel de GitGuardian y otorgue estos scopes de lectura:

* `incidents:read`
* `sources:read`

#### Asignaciones del conector

1. Introduzca la URL de la API de GitGuardian en el campo **Location**: `https://api.gitguardian.com` para la plataforma SaaS, o la URL de la API de su instancia autoalojada.
2. Introduzca la clave de API en el campo **Secret**.

Solo se importan los incidentes **open** (con estado `TRIGGERED` o `ASSIGNED`); los incidentes que resuelva o ignore en GitGuardian se mitigan automáticamente en DefectDojo en la siguiente sincronización. Un secreto confirmado como activo (validez *valid*) se importa como un hallazgo verificado.

## **GitHub**

El conector de GitHub es un **Asset Connector**: enumera los repositorios a los que su token tiene acceso y crea un Activo de DefectDojo para cada uno, agrupados en Organizaciones según el propietario de GitHub (organización o usuario). No se importa ningún hallazgo.

**Tenga en cuenta:** este conector importa únicamente el **inventario** de sus repositorios. Para importar las alertas de seguridad de GitHub (code scanning, Dependabot y secret scanning) como hallazgos, utilice el conector independiente **GitHub Advanced Security** que se describe más adelante. Ambos son independientes y pueden ejecutarse juntos.

#### Requisitos previos

El conector se autentica con un **personal access token** de GitHub y solo lee los **metadatos** del repositorio (nombre, descripción, URL y propietario); no accede a su código, incidencias ni alertas de seguridad. Importa todos los repositorios que la cuenta del token posee, en los que colabora, o de cuya organización es miembro, así que confirme que la cuenta del token puede ver los repositorios que desea reflejar. Recomendamos una cuenta de servicio dedicada.

El token solo necesita acceso de solo lectura a los metadatos del repositorio:

- Un token *fine-grained* necesita **Repository permissions → Metadata: Read-only**, otorgado a los repositorios (o a toda la organización) que desea importar.
- Un token *classic* necesita el scope **`repo`** para incluir repositorios privados (use **`public_repo`** si solo necesita los públicos), además de **`read:org`** para que se resuelvan los repositorios propiedad de la organización.

Solo se admite GitHub.com (incluido GitHub Enterprise Cloud). GitHub Enterprise **Server** no está soportado actualmente por este conector.

#### Asignaciones del conector

1. Introduzca `https://api.github.com` en el campo **Location**.
2. Introduzca el personal access token en el campo **Secret**.

No es necesario introducir ninguna lista de organizaciones ni de repositorios: DefectDojo importa todos los repositorios que el token puede ver. Cada repositorio se convierte en un Registro con el nombre del repositorio, agrupado por su **owner** de GitHub (organización o usuario). Si un repositorio se elimina más adelante, o el token pierde el acceso a él, su Registro asignado se marca como `MISSING` en la siguiente sincronización en lugar de eliminarse: DefectDojo nunca elimina un Producto de forma silenciosa.

## **GitHub Advanced Security**

El conector de GitHub Advanced Security importa alertas de **code scanning**, **Dependabot** y **secret scanning** de GitHub, como tres tipos de hallazgo independientes (`GitHub:CodeScanning`, `GitHub:Dependabot` y `GitHub:SecretScanning`). DefectDojo detecta todos los repositorios no archivados de la organización configurada y crea un Registro para cada uno.

#### Requisitos previos

Las funciones de GitHub Advanced Security deben estar habilitadas en los repositorios que desea importar. El conector se autentica con un **personal access token** de GitHub:

1. En GitHub, abra **Settings \> Developer settings \> Personal access tokens** y cree un token propiedad de (o con acceso a) la organización de destino.
2. Otórguele acceso de lectura a las alertas de seguridad: un token *fine\-grained* necesita acceso **Read\-only** a **Code scanning alerts**, **Dependabot alerts** y **Secret scanning alerts** en los repositorios de la organización; un token *classic* necesita los scopes **`repo`** y **`security_events`**.
3. Confirme que el propietario del token puede ver los repositorios que pretende importar: el conector solo ve los repositorios a los que el token tiene acceso.

#### Asignaciones del conector

1. Introduzca `https://api.github.com` en el campo **Location**. Para GitHub Enterprise Server, utilice `https://<your-host>/api/v3`.
2. Introduzca el login de la organización en el campo **Organization**.
3. Introduzca el personal access token en el campo **Secret**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada repositorio no archivado se convierte en un Registro, consultado en las tres familias de alertas en busca de alertas abiertas. Una familia de alertas que no esté habilitada para un repositorio se omite en lugar de reportarse como resuelta, de modo que las funciones deshabilitadas no provocan cierres falsos.

## **GitLab**

El conector de GitLab es un **Asset Connector**: enumera todos los proyectos (repositorios) a los que su token tiene acceso y crea un Activo de DefectDojo para cada uno, agrupados en Organizaciones según el namespace de GitLab (grupo o usuario). No se importa ningún hallazgo.

#### Requisitos previos

Necesitará un Personal Access Token con el scope **read_api**. Recomendamos crear el token desde una cuenta de servicio dedicada; el conector enumera los proyectos de los que esa cuenta es miembro.

#### Asignaciones del conector

1. Introduzca su URL de GitLab en el campo **Location**: `https://gitlab.com`, o la URL base de su instancia autoalojada.
2. Introduzca el Personal Access Token en el campo **Secret**.

Cada proyecto se convierte en un Registro con el nombre del proyecto, agrupado por su **namespace**. Los proyectos pendientes de eliminación en GitLab (eliminados por un usuario, pero aún no purgados por el trabajo en segundo plano de GitLab) se excluyen automáticamente, de modo que eliminar un proyecto marca su Registro como `MISSING` en la siguiente sincronización en lugar de dejar un activo fantasma renombrado.

## **Google Cloud Security Command Center**

El conector de Google Cloud SCC utiliza la API REST v2 de Security Command Center para importar los hallazgos de seguridad activos de su organización, carpeta o proyecto de Google Cloud. DefectDojo crea un Registro para cada **proyecto** de Google Cloud que tenga hallazgos abiertos.

#### Requisitos previos

Security Command Center debe estar **activado** en su organización (el nivel Standard es gratuito). A continuación, necesitará una cuenta de servicio que pueda listar hallazgos, y una clave JSON para ella:

1. En Google Cloud, cree una cuenta de servicio; se recomienda una dedicada para DefectDojo.
2. Otórguele el rol **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) en el alcance que desea importar (organización, carpeta o proyecto).
3. Cree una **clave JSON** para la cuenta de servicio y descárguela.

#### Asignaciones del conector

1. Deje el campo **Location** con el valor predeterminado `https://securitycenter.googleapis.com`, salvo que utilice un endpoint no estándar.
2. En el campo **Parent Resource**, introduzca el alcance desde el que importar: `organizations/{id}`, `folders/{id}` o `projects/{id}`.
3. Pegue el contenido completo del archivo de **clave JSON** de la cuenta de servicio en el campo **Service Account Key**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Solo se importan los hallazgos `ACTIVE` y no silenciados, por lo que los hallazgos que desactive o silencie en SCC se mitigan automáticamente en DefectDojo en la siguiente sincronización. El proyecto de GCP afectado de cada hallazgo se convierte en su Registro.

## **Group-IB ASM**

El conector Group-IB ASM (Attack Surface Management) usa la API REST de Group-IB ASM para importar a DefectDojo **incidencias** (hallazgos) de superficie de ataque externa. DefectDojo detecta cada **empresa/tenant** de Group-IB como un Registro independiente e importa las incidencias de esa empresa de forma programada e incremental. El activo al que se refiere cada incidencia (un dominio, una IP o una URL) se adjunta al hallazgo resultante como un **Endpoint**.

#### Requisitos previos

Necesitará su inicio de sesión de Group-IB ASM y una clave de API. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada pueda distinguirse de las acciones manuales del equipo.

Para generar una clave de API:

1. Abra Group-IB Attack Surface Management, haga clic en **Help** en la esquina inferior izquierda y seleccione **API**.
2. Haga clic en **Generate API Key** (arriba a la derecha, debajo de su nombre de usuario).
3. Introduzca su contraseña de SSO y haga clic en **Next**, luego haga clic en **Copy token**.
4. Guarde la clave en un gestor de secretos y planifique su rotación periódica.

#### Asignaciones del conector

Group-IB ASM se autentica mediante HTTP Basic Auth, donde el nombre de usuario es su inicio de sesión de ASM y la contraseña es su clave de API. **Se requieren ambos valores**: la clave de API por sí sola no es suficiente.

1. Introduzca `https://asm.group-ib.com` en el campo **Location**. Es el mismo para todos los tenants de Group-IB ASM.
2. Introduzca su inicio de sesión de ASM (normalmente una dirección de correo electrónico) en el campo **Username**.
3. Introduzca su clave de API en el campo **API Key** (Secret).
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importan.

DefectDojo asigna cada **empresa** de Group-IB como un Registro independiente, usando el ID de la empresa como identificador. En la primera Sincronización, DefectDojo recupera el historial reciente de incidencias; las Sincronizaciones posteriores son incrementales y solo obtienen las incidencias modificadas desde la última Sincronización (según la marca de tiempo `lastSeen` más reciente de cada incidencia).

#### Limitar a una sola empresa (opcional)

De forma predeterminada, el conector detecta automáticamente las empresas disponibles para sus credenciales de API (mediante el endpoint `clients` de ASM) y crea un Registro por empresa. Esta es la configuración recomendada y no requiere configuración adicional.

Si el endpoint `clients` no está disponible para su tenant — por ejemplo, cuando está restringido a cuentas de socios/MSP —, el conector puede limitarse a una sola empresa proporcionando su **ID de empresa** como campo específico de la herramienta `company_id` en la configuración del conector. Cuando se establece `company_id`, DefectDojo usa esa empresa directamente en lugar de enumerar las empresas. Déjelo sin establecer para usar la detección automática.

Consulte el manual de la API REST de Group-IB ASM (disponible en el propio producto en **Help → API**) para obtener más información.

## **HackerOne**

El conector HackerOne usa la API REST de HackerOne para importar reportes de su programa de recompensas por errores (bug bounty) o de divulgación de vulnerabilidades. DefectDojo crea un Registro para cada programa al que el token pueda acceder e importa sus reportes como hallazgos.

#### Requisitos previos

El conector usa la API **customer** de HackerOne, que requiere un **token de API de la organización**; un token personal de la configuración de su usuario solo funciona con la API de hacker y no se autenticará aquí.

1. En HackerOne, vaya a **Organization Settings > API Tokens**.
2. Cree un token y anote tanto el **identifier** como el valor del **token**. El acceso de lectura al programa es suficiente.

#### Asignaciones del conector

1. Introduzca `https://api.hackerone.com` en el campo **Location**.
2. Introduzca el **identifier** del token en el campo **API Token Identifier**.
3. Introduzca el valor del token en el campo **API Token**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada programa se convierte en un Registro, y sus reportes se importan como hallazgos conservando la calificación de severidad de HackerOne.

## **Harbor**

El conector Harbor usa la API REST v2.0 de Harbor para importar vulnerabilidades de imágenes de contenedor de todo su registro. DefectDojo enumera cada **proyecto** de Harbor y crea un Registro para cada uno, luego recorre los repositorios y artefactos del proyecto e importa las vulnerabilidades de cada artefacto **escaneado** — incorporando la imagen (repositorio + etiqueta/digest) como contexto del hallazgo. No existe configuración por imagen.

#### Requisitos previos

Necesitará una cuenta de Harbor (o una **cuenta robot**) con acceso de extracción/lectura a los proyectos que desea importar. Recomendamos una cuenta robot dedicada: en Harbor, abra un proyecto (o **Administration > Robot Accounts** para un robot de sistema), cree un robot con el permiso **pull** sobre repositorios y artefactos, y copie su nombre completo y su secreto. Los nombres de robot comienzan con `robot$` de forma predeterminada, pero el prefijo es configurable por instancia de Harbor (algunas usan `robot_`) — copie el nombre exactamente como lo muestra Harbor. Un nombre de usuario y contraseña normales también funcionan.

#### Asignaciones del conector

1. Introduzca su URL de Harbor en el campo **Location** — por ejemplo `https://harbor.example.com`. DefectDojo añade automáticamente la ruta de la API `/api/v2.0`.
2. Introduzca el nombre de usuario de Harbor, o el nombre de una cuenta robot exactamente como lo muestra Harbor (`robot$<name>` de forma predeterminada), en el campo **Username**.
3. Introduzca la contraseña o el secreto de la cuenta robot en el campo **Secret**. Se envía mediante autenticación HTTP Basic.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada proyecto de Harbor se convierte en un Registro. Para cada artefacto que tenga un escaneo completado, sus vulnerabilidades se importan como hallazgos; se incluyen el paquete/versión afectados, una severidad derivada de CVSS, el CVE, el CWE y una corrección (versión reparada) cuando Harbor los proporciona. Solo se importan los artefactos escaneados — active un escaneo en Harbor para las imágenes que aún no se hayan escaneado.

## **Have I Been Pwned**

El conector Have I Been Pwned (HIBP) usa la API REST de HIBP para informar de qué cuentas de los dominios propios de su organización han aparecido en filtraciones de datos conocidas. DefectDojo detecta cada dominio que haya verificado con HIBP e importa un hallazgo por cada filtración que afecte a ese dominio.

#### Requisitos previos

Necesitará una clave de API de Have I Been Pwned con búsqueda de dominio, lo que requiere un nivel de suscripción **Core** o superior. Puede obtener una clave desde su [cuenta de Have I Been Pwned](https://haveibeenpwned.com/API/Key).

También debe **verificar al menos un dominio** en su cuenta de HIBP antes de que haya datos de filtraciones disponibles. HIBP permite verificar un dominio mediante registro TXT de DNS, metaetiqueta, carga de archivo o correo electrónico, en **Domain search** dentro de su cuenta. Hasta que un dominio esté verificado, el conector no detecta ningún dominio y no importa ningún hallazgo.

#### Asignaciones del conector

1. Introduzca `https://haveibeenpwned.com` en el campo **Location**.
2. Introduzca su clave de API en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

DefectDojo crea un Registro independiente para cada dominio que haya verificado con HIBP, e importa un hallazgo por cada filtración que afecte a las cuentas de ese dominio. La severidad de cada hallazgo refleja el tipo de datos que expuso la filtración, y su descripción enumera las cuentas afectadas de su dominio para que su equipo pueda actuar sobre ellas.

Consulte la [documentación de la API de Have I Been Pwned](https://haveibeenpwned.com/API/v3) para obtener más información.

## **HCL AppScan**

El conector HCL AppScan usa la API REST v4 de AppScan para importar incidencias de **AppScan on Cloud (ASoC)** o de una instancia autoalojada de **AppScan 360°** (ambas comparten la API). Sincroniza toda la cuenta: DefectDojo detecta todas las aplicaciones y crea un Registro para cada una, y luego importa las incidencias de esa aplicación (DAST, SAST e IAST) como hallazgos.

#### Requisitos previos

Necesitará una **API key** de AppScan — un Key ID y un Key Secret generados en la configuración de su cuenta de AppScan (API Key). El conector los intercambia por un token de sesión de corta duración en cada ejecución; el Key ID, el Key Secret y el token nunca se registran en los logs.

#### Asignaciones del conector

1. Introduzca la URL de la consola de AppScan en el campo **Location**: para ASoC use `https://cloud.appscan.com` (o `https://eu.cloud.appscan.com` para la región de la UE); para AppScan 360° use el host de su instancia.
2. Establezca **Provider** en `ASOC` para AppScan on Cloud, o en `A360` para una instancia autoalojada de AppScan 360°.
3. Introduzca el **API Key ID** y el **API Key Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **aplicación** de AppScan a un Registro (VEP) y cada **incidencia** a un hallazgo: el título es el tipo de incidencia con su dominio/entidad/cause-id/URL/ruta añadidos; la severidad asigna Informational a Info (Low/Medium/High/Critical se transfieren sin cambios); se incluyen el CWE, una descripción etiquetada, la corrección y el aviso, y el endpoint de host/puerto. Las incidencias de análisis estático se registran como hallazgos estáticos y las incidencias dinámicas/interactivas como hallazgos dinámicos; las incidencias abiertas quedan activas y las corregidas/aprobadas quedan mitigadas.

Consulte la [documentación de la API REST de AppScan](https://help.hcl-software.com/appscan/ASoC/appseccloud_rest_apis.html) para obtener más información.

## **Intigriti**

El conector Intigriti usa la API externa de empresa de Intigriti para importar **envíos** de bug bounty / pentest a DefectDojo. Sincroniza toda la cuenta de la empresa: DefectDojo detecta todos los programas a los que el token puede acceder y crea un Registro para cada uno, luego importa los envíos de ese programa como hallazgos.

#### Requisitos previos

Necesitará un **token de API de empresa** de Intigriti. En el portal de empresa de Intigriti, en **Company Settings > API** (el ámbito `company_external_api`), genere un token de acceso con acceso de lectura a sus programas y envíos. Se recomienda un token dedicado para DefectDojo. El token se envía como Bearer token y nunca se registra en los logs.

#### Asignaciones del conector

1. Introduzca la URL base de la API externa de empresa de Intigriti en el campo **Location**: `https://api.intigriti.com/external/company`. La URL debe ser HTTPS.
2. Introduzca el token de API de empresa en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **programa** de Intigriti a un Registro y cada **envío** a un hallazgo, identificado por el código del envío. La severidad del hallazgo sigue la calificación de Intigriti (Exceptional/Critical → Crítica, luego Alta/Media/Baja, o en caso contrario Informational), y el estado del ciclo de vida del envío se asigna al estado del hallazgo: los envíos open/triage están activos, los envíos accepted están verificados, y los envíos closed pasan a ser duplicado, fuera de alcance, falso positivo o riesgo aceptado según su motivo de cierre. La descripción del hallazgo incluye el tipo de vulnerabilidad del reporte, el activo afectado, la prueba de concepto y las respuestas del investigador.

Consulte la [documentación de la API de Intigriti](https://kb.intigriti.com/en/articles/6117846-intigriti-api) para obtener más información.

## **Intruder**

El conector Intruder usa la [API REST de Intruder](https://developers.intruder.io/) para importar la postura de toda su cuenta a DefectDojo. Cada **destino** de Intruder se detecta como un Registro (Producto); cada **aparición** de una incidencia en un destino se convierte en un Hallazgo.

#### Asignaciones del conector

1. Deje el campo **Location** como `https://api.intruder.io/` (el servidor de API predeterminado de Intruder).
2. Introduzca un **token de acceso de API** de Intruder en el campo **Secret**.

Genere un token de acceso en Intruder en **My account > API Access Tokens** (necesitará la contraseña de su cuenta para crearlo, y el token solo se muestra una vez). Consulte la [documentación de la API de Intruder](https://developers.intruder.io/docs/creating-an-access-token) para más detalles.

Los hallazgos se derivan por aparición: la severidad proviene de la severidad de la incidencia, los CVE y CVSS de la aparición, la ubicación del destino/puerto, y una aparición en estado "snoozed" se importa como un hallazgo inactivo (falso positivo o riesgo aceptado).

## **IriusRisk**

El conector IriusRisk usa un token de API para importar datos de modelado de amenazas desde su instancia de IriusRisk.

#### Requisitos previos

Necesitará un token de API de su cuenta de IriusRisk. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que se distinga claramente la actividad automatizada de las acciones manuales del equipo.

Para generar un token de API en IriusRisk:

1. Inicie sesión en su instancia de IriusRisk.
2. Vaya a su **User Profile** en el menú superior derecho.
3. Seleccione **API Token** y genere un nuevo token.

Consulte la [documentación de la API de IriusRisk](https://support.iriusrisk.com/hc/en-us/categories/360001148511) para obtener más información.

#### Asignaciones del conector

1. Introduzca la URL de su instancia de IriusRisk en el campo **Location URL**. Para instancias alojadas en la nube, suele ser `https://{your-subdomain}.iriusrisk.com`. Para instalaciones locales, use la URL base de su instancia.
2. Introduzca su **API Token** en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

## **JFrog Xray**

El conector JFrog Xray usa la API REST de JFrog Xray para obtener datos de vulnerabilidades de sus repositorios de Artifactory. DefectDojo detectará todos los repositorios de su instancia de JFrog y generará informes de vulnerabilidades mediante Xray, importando hallazgos de forma programada.

#### Requisitos previos

Necesitará un token de API con acceso tanto a la API de Artifactory como a la de Xray. Recomendamos crear una cuenta de servicio dedicada para DefectDojo. La cuenta requiere:

* Acceso de lectura a los repositorios de Artifactory
* Permiso para generar y ver informes de vulnerabilidades de Xray (permiso `Apply on Watches` en Xray, o equivalente)

#### Asignaciones del conector

1. Introduzca la URL base de su instancia de JFrog en el campo **Location**. Debe ser la URL raíz de su instancia de JFrog, por ejemplo `https://your-instance.jfrog.io`. No incluya una ruta final — DefectDojo construirá automáticamente las rutas de API correspondientes.
2. Introduzca un **Reference Token** válido en el campo **Secret**. Los tokens se pueden generar en **User Management > Access Tokens** en la interfaz de JFrog Platform.
Deberá generar un **Reference Token** y usar ese valor.

Ámbitos de token necesarios para JFrog Xray:

- **All Services**, ya que DefectDojo necesita acceso tanto a los servicios de XRay como de Artifactory
- **Manage Reports + Manage Resources** como mínimo.

De forma predeterminada, DefectDojo asigna cada **repositorio** de Artifactory como un Registro independiente. Cada Sincronización genera un informe de vulnerabilidades completo por repositorio mediante Xray, de modo que los estados de los hallazgos en DefectDojo siempre reflejan el estado actual del repositorio.

#### Filtro de repositorio (opcional)

De forma predeterminada, el conector detecta **todos** los repositorios de su instancia de JFrog. En instancias con un gran número de repositorios — muchos de los cuales pueden no ser relevantes para la revisión de seguridad —, la detección se puede limitar con el campo opcional **Repository Filter**, en **Import Filters** en el formulario del conector.

El filtro se aplica durante la detección, **antes de realizar cualquier trabajo por repositorio**. Un repositorio fuera del filtro no tiene ningún coste: no se genera ningún informe de Xray para él y, en el modo de artefactos, no se enumera ninguno de sus artefactos de primer nivel. Esto lo convierte en la forma más eficaz de reducir tanto el tiempo de Sincronización como la carga que DefectDojo impone a su instancia de JFrog — más que cualquier ajuste aplicado más adelante en la Sincronización. Se recomienda especialmente junto con **Artifact-Level Records** en instancias grandes.

**Sintaxis:** una lista de claves de repositorio separadas por comas. Cada entrada puede usar comodines `*`:

* Una entrada que contenga `*` se compara como un patrón — `releases-*` coincide con toda clave de repositorio que comience por `releases-`, y `*docker-pr-local*` coincide con cualquier clave que contenga `docker-pr-local`. Un `*` coincide con cualquier secuencia de caracteres, incluido `/`.
* Una entrada sin `*` debe coincidir **exactamente** con una clave de repositorio.
* Un repositorio se detecta si coincide con **cualquier** entrada de la lista. Los espacios alrededor de las comas se ignoran.

```
releases-*, snapshots
```

El ejemplo anterior detecta todos los repositorios cuya clave comience por `releases-`, más el único repositorio llamado exactamente `snapshots`.

Notas:

* El filtro es una **lista de permitidos** (allow-list) — una coincidencia selecciona un repositorio. No existe sintaxis de exclusión o negación, por lo que no se puede expresar directamente "todo excepto X".
* La comparación es **sensible a mayúsculas y minúsculas**, tanto para entradas exactas como para comodines. `*` es el único carácter comodín; `?` y los rangos de caracteres no son compatibles.
* **Déjelo en blanco para detectar todos los repositorios.** Un valor que solo contiene espacios o comas se trata como en blanco.
* Un filtro que no coincide con nada simplemente no detecta nada — no se produce ningún error. Si una Sincronización no encuentra repositorios inesperadamente, revise el log del conector en busca de la entrada `repository filter scoped discovery`, que indica cuántos de los repositorios totales coincidieron.
* El campo se puede modificar después de crear la conexión.

**Cambiar el filtro más adelante:** los repositorios que un filtro recién restringido ya no incluye dejan de detectarse, y sus Registros existentes siguen el ciclo de vida normal de los productos que la herramienta ya no reporta — los Registros **mapeados** se marcan como `MISSING` en la siguiente Sincronización, y los Registros `NEW` sin mapear se eliminan. Los hallazgos ya importados en DefectDojo no se eliminan; el filtro solo rige la detección.

#### Registros a nivel de artefacto

El interruptor **Artifact-Level Records** cambia la detección a un nivel por debajo del repositorio: cada entrada de primer nivel bajo la raíz de un repositorio (para repositorios Docker, cada imagen; para repositorios genéricos, cada archivo o carpeta de nivel superior) se convierte en su propio Registro. Cada Sincronización sigue generando un único informe de Xray por repositorio — DefectDojo atribuye cada vulnerabilidad a los artefactos a los que afecta, de modo que la carga sobre su instancia de JFrog no aumenta.

> **Compruebe en qué modo se encuentra antes de su primera Sincronización.** Artifact-Level Records está **activado de forma predeterminada para las instalaciones nuevas**. Las instalaciones anteriores a esta función conservan su diseño existente a nivel de repositorio, por lo que el interruptor permanece desactivado hasta que alguien lo active. En ambos casos, el interruptor se puede cambiar en cualquier momento — consulte *Cambiar una conexión existente* más abajo.

Con Artifact-Level Records habilitado:

* Los repositorios permanecen como Registros y se convierten en **activos principales**: no contienen hallazgos propios, pero cuando la función Asset Hierarchy está habilitada, DefectDojo relaciona automáticamente cada activo de artefacto con su activo de repositorio mediante una relación `parent`. Los activos se pueden filtrar entonces por elemento principal/secundario, y los hallazgos se propagan hacia arriba en la jerarquía.
* Una vulnerabilidad que afecta a varios artefactos se importa en el activo de cada artefacto afectado, de modo que cada activo muestra el conjunto completo de hallazgos que le afectan.
* Los hallazgos se limitan a la **última build** de cada artefacto, de modo que los hallazgos de un artefacto describen su build actual en lugar de acumular resultados de todas las builds que Xray haya escaneado alguna vez.
* Las relaciones jerárquicas creadas por el conector nunca sobrescriben las relaciones que usted haya creado manualmente. Si un activo ya tiene un elemento principal asignado, el conector lo deja tal cual.
* El token necesita además acceso de lectura a la API de almacenamiento de Artifactory (incluido en los ámbitos anteriores).

**Cambiar una conexión existente a Artifact-Level Records:** el interruptor se puede cambiar en cualquier momento. En la primera Sincronización posterior, aparecen nuevos Registros de artefactos para mapear — habilite **Auto Map** en la conexión al cambiar el interruptor para que los hallazgos se muevan sin interrupción. Los activos a nivel de repositorio dejan de recibir hallazgos y sus hallazgos importados previamente se cierran en su siguiente Sincronización (los mismos hallazgos se vuelven a importar bajo los nuevos activos de artefacto, con un estado nuevo); las notas y el historial de los hallazgos antiguos a nivel de repositorio permanecen en el activo de repositorio. Volver al modo anterior invierte esto: los Registros de repositorio vuelven a recibir hallazgos (los hallazgos previamente cerrados se reabren al volver a coincidir), y los Registros de artefacto se marcan como MISSING — sus activos y hallazgos se conservan pero dejan de actualizarse, por lo que puede archivarlos cuando le convenga.

Consulte la [documentación de la API REST de JFrog Xray](https://jfrog.com/help/r/jfrog-rest-apis/xray-rest-apis) para obtener más información.

## **Jira Service Management Assets**

El conector JSM Assets es un **conector de activos**: enumera los objetos de su espacio de trabajo de Jira Service Management Assets (anteriormente Insight) y crea un Activo de DefectDojo para cada objeto, agrupados en Organizaciones según el esquema del objeto. No se importa ningún hallazgo.

#### Requisitos previos

* Assets requiere un plan **Jira Service Management Premium o Enterprise**. En los planes Free o Standard, la API de Assets responde con `403 "Access to Assets API was denied"`, aunque el resto del sitio funcione con normalidad.
* La cuenta de Atlassian utilizada debe tener **acceso de producto a Jira Service Management** (una plaza de agente) en el sitio — el acceso al sitio por sí solo no es suficiente.
* Cree un token de API clásico de Atlassian en [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens). Recomendamos una cuenta de servicio dedicada.

#### Asignaciones del conector

1. Introduzca la URL de su sitio de Atlassian en el campo **Location**: `https://{your-site}.atlassian.net`.
2. Introduzca el correo electrónico de la cuenta de Atlassian al que pertenece el token en el campo **Email**.
3. Introduzca el token de API en el campo **Secret**.

Cada objeto de Assets se convierte en un Registro con el nombre de la etiqueta del objeto, agrupado por su **esquema de objeto**.

## **Kubescape**

El conector Kubescape lee los resultados de postura (configuraciones incorrectas) de Kubernetes generados por el [operador de Kubescape](https://kubescape.io/docs/install-operator/) directamente desde la API de Kubernetes del clúster — no se requiere ninguna cuenta SaaS de ARMO. Lee los objetos `WorkloadConfigurationScan` que expone la API agregada de almacenamiento dentro del clúster del operador (`spdx.softwarecomposition.kubescape.io/v1beta1`). Cada **namespace** de Kubernetes que tiene resultados de postura se asigna a un Registro (Producto); cada control fallido de una carga de trabajo se convierte en un Hallazgo.

#### Requisitos previos

- El operador de Kubescape debe estar instalado en el clúster de destino con el escaneo de configuración habilitado (consulte [Instalación en su clúster](https://kubescape.io/docs/install-operator/)). Confirme que existen resultados con `kubectl get workloadconfigurationscans -A`.
- Un **kubeconfig** que otorgue acceso de lectura al grupo de API `spdx.softwarecomposition.kubescape.io` (list/get sobre `workloadconfigurationscans`) para el clúster de destino.

#### Asignaciones del conector

1. Introduzca la URL del servidor de API del clúster (o un identificador descriptivo del clúster) en el campo **Location**.
2. Pegue el **kubeconfig** del clúster de destino en el campo `kubeconfig`. Opcionalmente, establezca `kube_context` para seleccionar un contexto dentro de él, y `cluster_name` para etiquetar los Productos detectados.
3. Cada namespace con resultados de postura se detecta como un Registro; mapee los que desee importar a Productos de DefectDojo.

Los hallazgos se derivan por control fallido: el nombre del control y la carga de trabajo identifican el Hallazgo, la severidad proviene del factor de puntuación del control, el ID del control se convierte en el ID de vulnerabilidad, y cada Hallazgo enlaza con su referencia de control en `https://hub.armosec.io/docs/`.

## **Mend**

El conector Mend (anteriormente **WhiteSource**) usa la API de Mend para importar hallazgos de seguridad de su organización de Mend. DefectDojo crea un Registro para cada **proyecto** de Mend.

#### Requisitos previos

Necesitará un usuario (de servicio) de Mend con una **User Key** (un token de acceso personal) y su **Organization UUID** de Mend. Recomendamos una cuenta de servicio dedicada para que la actividad automatizada sea fácil de distinguir de las acciones manuales del equipo. Encuentre el Organization UUID en la aplicación Mend en **Administration > Organization UUID**.

#### Asignaciones del conector

1. Introduzca la URL de la API de Mend en el campo **Location**. Esta URL es **específica de la región** — use la URL base de la API de la región donde está alojada su organización de Mend.
2. Introduzca el correo electrónico de inicio de sesión del usuario de Mend en el campo **Email**.
3. Introduzca su **Organization UUID** de Mend en el campo **Organization UUID**.
4. Introduzca la **User Key** de Mend en el campo **User Key**.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

## **Lacework / FortiCNAPP**

El conector Lacework / FortiCNAPP usa la API v2 de Lacework para importar **vulnerabilidades de hosts y contenedores** de toda su cuenta de Lacework.

#### Requisitos previos

Necesitará una **API key** de Lacework — un ID de clave de API y un secreto, creados en la consola de Lacework en **Settings → API keys**. El conector los intercambia por un token de acceso de corta duración en cada sincronización; el ID de clave, el secreto y el token nunca se registran en los logs.

#### Asignaciones del conector

1. Introduzca la URL de su cuenta de Lacework en el campo **Location** — por ejemplo `https://YOUR-ACCOUNT.lacework.net` (también se acepta un nombre de cuenta simple).
2. Introduzca el **API Key ID** y el **API Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna la **cuenta** de Lacework a un Registro (el ámbito de toda la cuenta). Cada vulnerabilidad de **contenedor** y de **host** se convierte en un hallazgo: la severidad proviene de la propia calificación de Lacework, el paquete y la versión afectados se convierten en el componente, la versión de corrección se convierte en la mitigación, y la imagen/host afectado se registra como etiquetas. Las vulnerabilidades de contenedor se registran como hallazgos estáticos (escaneos de imagen) y las vulnerabilidades de host como hallazgos dinámicos (escaneos de host en ejecución).

Consulte la [documentación de la API de Lacework](https://docs.lacework.net/api/v2/docs) para obtener más información.

## **Microsoft Defender**

El conector de Microsoft Defender importa hallazgos de vulnerabilidades de dispositivos desde **Microsoft Defender Vulnerability Management (MDVM)** — un hallazgo por cada combinación de dispositivo / versión de software / CVE, incluyendo severidad, puntuación CVSS, nivel de explotabilidad y las actualizaciones de seguridad recomendadas. DefectDojo descubrirá los **grupos de dispositivos** de Defender y creará un Record para cada uno; los dispositivos que no estén asignados a ningún grupo de dispositivos se agrupan bajo un grupo sintético llamado **Unassigned**.

**Tenga en cuenta:** este conector es distinto del tipo de escaneo basado en archivos **"MSDefender Parser"**, que importa archivos de Defender exportados manualmente. Elija una única vía de importación por Producto para evitar hallazgos duplicados.

#### Requisitos previos

Su tenant de Microsoft necesita una licencia activa que incluya las API de exportación de vulnerabilidades de Defender: **Defender for Endpoint Plan 2**, **Microsoft Defender Vulnerability Management Standalone**, o MDE P1/P2 con el add-on de MDVM. (El SKU *Add-on* de MDVM por sí solo no es suficiente: requiere tener Defender for Endpoint Plan 2 como base.)

El conector se autentica como un **registro de aplicación (app registration)** de Microsoft Entra ID mediante el flujo de credenciales de cliente. Para crear uno:

1. En el [portal de Azure](https://portal.azure.com), abra **App registrations > New registration**. Asígnele un nombre (por ejemplo, `defectdojo-connector`), deje los valores predeterminados y seleccione **Register**.
2. En la página **Overview** de la aplicación, anote el **Application (client) ID** y el **Directory (tenant) ID**.
3. Abra **API permissions > Add a permission > APIs my organization uses** y busque **WindowsDefenderATP**. Si no aparece, el backend de Defender de su tenant aún no se ha aprovisionado: asegúrese de que la licencia esté activa, abra [security.microsoft.com](https://security.microsoft.com) una vez y vuelva a intentarlo pasados unos minutos.
4. Elija **Application permissions** (*no* Delegated: los permisos delegados nunca aparecen en el token de servicio del conector), expanda **Vulnerability**, marque **Vulnerability.Read.All** y seleccione **Add permissions**.
5. Seleccione **Grant admin consent** y confirme. La columna Status debe mostrar una marca verde: sin este paso, cada llamada a la API devuelve un error 403.
6. Abra **Certificates & secrets > New client secret**, establezca una fecha de caducidad y copie el **Value** del secreto de inmediato (solo se muestra una vez). El conector deja de funcionar cuando el secreto caduca, así que anote la fecha.

#### Asignaciones del conector

1. Ingrese `https://api.security.microsoft.com` en el campo **Location**.
2. Ingrese el **Directory (tenant) ID** en el campo **Tenant ID**.
3. Ingrese el **Application (client) ID** en el campo **Client ID**.
4. Ingrese el valor del secreto de cliente en el campo **Client Secret**.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada grupo de dispositivos de Defender se convierte en un Record. Microsoft regenera la instantánea de vulnerabilidades que lee el conector aproximadamente cada 6 horas, y los dispositivos recién incorporados pueden tardar hasta ~24 horas en producir sus primeros datos de vulnerabilidad: es normal que un tenant recién creado sincronice (Sync) cero hallazgos hasta que los dispositivos se incorporen y evalúen. La propia activación de la licencia también puede tardar ~20 minutos o más en propagarse a la API (los errores "No active license found" durante ese período se resuelven por sí solos).

## **Microsoft Defender for Cloud**

El conector de Microsoft Defender for Cloud importa hallazgos de vulnerabilidades de **Microsoft Defender Vulnerability Management (MDVM)** tal como los expone Defender for Cloud, tanto hallazgos de **servidor** (CVEs del sistema operativo y del software instalado en VM de Azure) como hallazgos de **registro de contenedores** (CVEs de imágenes de contenedor), incluyendo severidad, puntuación CVSS, el paquete o la imagen afectados y la remediación. DefectDojo descubre las **suscripciones** de Azure que su entidad de servicio (service principal) puede leer y crea un Record por cada suscripción habilitada.

**Tenga en cuenta:** este conector es distinto del conector **Microsoft Defender**, que importa hallazgos de dispositivos desde la API de Defender for Endpoint. Defender for Cloud es un producto de Azure con una superficie de API diferente (Azure Resource Manager / Resource Graph) y un modelo de permisos diferente (Azure RBAC). Ejecute el que corresponda según dónde residan sus hallazgos, o ambos si usa los dos productos.

#### Requisitos previos

Necesita una o más **suscripciones de Azure con Microsoft Defender for Cloud habilitado**, con los planes de Defender pertinentes activados para los recursos que desea escanear (en **Microsoft Defender for Cloud > Environment settings**, y luego seleccione su suscripción):

* **Defender for Servers (Plan 2)**: hallazgos de CVE del sistema operativo y del software de VM de Azure (escaneo de vulnerabilidades sin agente).
* **Defender for Containers**: hallazgos de CVE de imágenes del registro de contenedores.

Los hallazgos de evaluación de vulnerabilidades de SQL y de configuración/postura **no** se importan intencionalmente: este conector solo importa vulnerabilidades CVE.

El conector se autentica como un **registro de aplicación (app registration)** de Microsoft Entra ID mediante el flujo de credenciales de cliente:

1. En el [portal de Azure](https://portal.azure.com), abra **App registrations > New registration**. Asígnele un nombre (por ejemplo, `defectdojo-connector`), deje los valores predeterminados y seleccione **Register**.
2. En la página **Overview** de la aplicación, anote el **Application (client) ID** y el **Directory (tenant) ID**.
3. Abra **Certificates & secrets > New client secret**, establezca una fecha de caducidad y copie el **Value** del secreto de inmediato (solo se muestra una vez). El conector deja de funcionar cuando el secreto caduca, así que anote la fecha.
4. Otorgue a la aplicación acceso de lectura a cada suscripción que desee importar: abra **Subscriptions**, seleccione su suscripción y luego **Access control (IAM) > Add > Add role assignment**. Seleccione el rol **Security Reader** (o **Reader**) y, en la pestaña **Members**, asígnelo a la aplicación que creó; búsquela por el **nombre** o el **object ID** de la aplicación, ya que el selector no coincide con el client ID. Repita esto para cada suscripción.

A diferencia del conector Microsoft Defender basado en dispositivos, no se requieren permisos de API ni consentimiento de administrador: el acceso a Defender for Cloud se rige completamente por la asignación de rol de Azure RBAC descrita arriba.

#### Asignaciones del conector

1. Ingrese `https://management.azure.com` en el campo **Location**. (Para nubes soberanas, use el endpoint de ARM correspondiente, por ejemplo `https://management.usgovcloudapi.net`.)
2. Ingrese el **Directory (tenant) ID** en el campo **Tenant ID**.
3. Ingrese el **Application (client) ID** en el campo **Client ID**.
4. Ingrese el valor del secreto de cliente en el campo **Client Secret**.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada suscripción de Azure habilitada se convierte en un Record. Los hallazgos se leen a través de Azure Resource Graph, por lo que aparecen con rapidez una vez que Defender for Cloud ha escaneado sus recursos, pero los escaneos en sí se ejecutan según la programación de Microsoft: las imágenes del registro de contenedores suelen escanearse dentro de la hora siguiente a su carga (push), mientras que el primer escaneo de vulnerabilidades sin agente de una VM puede tardar varias horas. Es normal que una suscripción recién habilitada sincronice (Sync) cero hallazgos hasta que se hayan escaneado sus recursos.

## **MobSF**

El conector de MobSF usa la API REST de [Mobile Security Framework (MobSF)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) para importar resultados de análisis estático de aplicaciones móviles (APK/IPA). DefectDojo descubre cada app que se ha escaneado en su instancia de MobSF y crea un Record para cada una, y luego importa los hallazgos de análisis estático de esa app.

#### Requisitos previos

Necesitará su **REST API key** de MobSF. Encuéntrela en la página de inicio de MobSF, en **API** (también se muestra en la documentación de MobSF como el valor `Authorization`). La clave se envía en cada solicitud y nunca se registra en los logs.

#### Asignaciones del conector

1. Ingrese la URL base de MobSF en el campo **Location** (por ejemplo, `https://mobsf.example.com`).
2. En el campo **Secret**, ingrese la REST API key de MobSF.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **app** escaneada a un Record e importa sus hallazgos del informe JSON de MobSF en varias secciones: permisos de la aplicación, análisis de código, el certificado de firma, el manifiesto de Android, el uso de la API de Android y el análisis binario. Cada hallazgo se etiqueta con **CWE 919** (móvil), y su severidad proviene de la propia calificación de MobSF (high, warning, info, secure/good); un permiso *dangerous* se trata como Alta. Los hallazgos se registran como hallazgos estáticos y se deduplican por el scan, la sección, el título, la severidad y la ruta del archivo.

Consulte la [documentación de la API REST de MobSF](https://mobsf.github.io/docs/#/rest_api) para más información.

## **NeuVector**

El conector de NeuVector usa la API REST del controlador de [NeuVector](https://github.com/neuvector/neuvector) para importar **escaneos de vulnerabilidades de imágenes** de contenedor. DefectDojo descubre cada imagen que NeuVector ha escaneado y crea un Record para cada una, y luego importa el informe de escaneo de esa imagen como hallazgos.

#### Requisitos previos

Necesitará un **nombre de usuario y contraseña** de NeuVector para una cuenta del controlador con permiso para leer los resultados de los escaneos. El conector inicia sesión con estas credenciales para obtener un token de sesión; la contraseña y el token nunca se registran en los logs.

#### Asignaciones del conector

1. Ingrese la URL del controlador de NeuVector en el campo **Location**, incluyendo el puerto de la API REST; por ejemplo, `https://neuvector.example.com:10443`.
2. Ingrese el **Username** y **Password** del controlador.
3. Si su controlador usa un certificado autofirmado, establezca **Skip TLS Verification** en `true`.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **imagen** escaneada a un Record y cada **CVE** de su informe de escaneo a un hallazgo. La severidad proviene de la propia calificación de NeuVector, y se trasladan el paquete y la versión afectados, la puntuación y el vector CVSSv3, la versión de corrección (como mitigación) y el enlace de referencia. Los hallazgos se deduplican por la imagen, el CVE, el paquete, la versión y la severidad.

Consulte la [documentación de la API de NeuVector](https://open-docs.neuvector.com/automation/automation) para más información.

## **Nuclei (ProjectDiscovery Cloud)**

El conector de Nuclei usa la API REST de ProjectDiscovery Cloud Platform (PDCP) para obtener resultados de escaneo de [nuclei](https://github.com/projectdiscovery/nuclei) desde su cuenta de PDCP. DefectDojo descubre cada escaneo de la cuenta y crea un Record independiente para cada **escaneo**.

#### Requisitos previos

Necesitará una **API key** de ProjectDiscovery Cloud. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada se distinga claramente de las acciones manuales del equipo. Genere una clave desde **Settings > API Key** en la interfaz de ProjectDiscovery Cloud ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Los resultados llegan a PDCP ya sea desde escaneos alojados (hosted) o desde la CLI de nuclei ejecutada con `-dashboard`.

#### Asignaciones del conector

1. Ingrese la URL base de la API de PDCP en el campo **Location**: `https://api.projectdiscovery.io`.
2. Ingrese su **API key** en el campo **Secret**.
3. Opcionalmente, ingrese un **Team ID** para limitar la sincronización a un espacio de trabajo de equipo (se encuentra en **Settings > Team**). Si se deja en blanco, DefectDojo sincroniza su espacio de trabajo personal.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **escaneo** de PDCP como un Record independiente e importa los hallazgos de ese escaneo en todas las severidades, incluida la informativa.

## **OpenVAS / Greenbone**

El conector de OpenVAS / Greenbone importa **hallazgos de vulnerabilidades de red** desde una instancia de Greenbone (Greenbone Community Edition o Greenbone Enterprise). Se comunica con `gvmd` mediante **GMP (Greenbone Management Protocol)** —un protocolo XML sobre un socket TLS, no HTTP— y sincroniza toda la instancia: enumera las **tareas (tasks)** de escaneo y crea un producto de DefectDojo para cada una, importando los resultados del informe más reciente de cada tarea.

#### Requisitos previos

Un **usuario GMP** de Greenbone (nombre de usuario + contraseña) y acceso de red al puerto TLS de GMP de gvmd (por defecto **9390**). El stack de compose de Greenbone Community Edition expone gvmd a través de un socket unix, así que para alcanzarlo desde un conector conectado en red debe ejecutar el conector donde pueda acceder al socket, o exponer el puerto TLS de GMP (por ejemplo, un puente TLS con `socat` hacia `gvmd.sock`).

#### Asignaciones del conector

1. Ingrese el host de gvmd en el campo **Location** (host o `host:port`).
2. Ingrese el **Username** y **Password** de GMP.
3. Opcionalmente, establezca el **GMP Port** (por defecto 9390).
4. Para el certificado autofirmado predeterminado de gvmd, proporcione un **CA Certificate (PEM)** contra el cual verificar, o bien establezca **Skip TLS Verification** en `true`.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada tarea de Greenbone se convierte en un Record. Los hallazgos provienen del informe finalizado más reciente de la tarea, uno por cada `<result>`. La severidad se toma del nivel de amenaza (threat level) del resultado (los niveles informativos `Log`/`Debug` de Greenbone se asignan a Informativa), y se registra la puntuación CVSS numérica; las referencias CVE se convierten en identificadores de vulnerabilidad, la solución del NVT se convierte en la mitigación, y el host/puerto de cada resultado se convierte en un endpoint.

## Probely

Este conector usa la API REST de Probely para obtener datos.

​**Asignaciones del conector**

1. Ingrese la dirección del servidor de API correspondiente en el campo **Location**. (ya sea <https://api.us.probely.com/> o <https://api.eu.probely.com/> )
2. Ingrese una API key válida en el campo **Secret**.

Puede encontrar una API key en el menú User > API Keys de Probely.  
Consulte la [documentación de Probely](https://help.probely.com/en/articles/8592281-how-to-generate-an-api-key) para más información.

## Prowler

El conector de Prowler usa la API REST de **Prowler App** para importar hallazgos de postura de seguridad en la nube (CSPM) desde una instancia de Prowler App autoalojada. DefectDojo descubre cada **provider** (cuenta en la nube) de Prowler como un Record e importa los hallazgos **FAIL** del escaneo completado más reciente de ese provider.

#### Requisitos previos

Necesitará una instancia de **Prowler App** autoalojada en ejecución, y ya sea un correo electrónico y contraseña de usuario (para autenticación JWT) o una **API key** de Prowler App. Los hallazgos solo aparecen una vez que haya conectado una cuenta en la nube (AWS, GCP, Azure, Kubernetes, ...) en Prowler App y ejecutado un escaneo.

#### Asignaciones del conector

1. Ingrese la URL de Prowler App en el campo **Location** (por ejemplo, `https://prowler.your-company.com`).
2. Para autenticación JWT, ingrese el **Email** y **Password** del usuario de Prowler App. Alternativamente, deje esos campos en blanco e ingrese una **API Key** de Prowler App. Si se proporcionan ambos, se usa el email/password (JWT).
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importan.

DefectDojo crea un Record para cada provider de Prowler e importa los hallazgos FAIL de su escaneo completado más reciente, asignando las severidades de Prowler a las severidades de DefectDojo, el recurso en la nube afectado (ARN/resource id) como componente, y la remediación y el riesgo del check al hallazgo. Los hallazgos silenciados (muted) se omiten. La cuenta en la nube, la región y el servicio se adjuntan como etiquetas (tags).

Para más información, consulte la **[documentación de la API de Prowler App](https://api.prowler.com/api/v1/docs)**.

## Qualys

El conector de Qualys importa **detecciones de vulnerabilidades de hosts de VMDR** —cada una combinada con sus metadatos de Qualys KnowledgeBase (QID)— desde Qualys Cloud Platform. DefectDojo crea un Record para cada **host** de Qualys en su suscripción.

#### Requisitos previos

Una cuenta de usuario de Qualys con **acceso a la API de VMDR**, y la **URL del servidor de API (platform)** de su suscripción, que difiere según la suscripción. Encuéntrela en la interfaz de Qualys, en **Help > About**, o en la página de [Platform Identification](https://www.qualys.com/platform-identification/) de Qualys (por ejemplo, `https://qualysapi.qualys.com` para US Platform 1, o `https://qualysapi.qg2.apps.qualys.com` para US Platform 2).

#### Asignaciones del conector

1. Ingrese la URL del servidor de API de Qualys en el campo **Location** (por ejemplo, `https://qualysapi.qualys.com`).
2. Ingrese el nombre de usuario de la API de Qualys en el campo **Username**.
3. Ingrese la contraseña de la API de Qualys en el campo **Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada host de Qualys se convierte en un Record. Las detecciones que Qualys ha marcado como **Fixed** se excluyen, por lo que reimportar cierra los hallazgos remediados.

## **Quay**

El conector de Quay usa la API REST de Project Quay para descubrir repositorios de contenedores e importar los informes de vulnerabilidades generados por el escáner **Clair** integrado de Quay. DefectDojo crea un Record para cada **repositorio** de Quay y, en cada Sync, lee el informe de seguridad de Clair del manifiesto de imagen de cada tag activo.

#### Requisitos previos

El escaneo de seguridad (Clair) debe estar habilitado en su instancia de Quay, y necesitará un **token de acceso OAuth 2** de Quay:

* En Quay, cree (o abra) una Organization, vaya a **Applications**, cree una aplicación OAuth y luego **Generate Token** con al menos el alcance (scope) **Read repositories**. Se recomienda una aplicación dedicada para DefectDojo.
* El token se envía como un Bearer token en cada solicitud y nunca se registra en los logs.

#### Asignaciones del conector

1. Ingrese la URL base de Quay en el campo **Location**, por ejemplo `https://quay.io` o su instancia autoalojada `https://quay.example.com`. La URL debe ser HTTPS; no incluya una ruta de API al final: DefectDojo construye las rutas de la API automáticamente.
2. Ingrese el token de acceso OAuth en el campo **Secret**.
3. Opcionalmente, establezca un **Namespace** para restringir el descubrimiento a una única organización o usuario de Quay. Déjelo en blanco para descubrir todos los repositorios que el token pueda leer.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **repositorio** de Quay a un Record. Para cada repositorio, enumera los tags activos, los deduplica a sus manifiestos de imagen únicos (un manifiesto compartido por varios tags se escanea una sola vez) y lee el informe de Clair de cada manifiesto. Los manifiestos que Clair aún no ha terminado de escanear (por ejemplo, una lista de manifiestos multi-arquitectura, o una imagen aún en cola) se omiten hasta un Sync posterior. Cada vulnerabilidad de Clair se convierte en un hallazgo: el paquete afectado es el componente, la versión corregida se convierte en la mitigación, y las severidades **Negligible**/**Unknown** de Clair se registran como **Informativa**.

Consulte la [documentación de la API de Project Quay](https://docs.projectquay.io/api_quay.html) y la [documentación de Clair](https://quay.github.io/clair/) para más información.

## **Rapid7 InsightAppSec**

El conector de Rapid7 InsightAppSec importa **hallazgos de vulnerabilidades DAST** desde la plataforma en la nube InsightAppSec, enriquecidos con metadatos del módulo de ataque (por ejemplo, *SQL Injection*), puntuaciones CVSS y la evidencia recopilada por el escaneo. DefectDojo crea un Record para cada **app** de InsightAppSec.

**Tenga en cuenta:** este conector es distinto del conector **Rapid7 InsightVM** que se describe más abajo: InsightAppSec es el producto DAST en la nube de Rapid7 dentro de la plataforma Insight, mientras que los hallazgos de InsightVM provienen de su propia Security Console.

#### Requisitos previos

Una cuenta de la plataforma Insight con InsightAppSec, y una **API key** de la plataforma: en [Rapid7 Insight platform](https://insight.rapid7.com), abra el menú de configuración (el ícono de engranaje) > **API Keys** y genere una **User Key** (cualquier rol) o una **Organization Key** (administradores de la plataforma). Copie la clave cuando se muestre: solo se muestra una vez.

También necesitará la **región** de su plataforma, visible en su URL de Insight (por ejemplo, `us`, `us2`, `us3`, `eu`, `ca`, `au` o `ap`).

#### Asignaciones del conector

1. Ingrese el endpoint de API de su región en el campo **Location**, por ejemplo `https://us.api.insight.rapid7.com` (reemplace `us` por su región).
2. Ingrese la API key de la plataforma Insight en el campo **API Key**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada app de InsightAppSec se convierte en un Record. Solo se importan las vulnerabilidades **abiertas** (Unreviewed o Verified): los hallazgos que Rapid7 ha marcado como Remediated, Falso positivo, Ignored o Duplicado se excluyen, por lo que reimportar los cierra en DefectDojo. Las severidades se asignan directamente (`SAFE` e `INFORMATIONAL` se importan como Informativa).

## **Rapid7 InsightVM**

El conector de Rapid7 InsightVM importa hallazgos de vulnerabilidades de activos desde su **Security Console** de InsightVM (API v3), enriquecidos con el catálogo global de vulnerabilidades de la consola. DefectDojo crea un Record para cada **site** de InsightVM.

#### Requisitos previos

Acceso de red desde DefectDojo hasta su Security Console, y una **cuenta de usuario** de la consola; su inicio de sesión se usa para la autenticación HTTP Basic. La API de la consola se sirve por defecto en el puerto **3780**.

#### Asignaciones del conector

1. Ingrese la URL de su Security Console, incluyendo el puerto, en el campo **Location**; por ejemplo, `https://console.example.com:3780`.
2. Ingrese el nombre de usuario de la consola en el campo **Username**.
3. Ingrese la contraseña de la consola en el campo **Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada site de InsightVM se convierte en un Record; el conector recorre los activos del site e importa sus hallazgos de vulnerabilidades.

## **runZero**

El conector de runZero usa la Export API de runZero para sincronizar el inventario de activos de toda su organización en DefectDojo. Es principalmente un conector de **activos**: DefectDojo descubre cada activo y crea un Record para cada uno, agrupados en un Product Type según su **site** de runZero. Opcionalmente, también puede importar las vulnerabilidades de runZero como hallazgos.

#### Requisitos previos

Necesitará un **Export Token** de organización de runZero (Account → API), con el prefijo `XT`. El token tiene alcance de organización (la organización está codificada en el token), es de solo lectura, y se envía como un Bearer token; nunca se registra en los logs. Hay disponible un nivel community/starter.

#### Asignaciones del conector

1. Ingrese la URL de la consola de runZero en el campo **Location**, por ejemplo `https://console.runzero.com`. La URL debe ser HTTPS.
2. Ingrese el Export Token en el campo **Secret**.
3. Opcionalmente, establezca **Import Vulnerabilities** en `true` para importar también las vulnerabilidades de runZero como hallazgos; déjelo en blanco para sincronizar solo los activos.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos de vulnerabilidades se importan (aplica solo cuando se importan vulnerabilidades).

DefectDojo asigna cada **activo** de runZero a un Record (VEP): el nombre visible proviene del nombre o la dirección del activo, y su site, tipo, SO, direcciones y etiquetas se adjuntan como atributos; el **site** del activo se convierte en su Product Type. Los activos se sincronizan mediante una exportación completa que DefectDojo concilia (agrega/elimina). Cuando **Import Vulnerabilities** está habilitado, cada vulnerabilidad de runZero se convierte en un hallazgo en su activo, asignando la severidad, la puntuación CVSS, el CVE, el endpoint del servicio afectado (`protocol://address:port`) y la remediación.

Consulte la [documentación de la API de runZero](https://help.runzero.com/) para más información.

## **Semgrep**

Este conector usa la API REST de Semgrep para obtener datos.

#### Asignaciones del conector

Ingrese `https://semgrep.dev/api/v1/` en el campo **Location**.

1. Ingrese una API key válida en el campo **Secret**. La puede encontrar en la página de Tokens:   
​  
"Settings" en la barra de navegación izquierda > Tokens > Create new token ([https://semgrep.dev/orgs/\-/settings/tokens](https://semgrep.dev/orgs/-/settings/tokens))

Consulte la [documentación de Semgrep](https://semgrep.dev/docs/semgrep-cloud-platform/semgrep-api/#tag__badge-list) para más información.

## **ServiceNow CMDB**

El conector de ServiceNow CMDB es un **conector de activos (Asset Connector)**: en lugar de importar hallazgos, lee Configuration Items (CI) de su ServiceNow Configuration Management Database y crea un Asset de DefectDojo para cada CI, agrupados en Organizations según su clase de CI. No se importa ningún hallazgo.

#### Requisitos previos

Necesitará una instancia de ServiceNow y una cuenta que pueda leer las tablas de CMDB a través de la ServiceNow Table API. Recomendamos una cuenta de servicio dedicada y de solo lectura para DefectDojo. La cuenta necesita acceso de lectura a las tablas `cmdb_ci` que desea importar.

#### Asignaciones del conector

1. Ingrese la URL de su instancia de ServiceNow en el campo **Location**: `https://{your-instance}.service-now.com`.
2. Seleccione o cree una **Tool Configuration** de ServiceNow que contenga las credenciales de la instancia (el nombre de usuario y la contraseña de ServiceNow).

Cada Configuration Item se convierte en un Record con el nombre del CI, agrupado por su **clase de CI** (por ejemplo, aplicación, servidor o servicio de negocio). Discovery y Sync concilian la lista de CI: los CI nuevos aparecen como Records `NEW`, y un CI eliminado del CMDB se marca como `MISSING` en el siguiente Sync para que su equipo pueda triarlo. DefectDojo nunca elimina un Producto de forma silenciosa.

## **Shodan**

El conector de Shodan usa la API REST de Shodan para importar las vulnerabilidades (CVE) que Shodan ha observado en sus hosts expuestos a internet. Usted proporciona una consulta de búsqueda de Shodan que limita la importación a sus propios activos; DefectDojo crea un Record para cada host coincidente e importa sus CVE como hallazgos.

#### Requisitos previos

Necesitará una API key de Shodan, disponible en la página **Account** de Shodan. La búsqueda de hosts con datos de vulnerabilidades requiere una membresía de Shodan o un plan de API de pago: el nivel gratuito no puede paginar los resultados de búsqueda.

#### Asignaciones del conector

1. Ingrese `https://api.shodan.io` en el campo **Location**.
2. Ingrese su API key de Shodan en el campo **API Key**.
3. En el campo **Search Query**, ingrese una consulta de Shodan que limite la importación a los activos de su organización; por ejemplo, `hostname:example.com`, `net:203.0.113.0/24`, u `org:"Example Inc"`. Solo se importan los hosts que coincidan con esta consulta, así que manténgala limitada a la infraestructura que usted posee.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada host coincidente se convierte en un Record, y cada CVE que Shodan detectó en los servicios expuestos de ese host se importa como un hallazgo; la severidad se deriva de la puntuación CVSS, incluyendo el contexto de EPSS y CISA KEV cuando está disponible. Cada página de resultados de búsqueda consume un crédito de consulta de Shodan.

## SonarQube

El conector de SonarQube puede obtener datos tanto de una cuenta de SonarCloud como de una instancia local de SonarQube.

**Para usuarios de SonarCloud:**

1. Ingrese https://sonarcloud.io/ en el campo Location.
2. Ingrese una **API key** válida en el campo Secret.

**Para usuarios de SonarQube (on-premise):**

1. Ingrese la URL base de su instancia de SonarQube en el campo Location: por ejemplo, `https://my.sonarqube.com/`
2. Ingrese una **API key** válida en el campo Secret. Deberá ser un **[User](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/)** [API Token Type](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

El token deberá tener acceso a Projects, Vulnerabilities y Hotspots dentro de Sonar.

Los tokens de API se pueden encontrar y generar a través de **My Account -> Security -> Generate Token** en la aplicación de SonarQube. Para más información, [consulte la documentación de SonarQube](https://docs.sonarsource.com/sonarqube/latest/user-guide/user-account/generating-and-using-tokens/).

## **Snyk**

El conector de Snyk usa la API REST de Snyk para obtener datos.

#### Asignaciones del conector

1. Ingrese **[https://api.snyk.io/rest](https://api.snyk.io/v1)** o **[https://api.eu.snyk.io/rest](https://api.eu.snyk.io/v1)** (para una implementación regional en la UE) en el campo **Location**.
2. Ingrese una API key válida en el campo **Secret**. Los API Tokens se encuentran en la **[Account Settings](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token)** [página](https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token) de un usuario en Snyk.

Consulte la [documentación de la API de Snyk](https://docs.snyk.io/snyk-api) para más información.

## **Socket**

El conector de Socket usa la API de [Socket.dev](https://socket.dev) para importar **hallazgos de la cadena de suministro de software** — las alertas de Socket sobre sus dependencias (malware, typosquatting, scripts de instalación, vulnerabilidades conocidas y más de 70 categorías adicionales). DefectDojo descubre todos los repositorios de las organizaciones a las que su token tiene acceso y crea un Record para cada uno, luego importa las alertas del análisis completo más reciente de ese repositorio.

#### Prerrequisitos

Necesitará un **token de API** de Socket — un token de organización creado en el panel de Socket en **Settings → API Tokens** (con los alcances `repo:list` y de lectura de full-scan). El token se envía como bearer token y nunca se registra en los logs.

#### Asignaciones del conector

1. Deje el campo **Location** en blanco para usar `https://api.socket.dev/v0`, o introdúzcalo explícitamente.
2. Introduzca el token de API de Socket en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **repositorio** a un Record e importa las alertas de su análisis completo más reciente. Cada alerta se convierte en un hallazgo: la severidad proviene de la propia calificación de Socket (low, medium, high, critical), el paquete afectado se convierte en el componente y en un PURL, la categoría de la alerta (riesgo de cadena de suministro, calidad, mantenimiento, vulnerabilidad, licencia) se registra como etiquetas, y los detalles de la alerta se incorporan a la descripción. Los hallazgos se registran como hallazgos estáticos y se deduplican según la clave de alerta de Socket.

Consulte la [documentación de la API de Socket](https://docs.socket.dev/reference) para más información.

## **Sonatype IQ**

El conector de Sonatype IQ usa la API REST del servidor Sonatype IQ (Nexus Lifecycle) para importar vulnerabilidades de componentes de código abierto. Enumera todas las aplicaciones de su organización de IQ y, para cada una, importa las vulnerabilidades de componentes del informe más reciente de esa aplicación en la etapa del ciclo de vida que configure. DefectDojo crea un Record para cada aplicación automáticamente — no hay configuración por aplicación.

#### Prerrequisitos

Necesitará una cuenta de usuario de Sonatype IQ con el permiso **View IQ Elements** en las aplicaciones que desea importar. Sonatype recomienda autenticarse con un **user token** (generado en **My Profile > User Token** en IQ Server) en lugar de una contraseña; las dos partes del token se corresponden con los campos Username y User Token que aparecen a continuación. El conector funciona tanto con instancias de IQ Server autoalojadas como con instancias alojadas por Sonatype (SaaS).

#### Asignaciones del conector

1. En el campo **Location**, introduzca la URL base de su IQ Server — para un servidor autoalojado, `https://iq.example.com`; para una instancia alojada por Sonatype, `https://<tenant>.sonatype.app/platform`.
2. Introduzca el usuario de IQ (o la parte de código de usuario de su user token) en el campo **Username**.
3. Introduzca el user token de IQ (o la contraseña) en el campo **User Token**.
4. Opcionalmente, establezca un **Stage** para elegir de qué etapa del ciclo de vida se importa el informe por aplicación (`build`, `stage-release`, `release`, etc.). Déjelo en blanco para usar `build`.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada aplicación se convierte en un Record, y cada problema de seguridad en el informe más reciente de esa aplicación para la etapa seleccionada se importa como un hallazgo. La severidad se deriva de la puntuación numérica del problema, y se incluyen las referencias CVE, el CWE, el vector CVSS y la URL del paquete (PURL) del componente afectado cuando están disponibles.
## **Sysdig Secure**

El conector de Sysdig Secure importa **hallazgos de vulnerabilidades de contenedores / CNAPP** desde la API de gestión de vulnerabilidades de Sysdig Secure. Sincroniza toda la cuenta en el/los alcance(s) configurado(s) y crea un producto de DefectDojo para cada agrupación de activos escaneados.

#### Prerrequisitos

Un **token de API** de Sysdig Secure: en Sysdig Secure, vaya a **Settings > Sysdig Secure API Token** y copie el token. También necesita la **URL de región** de Sysdig (por ejemplo, `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, o su host on-premises).

#### Asignaciones del conector

1. Introduzca la URL de región/base de Sysdig en el campo **Location**.
2. Introduzca el token de API en el campo **Secret**.
3. Opcionalmente, establezca **Scopes** — una lista separada por comas de `runtime`, `registry`, y/o `pipeline` (déjelo en blanco para `runtime`, el alcance de cargas de trabajo desplegadas).
4. Opcionalmente, establezca **Runtime Product Grouping** — cómo se asignan los resultados de runtime a los productos: `cluster`, `namespace`, `workload`, o `image` (déjelo en blanco para `namespace`). Los resultados de registry y pipeline siempre se agrupan por repositorio de imágenes.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada agrupación de activos se convierte en un Record. Para cada resultado de análisis, el conector importa cada paquete vulnerable como un hallazgo. Los hallazgos de **runtime** (cargas de trabajo desplegadas) se registran como hallazgos dinámicos y se etiquetan con su contexto de clúster/namespace/workload/contenedor de Kubernetes; los hallazgos de **registry** y **pipeline** se registran como hallazgos estáticos de análisis de imágenes. La severidad `NEGLIGIBLE` de Sysdig se asigna a Informativa.

## Tenable

El conector de Tenable usa la API REST de **Tenable.io** para obtener datos. Los análisis se obtienen del endpoint `/scans` de Tenable VM.

Los conectores de Tenable on-premise no están disponibles por el momento.

#### **Asignaciones del conector**

1. Introduzca <https://cloud.tenable.com> en el campo Location.
2. Introduzca una **API key** válida en el campo Secret.

Consulte la [documentación de la API de Tenable](https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm) para más información.

## **Tenable Web App Scanning**

El conector de Tenable Web App Scanning importa **hallazgos de aplicaciones web (DAST)** desde Tenable Web App Scanning. Es un conector independiente de Tenable (Vulnerability Management): los dos productos cubren activos diferentes y se configuran de forma independiente, por lo que puede usar uno u otro, o ambos.

DefectDojo crea un Record para cada **aplicación web escaneada**. Las aplicaciones se descubren a partir de sus configuraciones de análisis de Web App Scanning; una configuración que nunca se ha ejecutado no genera un Record hasta que se complete su primer análisis. Cuando más de una configuración analiza la misma aplicación, comparten un único Record.

#### Prerrequisitos

**API keys** de Tenable (una access key y una secret key) para un usuario con permisos de Web App Scanning. En Tenable, vaya a **My Account > API Keys** para generarlas, y confirme que el usuario puede ver los análisis que desea importar — las keys limitadas a Vulnerability Management no pueden leer datos de Web App Scanning.

Los conectores de Tenable on-premise no están disponibles por el momento.

#### Asignaciones del conector

1. Introduzca <https://cloud.tenable.com> en el campo **Location**.
2. Introduzca su **Access Key** y **Secret Key**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Los hallazgos se importan con la severidad que Tenable reporta para su cuenta, incluida cualquier severidad que su equipo haya reclasificado. Cada hallazgo incluye la URL afectada como endpoint, el parámetro de solicitud y el payload que lo desencadenó, y la prueba y el resultado de Tenable como pasos para reproducirlo, junto con los valores de CWE, CVE, CVSS y EPSS cuando el plugin de detección los proporciona.

Solo se importan los hallazgos que están actualmente abiertos o reabiertos. Un hallazgo que Tenable ha marcado como corregido se cierra en DefectDojo en la siguiente sincronización.

## **Veracode**

El conector de Veracode importa hallazgos de aplicaciones desde la plataforma Veracode, divididos por tipo de análisis en los tipos de hallazgo **SAST**, **DAST**, **SCA** y **Manual**. DefectDojo crea un Record para cada **aplicación** de Veracode.

#### Prerrequisitos

Genere una **credencial de API** de Veracode para una cuenta que pueda ver las aplicaciones que desea importar: en la Veracode Platform, abra el menú de su cuenta > **API Credentials** y seleccione **Generate API Credentials** (consulte [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Copie tanto el **API ID** como la **API Secret Key** — la clave secreta solo se muestra una vez.

#### Asignaciones del conector

1. Introduzca la URL base de la API de Veracode en el campo **Location**: `https://api.veracode.com` (región comercial), `https://api.veracode.eu` (región europea), o `https://api.veracode.us` (región federal de EE. UU.).
2. Introduzca el API ID en el campo **API ID**.
3. Introduzca la clave secreta de API en el campo **Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada aplicación de Veracode se convierte en un Record. Solo se importan los hallazgos **abiertos**, por lo que una nueva importación cierra los hallazgos que Veracode reporta como resueltos.

## **Wazuh**

El conector de Wazuh usa el Wazuh Indexer (OpenSearch) para obtener hallazgos de vulnerabilidades. Wazuh 4.8 y versiones posteriores almacenan los CVE detectados en el Indexer en lugar de en la API del servidor Wazuh, por lo que este conector los lee directamente del índice `wazuh-states-vulnerabilities-*`.

DefectDojo crea un Record para cada agente (endpoint) de Wazuh e importa los CVE detectados de ese agente como hallazgos de forma programada.

#### Prerrequisitos

Necesitará:

* La URL base de su Wazuh Indexer, incluido el puerto (el Indexer escucha por defecto en el puerto 9200). DefectDojo se conecta directamente al Indexer, por lo que este endpoint debe ser accesible desde DefectDojo. Para implementaciones autoadministradas, es el host que ejecuta el Wazuh Indexer. Para Wazuh Cloud, use el endpoint del Indexer que se muestra en su consola de Wazuh Cloud, que es distinto de la URL del panel de Wazuh.
* Un usuario y contraseña del Indexer con acceso de lectura al índice `wazuh-states-vulnerabilities-*`. Recomendamos crear un usuario dedicado para DefectDojo.

La detección de vulnerabilidades debe estar habilitada en Wazuh para que se rellene el índice de estado de vulnerabilidades. Consulte la [documentación de detección de vulnerabilidades de Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) para más información.

#### Asignaciones del conector

1. Introduzca la URL base de su Wazuh Indexer en el campo **Location**, incluyendo el esquema y el puerto, por ejemplo `https://your-indexer.example.com:9200`. No incluya una ruta final. DefectDojo construye las rutas de búsqueda automáticamente.
2. Introduzca el nombre de usuario del Indexer en el campo **Username**.
3. Introduzca la contraseña del Indexer en el campo **Password**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

## Wiz

Para usar el conector de Wiz es necesario crear una cuenta de servicio: consulte la [documentación de Wiz](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) para más información. Necesitará una cuenta de Wiz para acceder a la documentación.

La cuenta de servicio debe cumplir todos los siguientes requisitos. Una cuenta de servicio a la que le falte alguno de ellos aún puede autenticarse correctamente, pero no importará nada:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: como mínimo `read:projects`, `read:issues`, y `read:vulnerabilities`.
* **Project visibility**: la cuenta de servicio debe tener alcance sobre cada Wiz Project que desee importar (o sobre todos los Projects). El conector descubre primero sus Wiz Projects y luego obtiene los hallazgos de cada Project — una cuenta que puede leer issues pero no tiene visibilidad de Projects descubre cero Projects, por lo que no hay nada que importar y ninguno de los dos lados reporta un error.

#### **Asignaciones del conector**

1. Introduzca su Wiz Client ID en el campo Client ID.
2. Introduzca el Wiz Client Secret en el campo Secret.

## **YesWeHack**

El conector de YesWeHack usa la API REST de YesWeHack para importar informes de sus programas de bug bounty y divulgación de vulnerabilidades. DefectDojo crea un Record para cada programa al que su token pueda acceder e importa sus informes como hallazgos.

#### Prerrequisitos

Necesitará un **Personal Access Token (PAT)** de YesWeHack. Es suficiente con acceso de lectura a sus programas. Algunas cuentas requieren TOTP/MFA al crear un token; una vez creado, el conector usa el valor del token en sí.

1. En YesWeHack, abra la configuración de su cuenta y vaya a **API / Personal Access Tokens**.
2. Cree un token y copie su valor. Solo se muestra una vez.

#### Asignaciones del conector

1. Introduzca `https://api.yeswehack.com/` en el campo **Location**.
2. Introduzca su Personal Access Token en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

DefectDojo crea un Record independiente para cada programa al que su token pueda acceder, e importa cada informe como un hallazgo. La severidad del hallazgo se toma de la calificación CVSS del informe (recurriendo a la prioridad de triaje si no está disponible), y su estado refleja el estado del flujo de trabajo del informe — por ejemplo, los informes resueltos se importan como Mitigado, y los informes marcados como inválidos o fuera de alcance se importan como inactivos.
