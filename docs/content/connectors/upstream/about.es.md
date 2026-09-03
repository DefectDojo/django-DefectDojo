---
title: Conectores ascendentes
description: Conecte DefectDojo a su conjunto de herramientas de seguridad sin complicaciones
summary: ''
date: 2023-09-07 16:06:50+02:00
lastmod: 2023-09-07 16:06:50+02:00
draft: false
weight: 0
chapter: true
sidebar:
  collapsed: true
seo:
  title: ''
  description: ''
  canonical: ''
  robots: ''
pro-feature: true
aliases:
- /es/import_data/pro/connectors/about_connectors/
- /es/en/connecting_your_tools/connectors/about_connectors
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: los Conectores ascendentes son una función exclusiva de DefectDojo Pro.</span>

DefectDojo permite a los usuarios crear integraciones de API sofisticadas, y les da control total sobre cómo se organizan sus datos de vulnerabilidades.

Pero todos necesitan un punto de partida, y ahí es donde entran los Conectores ascendentes. Los Conectores ascendentes (antes conocidos como **Conectores de API**) están diseñados para conectar sus herramientas de seguridad e importar datos a DefectDojo lo más rápido posible.

Actualmente admitimos Conectores ascendentes para las siguientes herramientas, con más en camino:

* **Acunetix 360**
* **Akamai API Security**
* **Anchore**
* **AWS Security Hub**
* **Azure DevOps**
* **Backstage**
* **Bitbucket**
* **Black Duck**
* **Bright Security**
* **Bugcrowd**
* **BurpSuite**
* **Censys**
* **Checkmarx ONE**
* **Cloudflare**
* **Cobalt.io**
* **Contrast**
* **Coverity**
* **CrowdStrike Falcon**
* **Deepfence ThreatMapper**
* **Dependency-Track**
* **Docker Scout**
* **Edgescan**
* **Endor Labs**
* **Escape**
* **Fairwinds Insights**
* **Fortify**
* **GitGuardian**
* **GitHub**
* **GitHub Advanced Security**
* **GitLab**
* **Google Cloud Security Command Center**
* **Group-IB ASM**
* **HackerOne**
* **Harbor**
* **Have I Been Pwned**
* **HCL AppScan**
* **Intigriti**
* **Intruder**
* **IriusRisk**
* **JFrog Xray**
* **Jira Service Management Assets**
* **Kubescape**
* **Lacework / FortiCNAPP**
* **Mend**
* **Microsoft Defender**
* **Microsoft Defender for Cloud**
* **MobSF**
* **NeuVector**
* **Nuclei (ProjectDiscovery Cloud)**
* **OpenVAS / Greenbone**
* **Probely**
* **Prowler**
* **Qualys**
* **Quay**
* **Rapid7 InsightAppSec**
* **Rapid7 InsightVM**
* **Rapid7 InsightVM - Cloud Instance**
* **runZero**
* **Semgrep**
* **ServiceNow CMDB**
* **Shodan**
* **Snyk**
* **Socket**
* **SonarQube**
* **Sonatype IQ**
* **Sysdig Secure**
* **Tenable**
* **Tenable Web App Scanning**
* **Veracode**
* **Wazuh**
* **Wiz**
* **YesWeHack**

Para obtener instrucciones de configuración paso a paso de cada herramienta, consulte la referencia de [Configuración de conectores específicos por herramienta](../../toolreference/upstream/).

La mayoría de los Conectores importan **hallazgos**. Unos pocos son **Conectores de activos** que en su lugar importan su **inventario de activos** — creando y manteniendo su jerarquía de Producto (Activo) y Tipo de Producto (Organización) en lugar de importar hallazgos: **Azure DevOps**, **Backstage**, **Bitbucket**, **GitHub**, **GitLab**, **Jira Service Management Assets** y **ServiceNow CMDB**. (**runZero** es principalmente un Conector de activos, pero opcionalmente también puede importar vulnerabilidades como hallazgos.)

Estas conexiones ofrecen una integración a velocidad de API con DefectDojo, y se pueden usar para incorporar y organizar automáticamente los datos de vulnerabilidades de la herramienta.

## Cómo orientarse en la página de Conectores

Los Conectores se listan en dos secciones, cada una con un contador junto a su encabezado y ambas ordenadas alfabéticamente:

* **Conectores configurados** — cada configuración de conector que existe en esta instancia. Una herramienta puede aparecer varias veces, una por configuración, y cada tarjeta se titula `<Tool> - <label>` para poder distinguirlas. Cuando varias configuraciones comparten una herramienta, se ordenan por su etiqueta.
* **Conectores disponibles** — cada herramienta compatible que aún no ha configurado.

El contador junto a un encabezado es el número de conectores mostrados actualmente, por lo que responde al cuadro de búsqueda y al filtro de tipo **Asset / Finding**, en lugar de mostrar siempre el total. En DefectDojo Pro Cloud, la tarjeta **Request Upstream Connector** no es un conector y no se cuenta.

Ambas secciones tienen su propio cuadro de búsqueda, que coincide con el nombre de la herramienta.

![La página de Conectores, con un contador junto a cada encabezado de sección](images/upstream_counts.png)

Las páginas de [Conectores descendentes](/connectors/downstream/about/) y [Conectores de autorización](/admin/sso/pro__authorization_connectors/) están organizadas de la misma manera.

## Inicio rápido de Conectores ascendentes

Si usa la configuración **Auto-Map** de DefectDojo, puede tener su primer Conector funcionando en muy poco tiempo.

1. Configure un [Conector](../add_edit/) a partir de una herramienta compatible.
2. [Descubra](../manage_operations/#discover-operations) la jerarquía de datos de su herramienta.
3. [Sincronice](../manage_operations/#sync-operations) las vulnerabilidades encontradas por su herramienta con DefectDojo.

¡Eso es todo, de verdad! Y recuerde que, incluso si crea su Conector de la forma 'fácil', más adelante puede cambiar fácilmente la manera en que está configurado, sin perder nada de su trabajo.

## Cómo funcionan los Conectores ascendentes

Mientras tenga la clave de API de la herramienta que intenta conectar, un conector se puede añadir en solo unos minutos. Una vez que la conexión funciona, DefectDojo **descubrirá** el entorno de su herramienta para ver cómo está organizando sus datos de escaneo.

Supongamos que tiene una herramienta BurpSuite configurada para escanear cinco repositorios distintos en busca de vulnerabilidades. Su Conector tomará nota de esta estructura organizativa y configurará **Registros** para ayudarle a traducir esos repositorios independientes a la jerarquía de Producto / Compromiso / Test de DefectDojo. Si tiene habilitado **'Auto-Map Records'**, DefectDojo aprenderá y copiará esa estructura automáticamente.

![image](images/_index.png)

Una vez configuradas las asignaciones de **Registro**, DefectDojo comenzará a importar datos de escaneo de forma periódica. Se le mantendrá al día sobre cualquier vulnerabilidad nueva detectada por la herramienta, y podrá empezar a trabajar de inmediato con las vulnerabilidades existentes usando el sistema de **Hallazgos** de DefectDojo.

Cuando esté listo para añadir más herramientas a DefectDojo, puede reorganizar fácilmente sus asignaciones de importación hacia otro destino. Se pueden configurar varias herramientas para importar vulnerabilidades al mismo destino, y siempre puede reorganizar su configuración para adaptarla mejor sin perder ningún trabajo.

## Mi Conector no es compatible

### Solicitar un conector desde la interfaz (DefectDojo Pro Cloud)

En DefectDojo Pro Cloud, puede pedirle a nuestro equipo que cree un conector para una herramienta que aún no admitimos — directamente desde la interfaz:

1. Vaya a **Conectores → Conectores ascendentes** (para herramientas que importan datos *hacia* DefectDojo). Los rastreadores de incidencias y otras integraciones salientes se pueden solicitar de la misma forma en **Conectores → Conectores descendentes**.
2. En la sección **Conectores disponibles**, haga clic en **Solicitar un conector**.
3. Complete el formulario de solicitud. El **Nombre de herramienta/producto**, la **URL base de la API de la herramienta**, el **Tipo de autenticación** y las credenciales para ese tipo de autenticación son obligatorios, porque nuestro equipo necesita una dirección accesible y una credencial funcional para crear un conector y confirmar que funciona con su herramienta. Las credenciales se almacenan de forma segura. Opcionalmente puede añadir el sitio web del proveedor, un enlace a la documentación de la API de la herramienta y una nota que describa su caso de uso.
4. Haga clic en **Enviar solicitud**. Verá una confirmación de que su solicitud fue recibida. Nuestro equipo revisa cada solicitud para evaluar si se puede construir el soporte — enviar una solicitud no garantiza que el conector se vaya a construir.

Solicitar un conector requiere permisos de **Maintainer global** y solo está disponible en **DefectDojo Pro Cloud** — la opción no aparece en instancias autoalojadas (on-premise).

### Importación manual

Incluso sin un conector, DefectDojo puede seguir gestionando la importación manual de una amplia variedad de herramientas de seguridad. Consulte nuestra [Lista de herramientas compatibles](/supported_tools), así como nuestra guía de importación de datos.

# **Próximos pasos**

* Consulte la página de **Conectores ascendentes** cambiando a la **interfaz Pro** de DefectDojo y abriendo **Conectores > Conectores ascendentes** en el encabezado **Importar**.
* Siga nuestra guía para [crear su primer Conector ascendente](../add_edit/).
* Consulte el proceso de [ejecución de operaciones](../manage_operations/) con sus herramientas de seguridad conectadas y vea cómo se pueden configurar para importar datos.
