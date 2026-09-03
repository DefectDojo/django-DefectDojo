---
title: "Microsoft Defender"
description: "Cómo configurar el Conector Upstream de Microsoft Defender para DefectDojo"
weight: 89
audience: pro
---
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
