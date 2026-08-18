---
title: Guía de actualización de DefectDojo Pro
description: Actualice una versión existente de DefectDojo Pro Helm, incluyendo la
  extracción del chart, la ejecución de la actualización y la reversión
draft: false
weight: 14
audience: pro
aliases:
- /es/get_started/pro/onprem/upgrading/
---

<!--
  Generado a partir del repositorio del chart de Helm de DefectDojo Pro.
  Fuente: docs/UPGRADE_GUIDE.md en la versión de chart 3.1.304.
  Edite la guía de origen, no este archivo. Las ediciones locales se sobrescriben
  la próxima vez que se publique el chart.
-->
Este documento cubre la actualización de una versión existente de DefectDojo Pro a una versión de chart más reciente.
La ruta recomendada es extraer el chart directamente desde el registro OCI de
DefectDojo — no se requiere extraer ningún zip. El flujo de trabajo con el zip empaquetado usado en el momento de la instalación
también funciona para actualizaciones y se documenta a continuación.

Esta guía cubre:

- [Antes de actualizar](#before-you-upgrade)
- [Origen del chart: registro OCI](#chart-source-oci-registry)
- [Autenticarse en el registro](#authenticate-to-the-registry)
- [Actualizar mediante el registro OCI (recomendado)](#upgrade-via-oci-registry-recommended)
- [Actualizar mediante el zip extraído](#upgrade-via-extracted-zip)
- [Actualizar con ArgoCD](#upgrade-with-argocd)
- [Verificar la actualización](#verify-the-upgrade)
- [Reversión](#rollback)
- [Solución de problemas](#troubleshooting)

---

## Qué cubre una actualización

Una versión de DefectDojo Pro es una versión de chart, un conjunto de
versiones de imágenes de contenedor y los archivos de configuración de Pro. Estos se compilan y prueban juntos y
deben avanzar juntos. Actualizar las etiquetas de imagen por sí solas no es compatible
y romperá la implementación.

Lo mismo se aplica a la configuración. Con casi cada versión se distribuye un nuevo `pro_settings.py`.
Nunca traslade una copia de una actualización a otra, y nunca aplique parches manuales a una
versión anterior: la aplicación debe ejecutar el `pro_settings.py` que corresponde a su
versión. Sus propias personalizaciones van en `local_settings.py`, que se
preserva entre actualizaciones y es el único de los dos archivos que debe editar.

Usar el chart se encarga de esto por usted. Distribuye y monta el `pro_settings.py`
correspondiente junto con su `local_settings.py`, de modo que no hay nada que
copiar ni migrar manualmente.

## Antes de actualizar

Toda actualización debe comenzar de la misma manera. Omitir estos pasos es la causa
más común de actualizaciones fallidas.

1. **Lea las notas de la versión** de cada versión entre su versión actual
   y la de destino. Los cambios incompatibles, los nuevos campos obligatorios y los
   requisitos previos de migración se indican allí. La página de la versión en GitHub de cada etiqueta
   enlaza al registro de cambios.
2. **Verifique la versión actual de su chart.** Este es el punto de partida para la actualización:

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **Haga una copia de seguridad de su base de datos.** Las actualizaciones del chart pueden incluir migraciones de Django
   que modifican el esquema. Realice un volcado lógico (o una instantánea a nivel de almacenamiento) de
   la instancia de PostgreSQL antes de continuar.
4. **Tenga disponibles sus archivos de valores.** El comando de actualización debe pasar el
   mismo preset de plataforma, preset de perfil y archivo de valores del cliente usados en la
   instalación. Los archivos de valores faltantes o desactualizados provocan diferencias inesperadas.
5. **Confirme que las referencias a secretos aún existen.** Si instaló con
   `--set dojo.existingSecret=...` o `--set license.existingSecret=...`,
   verifique que esos secretos de Kubernetes sigan presentes en el namespace.
6. **Renderice primero la actualización localmente** para detectar campos faltantes, valores
   inválidos o errores de plantilla antes de tocar el clúster:

   ```bash
   helm template dojopro $CHART_REF \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/<size>.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     > /tmp/dojopro-upgrade-render.yaml
   ```

   `$CHART_REF` es la referencia OCI (ver más abajo) o la ruta del chart extraído.

> Configure `NAMESPACE` una vez — todos los comandos de esta guía usan `$NAMESPACE`:
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **El valor predeterminado de la política de red cambió.** Las NetworkPolicies ahora se rigen por
> `networkPolicy.profile`, cuyo valor predeterminado es `standard`: se permite todo el tráfico de salida más
> el tráfico de entrada entre los propios pods de esta versión (el tráfico de entrada externo sigue
> restringido a la ruta de ingress). Esto es más permisivo que la anterior lista de permitidos de salida
> siempre granular. Para mantener el comportamiento restringido, configure
> `networkPolicy.profile: aggressive` y revise las excepciones
> (`nodeLocalDns`, `dnsSelectors`, `externalAPIs`) — consulte
> [Políticas de red](/get_started/pro/onprem/installing_on_kubernetes/#network-policies).

> **Requisito de base de datos del orquestador.** El orquestador (`ddorch`) usa una
> segunda base de datos llamada `<main-db-name>-ddorch` y la crea al iniciar si
> no existe. Si su rol de aplicación carece de `CREATEDB`, créela previamente
> (`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`) antes de actualizar
> a una versión de chart que habilite ddorch — de lo contrario, el pod de ddorch fallará con
> `permission denied to create database (SQLSTATE 42501)`. Consulte
> [Pre-flight: base de datos del orquestador (ddorch)](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

> **Valor predeterminado del reetiquetado de Organization/Asset.** `dojo.V3EnableOrganizationAssetRelabel`
> ahora tiene como valor predeterminado `null` (automático): está **habilitado para instalaciones nuevas** y **desactivado
> en actualizaciones**, de modo que el reetiquetado de la UI (Organization/Asset en lugar de
> ProductType/Product) nunca se activa inesperadamente en una versión existente. Para
> habilitarlo en una versión ya actualizada, configure `dojo.V3EnableOrganizationAssetRelabel: true`
> explícitamente; un valor explícito `true`/`false` siempre prevalece sobre el valor automático predeterminado.

---

## Origen del chart: registro OCI

El chart se publica en el DefectDojo GCP Artifact Registry como un artefacto
OCI:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Cada versión está etiquetada con la versión del chart (por ejemplo, `2.57.2`). La
versión del chart coincide con la versión de la aplicación en `Chart.yaml`, de modo que la etiqueta que pasa
a `helm upgrade --version` es el mismo número de versión que se muestra en la versión
de GitHub.

Listar las versiones de chart disponibles:

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **¿Por qué OCI para las actualizaciones?** Los presets (`presets/platforms/*.yaml`,
> `presets/profiles/*.yaml`) vienen empaquetados dentro del chart. Al hacer referencia al
> chart por su URL OCI se extraen automáticamente las versiones de preset correctas para el
> chart de destino — sin paso de reextracción, sin presets desactualizados.

---

## Autenticarse en el registro

El registro es privado. Helm debe iniciar sesión antes de poder extraer el
chart. Use una clave de cuenta de servicio de GCP o un token de acceso de corta duración
proporcionado por el soporte de DefectDojo.

**Opción A — clave JSON de cuenta de servicio:**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**Opción B — inicio de sesión interactivo con gcloud (para personas con acceso al registro):**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

Los tokens de acceso de `gcloud auth print-access-token` expiran después de una hora.
Vuelva a ejecutar `helm registry login` si ve un `401 Unauthorized` durante la
actualización.

> **Entornos aislados (air-gapped) o con firewall:** si los nodos de su clúster pueden alcanzar
> `us-south1-docker.pkg.dev` pero su estación de trabajo no puede, use el
> flujo de trabajo con zip extraído descrito más abajo. El flujo de trabajo OCI solo funciona cuando el host
> que ejecuta `helm upgrade` puede alcanzar el registro.

---

## Actualizar mediante el registro OCI (recomendado)

Apunte `helm upgrade` directamente a la URL OCI y fije la versión del chart con
`--version`. Todos los archivos de valores, indicadores `--set` e indicadores `--set-file` son los
mismos que en la instalación original.

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Las rutas de los presets de plataforma y de perfil anteriores son `presets/platforms/...`
> (sin el prefijo `$CHART/`). Cuando Helm extrae un chart desde OCI, los presets viven
> dentro del chart extraído, pero aquí `-f` apunta a **copias locales** de esos
> archivos. Si no mantiene copias locales de los presets, extraiga primero el chart
> con `helm pull oci://... --version $VERSION --untar` y referéncielos
> desde el directorio extraído — o use el flujo de trabajo con zip extraído.

**Variante con secretos en línea + archivo de licencia:**

```bash
helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Fije siempre `--version`. Omitirlo extrae la etiqueta a la que el registro
> resuelva en el momento del comando — no es repetible ni
> auditable. Fije la versión para que las reejecuciones, las reversiones y la respuesta a incidentes
> hagan referencia siempre al mismo artefacto.

---

## Actualizar mediante el zip extraído

Para estaciones de trabajo que no pueden alcanzar el registro OCI, o para clientes que
prefieren dejar el chart preparado como un archivo local, el zip empaquetado de la versión
de GitHub funciona de la misma manera en el momento de actualizar que en el momento de instalar. La
única diferencia respecto a la instalación es el verbo del comando (`helm upgrade` en lugar de
`helm install`).

1. Descargue `dojo-pro-helm-bundled-<version>.zip` (y la firma
   separada `.asc`) desde la versión de GitHub.
2. Verifique la firma usando la clave pública
   (`dojo-pro-release-signing.asc`) según se documenta en la guía de instalación.
3. Extraiga el chart a una **ruta con versión** para que los presets no choquen con
   extracciones anteriores:

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. Ejecute la actualización usando la ruta del chart extraído — los mismos archivos de valores e
   indicadores que su instalación original:

   ```bash
   helm upgrade dojopro $CHART \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/standard.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     --set-file ddorch.tls.rootCa=orch_ca.crt \
     --set-file ddorch.tls.cert=orch_server.crt \
     --set-file ddorch.tls.key=orch_server.key \
     --wait --timeout 15m
   ```

> **Vuelva a extraer en cada actualización.** Los archivos de preset evolucionan entre
> versiones de chart. Reutilizar una extracción antigua fija silenciosamente su actualización a los
> valores de preset antiguos.

---

## Actualizar con ArgoCD

Cuando DefectDojo Pro se gestiona con ArgoCD, actualizar es un único cambio en
`targetRevision` dentro de la especificación de la Application. Los presets de plataforma y de perfil
están versionados dentro del chart, por lo que se actualizan de forma sincronizada.

```yaml
spec:
  source:
    repoURL: us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2
    chart: dojopro
    targetRevision: <chart-version>    # bump this
    helm:
      valueFiles:
        - presets/platforms/aws-eks.yaml
        - presets/profiles/standard.yaml
      values: |
        # your environment-specific values
      parameters:
        - name: dojo.existingSecret
          value: dojopro-secrets
        - name: license.existingSecret
          value: dojopro-license
```

Sincronice la Application después de editar `targetRevision`. ArgoCD extraerá el
nuevo chart desde el registro OCI y reconciliará.

> ArgoCD necesita sus propias credenciales para el registro OCI. Configure el secreto
> del repo con `type: helm` y `enableOCI: "true"`. Consulte la
> [documentación de Helm OCI de ArgoCD](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support)
> para conocer la forma exacta del Secret.

---

## Verificar la actualización

Después de que `helm upgrade` finalice (o ArgoCD reporte Synced / Healthy), confirme
que la nueva revisión está activa:

```bash
# Chart revision bumped and status is deployed
helm list -n $NAMESPACE

# All pods Running and Ready — expect django, celery worker/beat,
# connectors, ddorch, ddorch-workers, and (if enabled) mcp-server
kubectl get pods -n $NAMESPACE

# Migrations succeeded — the initializer job should show Completed
kubectl get jobs -n $NAMESPACE

# App version matches the target
kubectl get deployment -n $NAMESPACE \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

Acceda a la página de inicio de sesión para confirmar que la UI se carga y que el usuario administrador puede
autenticarse. Para comprobaciones programáticas, el endpoint `/login/` devuelve 200
cuando la aplicación está en buen estado.

---

## Reversión

Helm conserva el historial de versiones por revisión. Si la actualización provoca una regresión
en el comportamiento, revierta a la revisión anterior:

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **Las migraciones de base de datos no se revierten.** El rollback de Helm restaura el
> estado del manifiesto (imágenes, configuraciones, secretos) pero no ejecuta
> `migrate --revert`. Si la actualización aplicó una migración de esquema que necesita
> revertir, restaure desde la copia de seguridad realizada en
> [Antes de actualizar](#before-you-upgrade) o coordine una reversión manual de la
> migración con el soporte de DefectDojo antes de revertir la
> versión de Helm.

Los usuarios de ArgoCD pueden revertir deshaciendo el cambio de `targetRevision` en
git (o mediante `argocd app rollback`) y sincronizando.

---

## Solución de problemas

**`401 Unauthorized` al extraer el chart.**
El token de acceso ha expirado. Vuelva a ejecutar `helm registry login` con un
`gcloud auth print-access-token` nuevo.

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`.**
Un selector u otro campo inmutable cambió. El chart fija etiquetas de selector
estables, por lo que esto normalmente significa una edición previa in situ de un
Deployment. Capture el diff, elimine el recurso problemático y vuelva a ejecutar
la actualización para que Helm lo vuelva a crear.

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`.**
Helm 4 usa server-side apply, que rastrea la propiedad de los campos. Este error
significa que otro gestor — `kubectl edit`, `kubectl scale`, o el controlador de HPA
(`kube-controller-manager`) — cambió un campo que Helm renderiza,
más comúnmente `.spec.replicas`. Recupere la propiedad una vez:

```bash
helm upgrade ... --force-conflicts
```

Las versiones de chart con esta corrección omiten `replicas` en los Deployments cuyo HPA
está habilitado, de modo que el escalado del HPA ya no entra en conflicto con las actualizaciones. Si
escaló manualmente un Deployment con `kubectl`, prefiera ajustar el
valor correspondiente de `replicas`/`horizontalpodautoscaler` en su lugar, para que el
chart siga siendo el propietario.

**`Error: UPGRADE FAILED: timed out waiting for the condition`.**
Los pods no alcanzaron el estado Ready dentro de la ventana de `--timeout`. Inspeccione la
carga de trabajo rezagada:

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

Causas comunes: fallos al extraer la imagen (autenticación del registro), migración de esquema
aún en curso (aumente `--timeout`), o sondas de disponibilidad (readiness) que fallan contra un
FQDN mal configurado.

**El preset cambió entre versiones y ahora mi archivo de valores entra en conflicto.**
Vuelva a renderizar con `helm template` (consulte [Antes de actualizar](#before-you-upgrade))
y reconcilie sus anulaciones con los nuevos valores predeterminados del preset antes de
ejecutar `helm upgrade`.

**`values don't meet the specifications of the schema ... got string, want boolean`.**
Un valor de activación/desactivación en su anulación está entre comillas. Helm trata `"false"` como una
cadena no vacía, y una cadena no vacía es verdadera (truthy), por lo que la función se
activaba cuando su intención era desactivarla. El esquema ahora rechaza
la forma entre comillas en lugar de dejarla pasar. Quite las comillas:

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

El mensaje de error indica la ruta problemática. `false`, `no` y `off` sin comillas
se interpretan todos como un booleano real y se aceptan.
