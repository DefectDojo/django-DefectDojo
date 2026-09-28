---
title: Feature Flags
description: Active y desactive funciones opcionales de DefectDojo Pro desde la interfaz
  de DefectDojo
weight: 1
audience: pro
---

Feature Flags le permite activar y desactivar funciones opcionales de DefectDojo Pro para su propia instancia — funciones que antes solo podían habilitarse contactando con el equipo de soporte de DefectDojo ahora se pueden autogestionar desde la interfaz.

La página de Feature Flags solo es visible para **superusuarios**. El resto de usuarios, incluidos los Propietarios globales, no la ven.

## Cómo abrir la página de Feature Flags

Vaya a **Settings > Feature Flags** en la barra lateral izquierda.

La página enumera todas las funciones opcionales con:

* **Name** — la función, con una etiqueta **BETA** cuando aún está en fase beta
* **Description** — qué hace la función
* **Documentation link** — dónde existe documentación para esa función
* **Toggle** — si la función está actualmente activada

Use el cuadro de búsqueda para filtrar la lista por nombre o descripción de la función.

### Funciones que no aparecen en la lista

La página enumera las funciones que usted puede optar por adoptar. Hay dos tipos de función que están ausentes de ella.

**Siempre activas.** Cuando una función alcanza la disponibilidad general, queda activada para todas las instancias y deja de aparecer en la lista, porque ya no hay ninguna decisión que tomar:

* **Downstream Connectors** — consulte [Downstream Connectors](/connectors/downstream/about/)
* **Universal Parser** — consulte [Universal Parser](/import_data/pro/specialized_import/universal_parser/)
* **Asset Hierarchy** — consulte [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/)
* **Appearance** y **Feature Flags** — las dos páginas de Settings con ese mismo nombre

Nada cambia para su instancia si ya tenía una de estas funciones activada. Si la tenía desactivada, ahora está activa: estas funciones forman parte de DefectDojo Pro en lugar de ser opcionales. Contacte con [DefectDojo Support](mailto:support@defectdojo.com) si esto supone un problema para su instancia.

**Habilitadas por DefectDojo a solicitud.** Algunas funciones dependen de infraestructura que se aprovisiona por instancia, por lo que las activa DefectDojo en lugar de hacerlo desde esta página:

* **Scheduling Service** — consulte [Scheduling Rules](/automation/rules_engine/scheduling/)

Contacte con [DefectDojo Support](mailto:support@defectdojo.com) para que se le habilite alguna de estas funciones. Si ya está activa en su instancia, permanece activa.

## Activar o desactivar una función

1. Busque la función en la lista.
2. Haga clic en su interruptor.
3. El cambio surte efecto de inmediato. Los demás usuarios lo verán reflejado en su siguiente carga de página.

Algunas funciones muestran un cuadro de diálogo de confirmación antes de aplicar el cambio. Esto ocurre al habilitar una función que conlleva una advertencia (por ejemplo, una que requiere un reinicio o que puede afectar a datos existentes), o una que no se puede volver a desactivar.

Desactivar una función normalmente es simplemente el proceso inverso de activarla. Las excepciones se indican en [Cuándo un interruptor está bloqueado](#when-a-toggle-is-locked).

### Organization / Asset Relabeling

**Organization / Asset Relabeling** cambia el nombre de "Product Type" a "Organization" y de "Product" a "Asset". Está activada de forma predeterminada y se activa o desactiva desde esta página como cualquier otra función, pero conviene saber qué partes de DefectDojo gobierna:

* La **Pro UI** sigue este interruptor. Las nuevas etiquetas aparecen en su siguiente carga de página.
* Las páginas de la **Classic UI**, sus URL y los informes generados toman su nomenclatura de la configuración de despliegue `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL` (también activada de forma predeterminada), que se lee cuando DefectDojo se inicia. Este interruptor no las modifica, y reiniciar tampoco hace que las modifique.

El interruptor almacenado se inicializó a partir de esa configuración de despliegue, de modo que ambos coinciden hasta que usted cambie uno de ellos. Si desactiva el cambio de nombre aquí y además usa la Classic UI, establezca `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL=False` en su despliegue y reinicie para que ambas superficies coincidan. En [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), contacte con [DefectDojo Support](mailto:support@defectdojo.com) para que se le cambie la configuración de despliegue.

Por este motivo, la función lleva una etiqueta **Restart Recommended** en la página de Feature Flags: la nomenclatura usada fuera de la Pro UI queda fijada cuando arranca el proceso. El cambio de nombre es cosmético en cualquier caso. Los modelos de base de datos, los nombres de campo y los endpoints de la API no cambian, por lo que la automatización existente sigue funcionando. Consulte [Asset Hierarchy](/asset_modelling/pro_hierarchy/asset_hierarchy/).

## Cuándo un interruptor está bloqueado

Una función que usted no puede cambiar se muestra con una insignia de candado que explica el motivo:

| Badge | What it means | What to do |
| --- | --- | --- |
| **Managed by DefectDojo** | DefectDojo ha configurado esta función de forma centralizada para su instancia. Su configuración no puede anularla. | Contacte con [DefectDojo Support](mailto:support@defectdojo.com) si necesita que se cambie. |
| **Unavailable on This Deployment** | La función no se ofrece en su tipo de instalación. Consulte [Disponibilidad de funciones](#feature-availability) más abajo. | Nada. La función no es aplicable a su instancia. |
| **Cannot Be Disabled** | La función ya está activada y es de un solo sentido. No existe ningún mecanismo para revertirla. | Nada. Esto es lo esperado. |
| **Managed by deployment** | La función está controlada por su configuración de despliegue en lugar de por esta página. | Consulte [DefectDojo Pro (On-Premise)](#defectdojo-pro-on-premise) más abajo. |

## DefectDojo Pro (Cloud)

En [DefectDojo Pro (Cloud)](/get_started/pro/cloud/), **Settings > Feature Flags** es el único lugar que necesita. Active una función y quedará operativa de inmediato.

Hay dos cosas que gestiona DefectDojo en lugar de usted:

* **Managed by DefectDojo** — la función está fijada de forma centralizada. Contacte con [DefectDojo Support](mailto:support@defectdojo.com) para que se le cambie.
* **Managed by deployment** — la función forma parte de cómo se aprovisiona su instancia. Contacte también con Soporte para estos casos, ya que las instancias Cloud no exponen la configuración de despliegue a los clientes.

Las instancias Cloud también tienen acceso a funciones que no se ofrecen on-premise. Consulte [Disponibilidad de funciones](#feature-availability).

## DefectDojo Pro (On-Premise)

En [DefectDojo Pro (On-Premise)](/get_started/pro/onprem/), la mayoría de las funciones funcionan exactamente igual que en Cloud: abra **Settings > Feature Flags** y actívelas o desactívelas.

Un pequeño número de funciones se leen en cambio desde su configuración de despliegue. Estas cambian la forma en que arranca la aplicación, por lo que no se pueden alternar en tiempo de ejecución. Aparecen en la página como de solo lectura, etiquetadas como **Managed by deployment**, e indican el nombre de la variable de entorno que las controla, por ejemplo `DD_V3_FEATURE_LOCATIONS` para [Locations](/asset_modelling/locations/pro__locations_overview/).

Dado que estas funciones requieren un reinicio, y que algunas no se pueden revertir una vez habilitadas, consulte la documentación propia de la función antes de cambiar alguna. Varias de ellas es mejor habilitarlas con ayuda de [DefectDojo Support](mailto:support@defectdojo.com).

Para cambiar una de esas funciones:

1. Establezca la variable de entorno en su despliegue de DefectDojo. La página le indica qué variable establecer.
2. Reinicie DefectDojo para que el nuevo valor se lea en el arranque.
3. Vuelva a cargar la página de Feature Flags para confirmar el nuevo estado.

Dado que estos valores se leen en el arranque, no es posible cambiarlos desde la interfaz, y alternarlos en su entorno sin reiniciar no tiene ningún efecto.

Las funciones que se ofrecen solo en Cloud aparecen como **Unavailable on This Deployment** en una instancia on-premise. Esto es lo esperado y no es un problema de licencia.

## Disponibilidad de funciones

La mayoría de las funciones están disponibles en ambos tipos de instalación. Las excepciones son:

| Feature | Availability | How it is controlled |
| --- | --- | --- |
| Request a New Connector | Solo [DefectDojo Pro (Cloud)](/get_started/pro/cloud/) | Página de Feature Flags. Se muestra como **Unavailable on This Deployment** en on-premise. |
| Locations | Ambos | Página de Feature Flags. Tenga en cuenta que Locations no se puede volver a desactivar una vez habilitada. Consulte [Locations Overview](/asset_modelling/locations/pro__locations_overview/). |
| Organization / Asset Relabeling | Ambos | Página de Feature Flags para la Pro UI; la Classic UI, sus URL y los informes generados siguen la configuración de despliegue `DD_ENABLE_V3_ORGANIZATION_ASSET_RELABEL`. Consulte [arriba](#organization--asset-relabeling). |

El resto de funciones opcionales se activan directamente en la página de Feature Flags tanto en instancias Cloud como On-Premise.

## Leer los feature flags fuera de la interfaz

No es necesario abrir la página de Feature Flags para saber qué funciones están activadas — el estado de los flags también se puede leer mediante programación, lo cual resulta útil cuando la automatización necesita comprobar que una función está disponible antes de depender de ella.

```
GET /api/v2/defectdojo_information/feature_flags/
```

Esto devuelve un array JSON con un objeto por cada feature flag. Junto a `key`, `title` y `description` del flag, cada objeto informa de los valores que la automatización suele necesitar: `effective` (si la función está realmente activa para esta instancia), `default`, `application_value` (la configuración propia de la instancia, o `null` si no está definida), `editable`, y `locked_reason` cuando un flag no se puede cambiar. Los flags retirados del producto se omiten.

Cualquier usuario **autenticado** puede leerlo — no se requiere rol de superusuario. Para el esquema de respuesta exacto de su versión, consulte la documentación interactiva de la API de su instancia en `/api/v2/oa3/swagger-ui/`, que se genera a partir de la compilación en ejecución. Consulte también la [documentación de la API v2](/automation/api/api-v2-docs/).

El mismo listado de solo lectura también se publica en la superficie `/api/mcp/` de la instancia, en `/api/mcp/defectdojo_information/feature_flags/`.

Este endpoint es de **solo lectura**. Activar o desactivar una función se sigue haciendo desde la página de Feature Flags, o bien — para las funciones configuradas por despliegue mencionadas anteriormente — en su configuración de despliegue.

## Preguntas frecuentes

**No encuentro en la lista una función que busco.**
La lista muestra únicamente funciones opcionales. Las funciones que están siempre activas no aparecen. Si esperaba encontrar una función que falta, confirme que su licencia la incluye y, a continuación, contacte con [DefectDojo Support](mailto:support@defectdojo.com).

**Activé una función pero no la veo.**
Vuelva a cargar la página — las entradas de menú y las rutas se evalúan cuando la página se carga, de modo que una función recién habilitada aparece en la siguiente carga en lugar de al instante en la vista actual.

**¿Actualizar la versión cambiará mi configuración?**
No. Actualizar conserva las funciones que ha activado y las que ha desactivado.
