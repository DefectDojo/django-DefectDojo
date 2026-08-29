---
title: Modelado de amenazas
description: Genere un modelo de amenazas, rutas de ataque y requisitos de seguridad
  a partir de un diseño de funcionalidad, antes de que exista el código
draft: false
audience: pro
weight: 4
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Nota: Threat Modeling es una función exclusiva de DefectDojo Pro y actualmente está en fase BETA.</span>

**Threat Modeling** convierte un diseño de funcionalidad en un modelo de amenazas revisado. Usted proporciona el diseño — texto pegado, un documento de diseño y, opcionalmente, un diagrama de arquitectura — y DefectDojo genera los componentes y flujos de datos que describe, las amenazas contra ellos, y los requisitos de seguridad que mitigan esas amenazas. Los requisitos luego pueden enviarse a DefectDojo como hallazgos, de modo que el trabajo en etapa de diseño fluye por la misma maquinaria de triaje, SLA, Jira e informes que todo lo demás.

Esta es la capacidad **pre-code** de Sensei. Mientras que [escanear y corregir](/sensei/about_sensei/) funciona sobre un repositorio que ya existe, el modelado de amenazas funciona sobre el diseño, antes de que haya código que escanear.

> **🔎 BETA:** Threat Modeling está en desarrollo activo y aparece etiquetado como **BETA** en toda la interfaz. El comportamiento y las pantallas pueden cambiar entre versiones. Durante la fase BETA se habilita por instancia desde DefectDojo — contacte a su representante de DefectDojo para activarlo.

> **📍 Dónde encontrarlo:** abra **Threat Modeling** desde la navegación izquierda, justo debajo de Sensei.

## Qué necesita

- La función con licencia **Sensei**. El modelado de amenazas se distribuye bajo el mismo derecho de uso que escanear y corregir.
- Un rol global de **Maintainer** o **Owner**. Los usuarios que no lo tengan no verán la página.
- Un producto al cual vincular el modelo de amenazas. Las instancias que usan la nomenclatura 3.0 ven los productos llamados **assets**; esta página dice *producto* en todo momento, y la interfaz sigue la nomenclatura que tenga configurada su instancia.

No se instala nada ni se conecta ningún repositorio. El modelado de amenazas solo lee el diseño que usted proporciona.

## Generar un modelo de amenazas

Elija **New threat model**, seleccione el producto, asígnele un nombre y proporcione el diseño en el formato que tenga disponible:

- **Paste the description** directamente, o
- **Upload a design document** — `.md`, `.markdown`, `.txt`, `.text` o `.pdf`. La extracción de texto desde PDF es best-effort; si un PDF es mayormente imágenes, pegue el texto en su lugar.
- **Optionally add an architecture diagram** — PNG, JPEG, WebP o GIF. El diagrama se lee junto con el texto, por lo que un componente que solo aparece en la imagen igualmente se detecta.

Puede combinarlos: un resumen breve pegado junto con un diagrama suele producir un mejor modelo que cualquiera de los dos por separado.

La generación se ejecuta en segundo plano y atraviesa cuatro etapas, que se muestran en la ejecución a medida que avanza:

1. **Extracting architecture** — componentes, límites de confianza, activos de datos y flujos de datos.
2. **Enumerating threats** — amenazas por categoría STRIDE.
3. **Writing security requirements** — requisitos verificables, cada uno vinculado a las amenazas que mitiga.
4. **Assembling results** — el diagrama y las verificaciones finales de consistencia.

Una ejecución normalmente tarda varios minutos. Puede salir de la página; el progreso y los resultados se conservan en la ejecución.

## Leer los resultados

### Arquitectura

La pestaña **Architecture** representa lo extraído como un diagrama de flujo de datos: componentes agrupados por límite de confianza, con flujos etiquetados por protocolo. Los flujos que **cruzan un límite de confianza** se dibujan de forma diferente, porque son los más interesantes. Al seleccionar un componente se muestran las amenazas que lo afectan.

El modelo también registra lo que **no** pudo determinar: supuestos que tuvo que asumir y puntos que resultaron poco claros en el diseño. Lea esto primero: le indica dónde el propio diseño es ambiguo, lo cual suele ser el resultado más útil del ejercicio.

### Amenazas

Cada amenaza incluye:

- Su **categoría STRIDE** (suplantación de identidad, alteración, repudio, divulgación de información, denegación de servicio, elevación de privilegios) y una **severidad**.
- El **perfil del atacante** — por ejemplo, un atacante externo no autenticado, alguien interno, o un compromiso de la cadena de suministro — y la habilidad requerida.
- Una **ruta de ataque** ordenada: los pasos que seguiría un atacante, con sus prerrequisitos.
- Un **CWE**, cuando corresponde, tomado de una lista fija en lugar de inventado.
- Los **componentes, flujos y activos de datos** que afecta.

### Requisitos de seguridad

Cada requisito se redacta como una afirmación verificable, con un paso de **Verification** que describe cómo confirmar que se cumple, una categoría (authentication, authorization, input validation, cryptography, etc.) y una prioridad. Todo requisito indica las amenazas que mitiga.

La cobertura se contabiliza de forma explícita: una amenaza está mitigada por al menos un requisito, o bien aparece listada como una **brecha de cobertura**. Las brechas se muestran en lugar de ocultarse, de modo que ninguna amenaza se descarta silenciosamente.

## Evidencia, y en qué confiar

Todo componente, amenaza y requisito lleva la **evidencia** de la que proviene, y la evidencia se etiqueta según su origen:

- **Del texto del diseño** — una cita que se verificó, palabra por palabra, contra el texto que usted proporcionó.
- **Del diagrama** — leído a partir de la imagen, por lo que no hay texto que citar.
- **Inferido** — no indicado en el diseño en absoluto.

Una cita que no pudo verificarse contra el texto proporcionado se conserva, pero se **marca como no verificada**, mostrando la cita reclamada para que usted mismo la evalúe. Los elementos se marcan en lugar de eliminarse, porque una amenaza descartada silenciosamente es un riesgo del que nadie se entera. Los elementos estructuralmente inválidos — una amenaza que hace referencia a un componente que nunca se extrajo — se descartan, y la cantidad de elementos descartados queda registrada en la ejecución.

**Trate el resultado como un borrador para revisión, no como un producto terminado.** Se genera a partir de un documento de diseño mediante un modelo de lenguaje; las etiquetas de evidencia existen para que pueda ver qué partes están fundamentadas en lo que usted escribió y cuáles son inferencia.

## Convertir requisitos en hallazgos

Los requisitos se vuelven accionables mediante **Push to findings**. Seleccione los requisitos que desee y DefectDojo crea un hallazgo por requisito, en un compromiso dedicado llamado **Sensei Threat Modeling** en ese producto, con un Test por versión del modelo de amenazas.

Cada hallazgo incluye:

- El enunciado del requisito, además de la narrativa de cada amenaza que mitiga — categoría STRIDE, atacante y la ruta de ataque numerada — para que quien tome el ticket tenga el contexto sin necesidad de abrir el modelo de amenazas.
- El paso de verificación como mitigación.
- La severidad y el CWE del requisito.
- La etiqueta `sensei-threat-model`, una etiqueta `tm-v<version>` y una etiqueta STRIDE.

Los hallazgos se crean **activos pero no verificados**: un requisito generado es una propuesta para que una persona la confirme.

Enviar (push) es **idempotente**. Cada requisito es dueño de su hallazgo, por lo que volver a enviar el mismo modelo actualiza en el lugar en vez de crear duplicados; y si edita un requisito y vuelve a enviarlo, el hallazgo se actualiza en consecuencia. Volver a enviar no reescribe quién generó el hallazgo originalmente.

## Versiones y sustitución

Los modelos de amenazas se **versionan por producto**. Regenerar a partir de un diseño actualizado crea una nueva versión en lugar de sobrescribir la anterior, de modo que conserva el historial de cómo era el diseño cuando se tomó una decisión.

Cuando envía una versión más reciente, los hallazgos de la versión anterior que ya no corresponden a un requisito vigente se marcan como **mitigados** en lugar de dejarse abiertos, de modo que el compromiso refleje el diseño actual.

## Exportar

Un modelo de amenazas se puede descargar como **Markdown** para una revisión de diseño o un ticket, o como **JSON** para cualquier uso programático. Ambas opciones están disponibles desde el propio modelo de amenazas.

## Actividad de generación

La pestaña **Activity** enumera cada generación, su estado y la etapa que alcanzó. Las ejecuciones en curso se pueden **cancelar**. Una ejecución fallida muestra **por qué** falló — un problema de configuración, una entrada demasiado extensa o un error temporal del servicio — y las etapas completadas quedan guardadas como checkpoint, de modo que al reintentar se retoma en lugar de empezar desde el principio.

## Costos

El modelado de amenazas llama a un modelo de lenguaje de gran tamaño, y cada generación tiene un costo. Una generación realiza aproximadamente ocho llamadas, y el uso se registra por ejecución junto con el resto del uso de LLM de Sensei, de modo que puede ver cuánto costó producir un modelo. Cancelar una ejecución detiene las llamadas restantes en el siguiente límite de etapa.
