---
title: "Compartir telemetría de sensores"
description: "Acepte compartir con DefectDojo eventos anonimizados de detecciones de sensores y vea lo que aportaron sus sensores"
weight: 11
audience: pro
draft: false
---

> **Todavía no está disponible:** Compartir telemetría de sensores todavía no se puede activar, ni en DefectDojo Cloud ni en una instancia autoalojada, sea cual sea su configuración. Esta página describe cómo funcionará una vez publicada.

Compartir telemetría de sensores permite que una instancia envíe **eventos de detección de sensores** anonimizados al servicio de inteligencia de amenazas de DefectDojo. Una detección es un único hallazgo de un sensor en sus hosts que está vinculado a un CVE. Las detecciones compartidas indican al servicio de inteligencia qué vulnerabilidades se están explotando en el mundo real, y esa evidencia llega a todas las instancias a través del feed de Inteligencia de amenazas.

Compartir es una función de **DefectDojo Pro**. Está **desactivada de forma predeterminada** y no se envía nada hasta que un superusuario la activa.

## Qué se comparte y qué no

Cada evento contiene cuatro valores y nada más:

| Campo | Qué es |
| --- | --- |
| CVE | El CVE con el que está etiquetada la regla de detección que coincidió |
| Hora | La hora en que se vio la detección, en UTC. No se envían minutos ni segundos |
| Origen | Como máximo, el país y la red (ASN) de donde vino la detección. A menudo está vacío |
| ID de contribuyente | Un identificador aleatorio que cambia cada mes natural |

Un evento nunca contiene una carga útil ni el cuerpo de una solicitud, un nombre de host, una dirección IP, un nombre de usuario, una línea de comandos, un nombre de activo, un nombre de empresa, el nombre o el identificador de la regla de detección, ni el nombre o la URL de su instancia. El origen solo se rellena cuando su instancia está configurada para buscarlo, y solo para una dirección pública. En ese caso, DefectDojo determina el país y la red en su instancia y descarta allí la dirección, antes de enviar nada.

Los identificadores de reglas se omiten a propósito: una regla escrita por usted puede llevar cualquier nombre, incluido el de su empresa, el de un host o el de una persona.

Los eventos se entregan a DefectDojo con la clave de licencia de su instancia, que es la forma en que el servicio de inteligencia los acepta. La clave viaja con la entrega, no dentro de los eventos.

El ID de contribuyente permite al servicio de inteligencia contar cuántas instancias distintas vieron un CVE dentro de un mes. Se genera al azar, se sustituye por uno nuevo cada mes, y el anterior no se puede deducir a partir del nuevo.

Solo se envían las detecciones posteriores a la activación y de las últimas 24 horas. Desactivar el uso compartido elimina todos los eventos que aún esperaban su envío y descarta el ID de contribuyente, y lo mismo ocurre con un cambio de la cláusula contractual. Volver a activarlo empieza con un ID de contribuyente nuevo.

## Antes de poder activarlo

El uso compartido está cubierto por una cláusula de su contrato con DefectDojo. La tarjeta indica la **versión de la cláusula contractual** que usted acepta al activarlo, y no se puede activar hasta que esa versión esté disponible en su instancia.

La cláusula contractual se publicará antes de que el uso compartido esté disponible.

Si DefectDojo publica más adelante una nueva versión de la cláusula, el uso compartido se pausa por sí solo. La tarjeta lo indica, los eventos que esperaban con la versión anterior se eliminan y no se envía nada hasta que un superusuario vuelva a activarlo con la nueva versión. Mientras está en pausa, la casilla aparece desmarcada, de modo que la nueva versión solo se acepta al volver a marcarla. El uso compartido empieza entonces de cero, con un ID de contribuyente nuevo.

El uso compartido nunca está disponible en una instancia air-gapped, en la demo pública ni en el sandbox.

## Activar o desactivar el uso compartido

1. Inicie sesión como superusuario y abra **Settings > System Settings**.
2. Desplácese hasta la tarjeta **Sensor Telemetry**, al final de la página.
3. Lea qué se comparte y la versión de la cláusula contractual que indica la tarjeta. Cuando su instancia tiene la dirección de la cláusula, la tarjeta la enlaza junto a la versión (**Read the contract term**).
4. Marque **Share Sensor Hit Events** y después seleccione **Submit**. Para dejar de compartir, desmarque la casilla y seleccione **Submit**.

Cada cambio queda registrado en el registro de auditoría con el usuario que lo hizo.

## Qué muestra la tarjeta

* **Sharing**: Off, On, Paused (la cláusula contractual cambió), On, Not Sending (no hay un endpoint de inteligencia o una clave de licencia configurados; la tarjeta indica cuál falta) o Not Available.
* **Events Shared**, **Events Waiting** y **Events Dropped**: cuántos eventos se entregaron, están en cola o se descartaron. Un evento que no se puede entregar se reintenta durante un día como máximo y luego se descarta.
* **Last Shared**: cuándo se entregaron eventos por última vez.
* **La lista de CVE**: los CVE que observaron sus sensores, hasta los 200 vistos más recientemente, con el número de detecciones, cuántas se compartieron y cuándo se vio cada uno por primera y por última vez. El título de la tarjeta muestra cuántos CVE se observaron en total. Esta lista se conserva en su instancia tanto si el uso compartido está activado como si no.
* **Seen Elsewhere**: si otras instancias que comparten vieron el mismo CVE. Solo se rellena mientras el uso compartido está activado y el servicio de inteligencia responde, y solo para los CVE que su instancia ya compartió: la consulta nombra el CVE, por lo que nunca se pregunta por un CVE visto solo antes de la activación. En caso contrario, la línea bajo la tabla explica por qué está vacía, por ejemplo, que la instancia no tiene configurado un endpoint de inteligencia o una clave de licencia.

La tarjeta aparece cuando su instancia tiene sensores, ha observado un CVE o se ha configurado para compartir.

## Configuración autoalojada

En una instancia autoalojada, el operador define estas variables de entorno. Todas están vacías de forma predeterminada, y vacía significa desactivada.

| Variable | Propósito |
| --- | --- |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_VERSION` | La versión de la cláusula contractual. Sin ella, el uso compartido no se puede activar |
| `DD_SENSOR_TELEMETRY_CONTRACT_TERM_URL` | Opcional. La dirección HTTPS donde se puede leer la cláusula contractual. La tarjeta la enlaza junto a la versión |
| `DD_SENSOR_TELEMETRY_ENDPOINT` | La URL base HTTPS del servicio de inteligencia. Sin ella, nunca se realiza ninguna llamada de red |
| `DD_THREAT_INTEL_LICENSE_KEY` | La clave de licencia que se envía con cada entrega. Sin ella, no se realiza ninguna llamada de red |
| `DD_SENSOR_TELEMETRY_SOURCE_RESOLVER` | Opcional. La ruta de Python con puntos de una función que convierte una dirección de origen pública en un país y un ASN. DefectDojo no incluye ninguna base de datos de países ni de ASN, así que sin ella los eventos no llevan origen |
