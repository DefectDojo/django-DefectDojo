---
title: Direcciones IP de salida
description: Las direcciones IP de salida desde las que se conecta DefectDojo Cloud,
  para incluir en la lista de permitidos de sus firewalls externos.
weight: 5
audience: pro
---

Cuando DefectDojo Cloud se conecta con sus sistemas — los Conectores sincronizando la
API de un escáner, enviando incidencias a Jira o ServiceNow, enviando webhooks de
notificación, o entregando correo electrónico por SMTP — esas conexiones se
**inician de forma saliente** desde su entorno de DefectDojo. Si el sistema del
otro extremo está detrás de un firewall, deberá permitir las direcciones IP
salientes (egress) de DefectDojo para que esas conexiones no se bloqueen.

Esta página indica dónde encontrar esas direcciones IP de salida.

## Salida (egress) frente a entrada (ingress)

Se trata de dos cosas distintas, y esta página cubre solo la primera:

- **Salida (egress, esta página)** — las direcciones IP de origen desde las que
  se conecta DefectDojo Cloud **hacia afuera**, hacia *sus* sistemas externos.
  Incluya estas en la lista de permitidos de **sus** firewalls para que
  DefectDojo pueda llegar a los sistemas con los que se integra.
- **Entrada (ingress)** — las reglas que controlan quién puede llegar a **su**
  instancia de DefectDojo. Estas se gestionan como Reglas de Firewall en el
  Cloud Manager, no aquí. Consulte
  [Solución de problemas de conectividad](../connectivity-troubleshooting/) y el
  paso de Reglas de Firewall en
  [Configurar una instancia de Cloud adicional](../additional-cloud-instance/).

## Implementaciones multiinquilino

Las instancias Standard, Pay-as-you-go y Premium se ejecutan en clústeres
regionales compartidos de Google Kubernetes Engine (GKE). Las conexiones
salientes provienen de las direcciones IP externas de los nodos de la región en
la que se ejecuta su instancia.

El conjunto actual de IP de salida de los nodos se publica como un feed JSON,
agrupado por región:

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

El feed tiene este aspecto:

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

Para incluir en la lista de permitidos el tráfico de salida de DefectDojo:

1. Identifique la región en la que se ejecuta su instancia (la Ubicación del
   Servidor que seleccionó al aprovisionar la instancia).
2. Permita todas las direcciones IP indicadas para esa región. Cada entrada es
   un `/32` (host único).

**Esta lista cambia con el tiempo.** Se añaden y sustituyen nodos a medida que
la plataforma escala automáticamente, por lo que el conjunto de IP de salida de
una región no es fijo. Trate el feed JSON como la fuente de verdad en lugar de
copiar las direcciones una sola vez:

- Obtenga el feed mediante programación y actualice periódicamente la lista de
  permitidos de su firewall a partir de él, o
- Vuelva a consultar el feed y concilie sus reglas periódicamente.

Si su firewall no puede seguir una lista cambiante y necesita un conjunto
pequeño y estable de direcciones, hable con su representante de DefectDojo
sobre una instancia **Dedicated** (vea a continuación).

## Implementaciones de un solo inquilino (Dedicated)

Una instancia de nivel **Dedicated** se ejecuta en su propio proyecto y VPC de
GCP, y su dirección IP de salida es **estable** — se asigna cuando se
aprovisiona la instancia y no cambia a medida que la plataforma escala.

Como está vinculada a su instancia específica, la IP de salida estable no se
publica en el feed público. Póngase en contacto con
[support@defectdojo.com](mailto:support@defectdojo.com) para obtener la(s)
dirección(es) IP de salida asignada(s) a su instancia Dedicated, e inclúyalas
en la lista de permitidos de sus firewalls externos.

*¿Tiene alguna pregunta que esta página no responde? Póngase en contacto con su
representante de DefectDojo.*
