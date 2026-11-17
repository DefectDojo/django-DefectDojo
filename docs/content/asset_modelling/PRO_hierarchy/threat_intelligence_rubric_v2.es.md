---
title: "Inteligencia de amenazas: puntuación basada en evidencia (Rubric v2)"
description: "Cómo la evidencia de explotación revisada alimentará el piso de Prioridad de la inteligencia de amenazas"
weight: 3
audience: pro
---

> **Todavía no está disponible.** Esta página describe una capacidad en desarrollo. No aparece en
> la página **Feature Flags** y todavía no se puede activar, ni en DefectDojo Cloud ni en una
> instancia autoalojada. Hoy cada hallazgo se puntúa como se describe en
> [Inteligencia de amenazas](../threat_intelligence/).

La [inteligencia de amenazas](../threat_intelligence/#cómo-cambia-la-puntuación) convierte la
evidencia de exploits en un **piso** en la escala de EPSS: la puntuación externa de un hallazgo es,
como mínimo, el piso que alcanza su evidencia más fuerte. La tabla de pisos se llama **rúbrica**
(rubric). Rubric v2 es su próxima versión. Conserva el valor de cada piso y añade un tipo de
evidencia: **afirmaciones de explotación que los analistas de DefectDojo han revisado y
confirmado**.

## Qué cambia

| Evidencia | Piso de Prioridad (equivalente a EPSS) |
|---|---|
| Evidencia de explotación confirmada **y** un actor de amenazas confirmado e identificado por su nombre detrás de ella (nuevo) | 45% |
| En CISA KEV **y** usado en ransomware | 30% |
| En KEV, explotado en el mundo real o **cualquier evidencia de explotación confirmada**, incluida una observación de canary confirmada (nuevo) | 20% |
| Exploit público armado (Metasploit / Exploit-DB) | 15% |
| Existe una plantilla de detección de Nuclei | 12% |
| Solo prueba de concepto pública | 8% |
| Sin evidencia de exploit | sin cambios |

Los pisos tienen los mismos valores que hoy, y la puntuación externa del hallazgo sigue siendo la
mayor entre su valor derivado de EPSS y su piso más alto, por lo que la rúbrica solo puede aumentar
una puntuación.

En la práctica:

- **Más hallazgos alcanzan el piso de "explotación conocida".** Un CVE que no está en CISA KEV pero
  tiene evidencia de explotación revisada (un informe de incidente, un aviso del fabricante que la
  declara, una observación de honeypot o de canary) recibe el mismo piso del 20% que una entrada de
  KEV.
- **El piso más alto pasa a ser alcanzable.** Con Rubric v1, el piso del 45% requería telemetría de
  fabricantes que el feed no incluye, por lo que ningún hallazgo lo alcanzó nunca. Con Rubric v2 se
  alcanza con evidencia confirmada que tenga detrás un actor de amenazas confirmado e identificado
  por su nombre, y con nada menos.
- **Nada se debilita.** Sin evidencia revisada, una vulnerabilidad se puntúa exactamente igual que
  hoy. Una entrada de KEV con uso en ransomware se queda en el 30%: el indicador de ransomware de
  CISA no nombra a ningún actor.

Lo que **no** aumenta un piso: una afirmación sin revisar o rechazada, una prueba de concepto por sí
sola y el indicador "exploit disponible" de un escáner o de un fabricante (se muestran como hoy y no
cuentan como evidencia).

## Antes de activarla

Pasar una instancia a Rubric v2 puede aumentar la Prioridad de los hallazgos, por eso DefectDojo
mide el cambio antes de hacerlo: para cada instancia, cuántos hallazgos pasarían de qué piso a cuál
y, para cada cambio, las vulnerabilidades que hay detrás de la mayoría de los hallazgos. Sus
prioridades actuales siguen en Rubric v1 hasta que se publique Rubric v2.
