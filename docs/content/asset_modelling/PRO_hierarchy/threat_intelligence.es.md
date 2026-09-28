---
title: Inteligencia de amenazas
description: Evidencia de exploits y amenazas como entrada de primera clase para la
  Prioridad y el Riesgo
weight: 2
audience: pro
---

DefectDojo Pro enriquece sus hallazgos con **inteligencia de amenazas dedicada** — disponibilidad de exploits, explotación conocida y actividad de actores de amenazas — y la incorpora al cálculo de la Prioridad y el Riesgo. Esto va mucho más allá de EPSS y del indicador KEV de CISA.

## Qué obtiene

Cada hallazgo con un CVE se compara, cada noche, con un feed de inteligencia curado, construido a partir de CISA KEV, Metasploit, Exploit-DB, plantillas de Nuclei y el seguimiento de pruebas de concepto públicas. Cuando existe evidencia de exploit, el hallazgo muestra una tarjeta de **Inteligencia de amenazas**:

* una insignia de **madurez del exploit** — *Ninguna → PoC → Armado → Activo en el mundo real*
* una **puntuación de amenaza** (0–100)
* **chips de evidencia que enlazan con la fuente** — la entrada en KEV (con su fecha de inclusión),
  uso en ransomware, un módulo de Metasploit, una entrada en Exploit-DB, una plantilla de Nuclei y
  repositorios públicos de prueba de concepto
* una línea en lenguaje sencillo que explica **por qué** aumentó la prioridad del hallazgo

Más allá de la tarjeta, esta inteligencia es una superficie funcional en toda la aplicación:

* una **columna de Madurez del Exploit** en la lista de hallazgos — ordenable y filtrable
  (por ejemplo, "solo Armado o Activo")
* un widget de **"Urgente y explotado activamente"** en el panel de Diseño de Prioridad, que cuenta los
  hallazgos activos de riesgo Urgente con explotación en el mundo real — al hacer clic se abre la lista
  de hallazgos filtrada exacta
* un **evento de notificación** (`threat_intel_alert`) cuando el CVE de un hallazgo existente obtiene
  nueva evidencia de exploit, como su inclusión en CISA KEV o la aparición de un módulo de Metasploit.
  Solo se notifican mejoras — que la evidencia caduque silenciosamente nunca genera una notificación.

## Cómo cambia la puntuación

El motor de Prioridad ya combinaba la severidad, el contexto de negocio y una "puntuación externa"
construida a partir de EPSS + KEV. La inteligencia de amenazas generaliza esa puntuación externa: cada
tipo de evidencia de exploit actúa como un piso en la escala de EPSS.

| Evidencia | Piso de Prioridad (equivalente a EPSS) |
|---|---|
| Explotación activa + ransomware/actor identificado | 45% |
| En CISA KEV **y** usado en ransomware | 30% |
| En KEV o explotado en el mundo real | 20% |
| Exploit público armado (Metasploit / Exploit-DB) | 15% |
| Existe una plantilla de detección de Nuclei | 12% |
| Solo prueba de concepto pública | 8% |
| Sin evidencia de exploit | sin cambios |

La puntuación externa del hallazgo es la **mayor** entre su valor derivado de EPSS y el piso de evidencia
más alto de la tabla anterior — por lo tanto, la inteligencia solo *aumenta* una puntuación, nunca la
reduce, y un hallazgo cuyo EPSS ya supere el piso no se ve afectado. El conocido **escalar de puntuación
externa** por tipo de producto, en la configuración de su Motor de Priorización, escala esta contribución
exactamente igual que siempre escaló EPSS/KEV.

### El piso de Riesgo por explotación activa

La tabla anterior aumenta la **Prioridad**, pero de forma proporcional a la severidad base del hallazgo. Esto
tiene una consecuencia que vale la pena señalar con claridad: un hallazgo de severidad Baja que contiene un
CVE que se está explotando en el mundo real solo recibe un pequeño aumento absoluto, y podría seguir
situándose en una banda de **Riesgo** baja. La mayoría de los equipos considera que esto es incorrecto —
"explotado activamente" nunca debería quedar clasificado como Baja.

Por eso existe una segunda regla, de tipo categórico. Cuando la inteligencia de amenazas reporta
**explotación activa en el mundo real**, la Prioridad del hallazgo se eleva como mínimo al nivel de una
banda de Riesgo configurada, sin importar lo que produjera por sí solo el cálculo ponderado. Viene
configurada de forma predeterminada en **Requiere acción**; cada tipo de producto puede subirla a
Urgente, bajarla o desactivarla por completo, en la configuración del Motor de Priorización bajo *Piso de
Riesgo por Explotación Activa*.

El piso solo puede elevar — nunca hace bajar a un hallazgo, y un hallazgo que ya puntúa más alto por sí
mismo no se ve afectado. Como se aplica a la Prioridad, la banda de Riesgo y la puntuación de Riesgo se
derivan de ella automáticamente, de modo que cada lista, filtro, gráfico y cálculo de SLA ve el mismo
número coherente.

## Hallazgos sin CVE

La inteligencia de amenazas se relaciona mediante el CVE. Muchos hallazgos — la mayoría de los resultados
de SAST, secretos, configuraciones incorrectas, reglas personalizadas — no tienen CVE, y no existe
inteligencia de amenazas a nivel de instancia de vulnerabilidad para ellos en ninguna parte (esto es así
para todos los proveedores, no solo para DefectDojo). Esos hallazgos:

* conservan su Prioridad y Riesgo actuales de forma **exacta** — la función nunca reduce una puntuación
* siguen priorizándose mediante todas las demás entradas del motor (severidad, criticidad de negocio,
  exposición, etc.)
* muestran en la tarjeta "No hay inteligencia de amenazas disponible — este hallazgo no tiene un CVE con
  el que compararlo", distinto del caso de un hallazgo con CVE que simplemente aún no tiene ningún
  exploit conocido

Una consecuencia honesta de esto: en una cola mixta, a medida que los hallazgos con CVE ganan evidencia
de exploit, los hallazgos sin CVE bajan en la clasificación *relativa*, aunque su puntuación no cambie.

## Confianza y estabilidad de la puntuación

* **Inteligencia firmada.** Cada paquete nocturno está firmado criptográficamente por DefectDojo; su
  instancia rechaza los datos manipulados o sin firmar. Las instancias aisladas (air-gapped) importan el
  mismo paquete firmado con un paso de verificación fuera de línea.
* **Sin fluctuaciones de puntuación.** Las mejoras de evidencia se aplican la misma noche en que
  aparecen. Si una fuente *deja de reportar* una evidencia, las puntuaciones se mantienen estables
  durante una ventana de estabilidad (14 días de forma predeterminada) — un fallo puntual del feed nunca
  hace rebotar su cola, y las desescaladas genuinas se asientan de forma silenciosa una vez transcurrida
  la ventana.
* **Compatibilidad con entornos aislados.** El paquete diario (incluidos los datos de EPSS) puede
  transferirse e importarse fuera de línea, de modo que las instancias aisladas obtienen el mismo
  enriquecimiento.

## Implementaciones autoalojadas

Las instancias de DefectDojo Cloud no necesitan ninguna configuración. Las instancias autoalojadas
tienen tres opciones:

* **Conectado (predeterminado).** La instancia descarga el paquete firmado cada noche desde
  `intel.defectdojo.com` mediante HTTPS. Este es un destino que ninguna otra función de DefectDojo
  utiliza, por lo que normalmente hay que permitirlo de forma explícita: abra el puerto 443 saliente
  hacia ese host y, en Kubernetes, añádalo a su política de red de salida. Tenga en cuenta que la
  descarga se ejecuta en el **worker de Celery**, no en el pod web, así que la configuración del proxy
  también debe alcanzar a ese componente.
* **Réplica interna.** Apunte `DD_THREAT_INTEL_BUNDLE_URL` (y las URL correspondientes de digest y
  firma) a una ubicación dentro de su red que usted mismo sincronice. La verificación de firma se sigue
  aplicando, por lo que una réplica no puede alterar los datos.
* **Aislado (air-gapped).** Transfiera el paquete y su firma manualmente e impórtelos con
  `manage.py load_threat_intel_bundle --file <bundle>`. La firma se verifica durante la importación.

Si la instancia no puede acceder al feed, la función falla de forma segura: la ejecución se registra
como fallida y sus puntuaciones y evidencias existentes se dejan exactamente como estaban. Nada se
degrada salvo la actualidad de la inteligencia.

## Activarla

La función viene desactivada de forma predeterminada. Los administradores pueden activarla
directamente, o ejecutarla primero en **modo sombra** — que calcula las puntuaciones hipotéticas sin
cambiar nada en el entorno activo y genera un informe de desviación que muestra exactamente qué
hallazgos se moverían — antes de activarla. Contacte con soporte o consulte el runbook de operaciones
para conocer la implementación recomendada en instancias grandes.
