---
title: Correlación de causa raíz
description: Agrupe los Hallazgos que comparten una causa raíz -- el mismo componente
  vulnerable, CVE, recurso de infraestructura o debilidad en una URL -- para poder
  rastrear una sola corrección hasta cada Hallazgo que resuelve
weight: 1
audience: pro
---

Una biblioteca vulnerable incluida en cuarenta servicios produce cuarenta Hallazgos. Cada uno es real, cada
uno se triaja por separado, y cada uno se corrige con el mismo cambio de versión. La **correlación de causa
raíz** deja esa relación explícita: DefectDojo Pro agrupa los Hallazgos que comparten una causa raíz en una
lista clasificada de **Causas raíz**, de modo que pueda ver la única corrección y todo lo que esta resuelve.

La correlación es **aditiva y no destructiva**. Cada Hallazgo permanece visible de forma independiente,
conserva su propio estado, y se triaja exactamente igual que antes. La correlación solo agrega vínculos
entre Hallazgos, los nodos de clúster en los que se agrupan esos vínculos, y la evidencia que produjo cada
vínculo.

> **La correlación no es deduplicación.** La [Deduplicación](/triage_findings/finding_deduplication/)
> determina que dos informes describen el *mismo* Hallazgo y marca uno como duplicado. La correlación
> relaciona Hallazgos *diferentes* que resultan compartir una causa, y nunca marca nada como
> duplicado. Ambas se ejecutan de forma independiente y las dos pueden estar habilitadas a la vez.

## Activación de la correlación de causa raíz

La correlación de causa raíz está en **Beta**, depende de un feature flag y está **desactivada de forma
predeterminada**. Un superusuario puede activarla desde **Configuración > Feature Flags** tanto en
instancias Cloud como On-Premise. Consulte [Feature Flags](/admin/feature_flags/pro__feature_flags/).

Mientras el flag esté desactivado, el motor no realiza ningún trabajo: no se construyen clústeres, no se
crean vínculos y no se envía nada después de una importación.

Después de activar el flag, los Hallazgos existentes **no** se correlacionan de forma retroactiva hasta que
se vuelvan a importar o hasta que ejecute un backfill (consulte
[Backfill de Hallazgos existentes](#backfilling-existing-findings)).

## Qué se correlaciona

La correlación agrupa según cuatro señales. Tres de ellas son **exactas** -- solo se crea un vínculo cuando
dos Hallazgos realmente nombran lo mismo -- y una es una heurística etiquetada como tal.

| Tipo de causa raíz | Los Hallazgos se agrupan cuando... | Ejemplo | Coincidencia |
|---|---|---|---|
| **Componente** | hacen referencia al mismo componente de software en la misma versión | `log4j-core 2.14.1` | Exacta |
| **CVE** | hacen referencia al mismo identificador CVE | `CVE-2021-44228` | Exacta |
| **Recurso** | nombran el mismo objeto de infraestructura | `aws_s3_bucket.logs` | Exacta |
| **Endpoint** | reportan la misma clase de debilidad en la misma URL | `CWE-79 at example.com/search` | Heurística |

Un Hallazgo se une a **todos** los clústeres que le apliquen, no solo a uno. Un Hallazgo de SCA para
`log4j-core 2.14.1` que incluye tres CVE se une a cuatro Causas raíz: su clúster de componente y un
clúster por cada CVE. Esto es lo que permite que un Hallazgo de imagen de contenedor que solo reporta un
CVE se correlacione con el Hallazgo de SCA que reporta el componente.

### Coincidencia de componentes

Donde se usa el modelo de datos de Locations, los componentes se identifican mediante el **Package URL
(purl)**, sin calificadores ni subrutas, de modo que el mismo paquete reportado en distintas distribuciones
o arquitecturas forma un único clúster en lugar de varios. Los Hallazgos que solo llevan los campos
heredados `component_name` / `component_version` se identifican con esos campos en su lugar.

Los Hallazgos sin un componente utilizable se omiten en lugar de agruparse: una versión faltante, o el
marcador de posición `unknown-package` que emiten algunos formatos SBOM, colapsarían de otro modo cada fila
sin componente en un único clúster sin sentido.

### Coincidencia de CVE

Los identificadores CVE se convierten a mayúsculas y se recortan, de modo que `cve-2021-44228` y
`CVE-2021-44228` caen en el mismo clúster. Solo coinciden los identificadores CVE: GHSA, GO, RUSTSEC y otros
prefijos de asesorías se reconocen como identificadores de vulnerabilidad en otras partes de DefectDojo,
pero todavía no forman Causas raíz.

### Coincidencia de recursos

Las herramientas de postura en la nube (CSPM) y de infraestructura como código (IaC) reportan un
**recurso** en lugar de un paquete: un bucket de S3, un espacio de nombres de Kubernetes, un bloque de
recurso de Terraform. Esos Hallazgos llevan un nombre pero no una versión, por lo que no son componentes de
software y no se comparan como tales.

La coincidencia de recursos los agrupa por el identificador del recurso, normalizado a un mismo formato de
mayúsculas/minúsculas para que las herramientas que lo escriben de forma distinta igual coincidan. Es una
unión exacta, y es lo que permite que un Hallazgo de IaC sobre `aws_s3_bucket.logs` se ubique en la misma
Causa raíz que el Hallazgo de CSPM en tiempo de ejecución sobre el bucket desplegado.

Solo se comparan los identificadores calificados: un nombre de recurso lleva un tipo o un separador de ruta
(`.`, `/`, `:`). Una única palabra suelta se ignora, de modo que un Hallazgo cuyo escáner simplemente omitió
la versión del componente no se arrastra a un clúster de recursos con el que no tiene nada que ver.

### Coincidencia de endpoints

Dos herramientas DAST que analizan la misma aplicación a menudo reportarán ambas la misma debilidad en la
misma URL. La coincidencia de endpoints agrupa esos casos: la Causa raíz es una **clase de debilidad en una
ubicación**, por ejemplo `CWE-79 at example.com/search`.

Esta es la única señal **heurística**, y está etiquetada como tal en todos los lugares donde aparece. Un
purl o CVE compartido es una identidad; "mismo CWE, misma URL" es un juicio, y un revisor debe poder
ponderarlo de otra manera. El detalle del clúster marca a cada miembro con su tipo de coincidencia.

El CWE es obligatorio. Una URL por sí sola es un lugar, no una causa -- agrupar todos los Hallazgos en
`/search` sin importar qué tienen de malo produciría clústeres grandes y sin sentido.

Las cadenas de consulta, los fragmentos y los puertos se ignoran al comparar URL, de modo que `/search?q=a`
y `/search?q=b` son el mismo lugar, al igual que el mismo servicio en los puertos 443 y 8443.

> **Esto no correlaciona SAST con DAST.** Los hallazgos estáticos identifican un archivo fuente y los
> hallazgos dinámicos identifican una URL; establecer una correspondencia entre ambos requeriría un mapa de
> rutas que DefectDojo no tiene. La coincidencia de endpoints relaciona los hallazgos dinámicos entre sí.

### Cuando un CVE ya está cubierto por un componente

Un Hallazgo se une a su causa de componente *y* a cada una de sus causas de CVE, de modo que un Hallazgo de
SCA para `log4j-core 2.14.1` que incluye dos CVE produce tres Causas raíz. Sin intervención, las tres
compiten por el primer lugar de la lista clasificada, pero solo una de ellas representa trabajo real.
Actualizar `log4j-core` a una versión corregida resuelve ambos CVE de inmediato; no existe una acción
separada de "corregir CVE-2021-44228".

Por eso una Causa raíz de tipo CVE se marca como **cubierta** cuando *todos* sus Hallazgos miembro activos
son también miembros activos de una única causa de componente o de recurso. Las causas cubiertas se ocultan
de forma predeterminada en la página de Causas raíz, de modo que la lista se limite a las cosas sobre las
que realmente puede actuar.

En el momento en que **un** miembro queda fuera de ese componente, el CVE vuelve a valerse por sí mismo. Ese
es el caso del Hallazgo de imagen de contenedor que solo reporta un CVE sin ningún componente adjunto:
ninguna corrección de componente lo alcanza, por lo que el CVE es, genuinamente, trabajo aparte. Este es
exactamente el caso multidominio que la correlación existe para poner de manifiesto, y nunca se oculta.

Active **Show covered CVEs** encima de la tabla para verlos. Cada uno está etiquetado con la causa que lo
cubre, de modo que quede claro qué corrección lo resuelve. Las causas cubiertas solo se ocultan de la lista
predeterminada: conservan sus miembros, su evidencia y su retroalimentación, siguen siendo accesibles desde
el panel de Causas raíz de un Hallazgo, y un vínculo guardado hacia una de ellas se sigue abriendo con
normalidad.

La cobertura se reevalúa en cada ejecución, en ambas direcciones: un CVE deja de estar cubierto en cuanto
aparece un Hallazgo no cubierto, y vuelve a estar cubierto en cuanto ese Hallazgo se corrige o se triaja
fuera de la lista activa. Rechazar un vínculo también saca a ese miembro del cálculo, ya que usted ha
indicado que no pertenece ahí.

Las causas de componente y de recurso nunca se marcan como cubiertas, aun cuando sus miembros se superpongan
con los de otra. Cada una tiene su propia versión que actualizar, por lo que cada una representa trabajo
real.

### Qué Hallazgos son elegibles

Solo se correlacionan los Hallazgos activos y sobre los que se puede actuar. Un Hallazgo queda excluido
mientras está inactivo, mitigado, marcado como duplicado, como falso positivo, fuera de alcance, o con
riesgo aceptado. Los Hallazgos salen de sus clústeres a medida que se triajan, de modo que los conteos de
una Causa raíz siempre describen el trabajo pendiente.

## Cómo leer la página de Causas raíz

Abra **Root Causes** en la sección **Manage** de la barra lateral. La página enumera todas las Causas raíz
a las que tiene acceso, clasificadas de modo que las más grandes y riesgosas aparezcan primero.

| Columna | Qué le indica |
|---|---|
| **Root Cause** | El componente y la versión, o el CVE |
| **Type** | Componente, CVE, Recurso o Endpoint |
| **Fix** | La versión que lo corrige, cuando los miembros del clúster coinciden en una |
| **CVEs** | Todos los CVE observados entre los miembros del clúster (clústeres de componente) |
| **Active Findings** | Cuántos Hallazgos pendientes representa esta causa |
| **Products** | Radio de impacto: cuántos Productos se ven afectados |
| **Risk** | Riesgo agregado, sumado a partir de las severidades de los miembros activos |
| **Muted** | Si el clúster ha sido silenciado |

Las causas de tipo CVE que una causa de componente o de recurso ya cubre por completo se ocultan a menos
que **Show covered CVEs** esté activado; consulte
[Cuando un CVE ya está cubierto por un componente](#when-a-cve-is-already-covered-by-a-component).

Al seleccionar una fila se abre el clúster, que enumera cada Hallazgo miembro con su severidad, Producto,
dominio, tipo de **coincidencia**, y la **evidencia** que lo vincula. La evidencia se registra por vínculo,
de modo que un clúster siempre pueda explicarse a sí mismo: un vínculo de componente registra el purl con
el que coincidió, un vínculo de CVE registra el identificador, y un vínculo de endpoint registra la URL y
el CWE. La columna **Match** muestra `exact` para los vínculos de componente, CVE y recurso, y `heuristic`
para los vínculos de endpoint, de modo que un juicio nunca se presenta como una identidad.

El riesgo agregado es una suma determinista sobre las severidades de los miembros activos (Crítica 100,
Alta 70, Media 40, Baja 10, Informativa 1). No depende de que el motor de priorización esté habilitado.

**Fix** se toma de las propias versiones de corrección de los miembros, y solo se muestra cuando todos los
miembros que reportan una coinciden en la misma. Los escáneres no siempre coinciden, y un clúster de CVE
puede abarcar componentes que se corrigen cada uno en una versión distinta, de modo que cuando no hay una
única respuesta la columna se deja vacía en lugar de elegir una al azar.

### Lo que ve está limitado a su acceso

Los miembros, los conteos y el radio de impacto se filtran según los Hallazgos que usted está autorizado a
ver, y la clasificación se calcula después de ese filtrado. Por eso dos usuarios con distinto acceso a
Productos verán conteos diferentes para la misma Causa raíz, y un clúster cuyos miembros usted no puede ver
no aparecerá en absoluto para usted.

## Dónde más aparece la correlación

### En un Hallazgo

La propia página de un Hallazgo incluye un panel de **Root Causes** que enumera cada clúster al que
pertenece, dividido entre el componente (o recurso) vulnerable y los CVE que comparte. Ahí es normalmente
donde la correlación resulta más útil: usted ya está triajando un Hallazgo y esta le indica que la
corrección es compartida. Los vínculos que usted ha rechazado no vuelven a aparecer ahí.

### En la prioridad del Hallazgo

Una Causa raíz que abarca muchos Productos hace que cada uno de sus Hallazgos miembro sea más urgente,
porque una sola corrección los resuelve todos. Por eso la prioridad aumenta con el **radio de impacto de la
Causa raíz más amplia a la que pertenece un Hallazgo**:

- Un clúster limitado a un solo Producto no agrega nada: no existe la narrativa de "una corrección resuelve
  muchos".
- Cada Producto adicional afectado agrega un poco más, hasta un tope, de modo que un clúster muy amplio no
  puede superar a la severidad.
- Cuenta el clúster más amplio, no la suma de todos ellos, de modo que un Hallazgo no se prioriza más solo
  por llevar muchos identificadores CVE.
- Los vínculos que usted ha **rechazado** dejan de contar. Un clúster **silenciado** sigue contando:
  silenciarlo lo oculta de la lista clasificada, pero no significa que los Hallazgos no estén relacionados.

Este peso se puede ajustar por Producto como el multiplicador **Correlation** en el motor de priorización,
junto con Severity, Exploitability, Endpoints y Reachability. Todo el término desaparece cuando el feature
flag está desactivado, de modo que las puntuaciones no cambian en una instancia que no usa correlación.

### En un panel

**Top Root Causes** está disponible como widget de panel, y enumera los clústeres con mejor clasificación
junto con su cantidad de hallazgos, los Productos afectados y el riesgo. Agréguelo desde el selector de
widgets; solo aparece ahí mientras la función está habilitada. Sus conteos están limitados a su acceso de
la misma manera que la página.

## Dar retroalimentación sobre un clúster

La correlación es un juicio sobre sus datos, así que usted puede corregirla.

- **Confirmar** un miembro para registrar que el vínculo es correcto.
- **Rechazar** un miembro para registrar que no lo es, lo cual lo elimina de la lista de miembros activos
  del clúster.
- **Silenciar** una Causa raíz completa para que deje de competir por atención en la lista clasificada.
  **Anular el silenciado** la restaura.

La retroalimentación es duradera. El desgaste habitual de una reimportación -- un Hallazgo que se mitiga y
luego se reactiva -- no borrará una confirmación ni un rechazo, y un clúster silenciado nunca se elimina
aunque temporalmente no tenga miembros. Solo se reconcilian y desaparecen los vínculos que el sistema creó
por sí mismo cuando dejan de aplicar.

## Cómo y cuándo se ejecuta la correlación

La correlación se ejecuta **automáticamente y de forma asíncrona después de cada importación y
reimportación**, sobre los Hallazgos que esa importación afectó. Es de mejor esfuerzo: un fallo dentro de
la correlación se registra y se absorbe, y nunca hace fallar la importación que lo desencadenó.

Como es idempotente, volver a ejecutarla sobre los mismos Hallazgos converge en el mismo resultado en lugar
de duplicar nada. A medida que los Hallazgos cambian, el motor también reconcilia: una actualización de
versión de componente mueve el Hallazgo al nuevo clúster y elimina el anterior una vez que queda vacío.

### Backfill de Hallazgos existentes

Para correlacionar Hallazgos anteriores a la activación de la función, ejecute el comando de gestión. Omita
el argumento para recalcular todo el portafolio, o limítelo a un solo Producto:

```bash
python manage.py recompute_correlations
python manage.py recompute_correlations --product-id 42
```

## Qué expone la API

Las Causas raíz se pueden leer a través de la API estándar, de modo que pueda incorporarlas a un informe,
abrir tickets a partir de ellas, o rastrearlas como una métrica sin pasar por la interfaz.

- `GET /api/v2/root_causes/` las enumera, clasificadas de la misma manera que la página.
- `GET /api/v2/root_causes/{id}/` devuelve una Causa raíz junto con sus Hallazgos miembro, cada uno con la
  evidencia que lo vincula y si la coincidencia fue exacta o heurística.

Ambos son de solo lectura. Confirmar, rechazar y silenciar se hacen desde la interfaz por ahora; eso se
deja deliberadamente sin publicar mientras la función está en Beta, de modo que agregarlos más adelante no
pueda romper nada que usted ya haya construido.

Filtros en la lista: `cause_type` (`exact` o `in`), `muted`, `identity_key` (`exact` o `icontains`) y
`display_name__icontains`.

Dos comportamientos que vale la pena conocer antes de programar contra la API:

- **Los conteos están limitados al acceso del token**, exactamente igual que en la interfaz. Dos tokens con
  distinto acceso a Productos reportarán distintos `active_member_count`, `product_count` y `risk_score`
  para la misma Causa raíz. Esto es intencional -- los números describen lo que *ese* llamador puede ver,
  así que no los trate como totales de todo el portafolio.
- **Las causas de CVE cubiertas se dejan fuera de la lista** pero siempre se pueden recuperar por id. Pase
  `?include_subsumed=true` para incluirlas; un id de Causa raíz que haya guardado antes sigue funcionando a
  través de `GET /api/v2/root_causes/{id}/` incluso después de que quede cubierta. Cada causa cubierta
  lleva `subsumed_by_id` y `subsumed_by_name` para que pueda ver qué corrección la resuelve.

Si el feature flag está desactivado, ambos endpoints devuelven **403**, no 404 -- el endpoint existe,
simplemente no está habilitado.

## Interacción con la deduplicación global de componentes

La [Deduplicación global de componentes](/triage_findings/finding_deduplication/pro__global_component_deduplication/)
marca los Hallazgos de SCA entre Productos como duplicados, y los duplicados no se correlacionan. Con
ambas funciones activadas, el conteo de miembros de una Causa raíz refleja entonces los originales que
sobreviven en lugar de cada aparición. Las dos también se basan en cosas distintas -- la deduplicación
global compara por nombre y versión de componente, mientras que la correlación usa el Package URL
completo -- de modo que habilitar ambas es compatible, pero los conteos que producen no son directamente
comparables.
