---
title: Dimensionamiento de hardware para DefectDojo Pro autoalojado
description: Orientación general para dimensionar cómputo, memoria y almacenamiento
  para un despliegue autoalojado de DefectDojo Pro
draft: false
weight: 4
audience: pro
---

Dimensionar un despliegue de DefectDojo se reduce a dos preguntas. Cuántos datos está conservando y cuántas personas trabajan en él a la vez. Esta página ofrece puntos de partida para ambas.

Considere lo que sigue como orientación general y no como una especificación. Las cifras se inclinan deliberadamente hacia lo conservador, y asumen un despliegue que realiza triaje diario junto con importaciones de escaneo regulares. Sus propios números variarán según cómo use el producto, así que lea las notas debajo de la tabla antes de aprovisionar nada.

Las especificaciones se dan como cifras genéricas de vCPU y memoria para que se apliquen a cualquier proveedor de nube o hardware on-premise. La orientación de nodos de aplicación asume Kubernetes. Si ejecuta Docker Compose en un único host, use los mismos totales.

## Tabla de dimensionamiento

| Hallazgos | Usuarios concurrentes | Base de datos | Nodos de aplicación |
| --- | --- | --- | --- |
| Hasta 100K | Hasta ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16–32 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |
| 500M | 500+ | 192 vCPU / 768 GB+ | 50+ × (8 vCPU / 32 GB) |

Dónde se ubica dentro de un rango depende de su carga de trabajo. Comience por el extremo superior de un rango si algo de [Qué le hace subir de nivel](#what-pushes-you-up-a-tier) se aplica a usted.

La fila de 500M es un punto de referencia en el extremo lejano en lugar de una continuación del patrón anterior, así que no interpole entre ella y el nivel de 10M. Un despliegue situado entre esos dos necesita dimensionarse individualmente. También asume un trabajo que el hardware por sí solo no hará por usted, cubierto en [Despliegues muy grandes](#very-large-deployments).

## Cómo interpretar estos números

### La memoria de la base de datos importa más que su CPU

DefectDojo ejecuta consultas intensivas en agregación sobre sus hallazgos. Estas se mantienen rápidas mientras el conjunto de trabajo y sus índices se sirven desde memoria, y se degradan rápidamente en cuanto la base de datos empieza a recurrir al disco. Cuando tenga que elegir, compre memoria antes que núcleos. La tabla lo refleja. La memoria aproximadamente se duplica de nivel a nivel, mientras que el número de CPU se mueve mucho más lentamente.

### Los nodos de aplicación siguen a los usuarios, no a los hallazgos

Las cifras de usuarios concurrentes de la tabla asumen que los conjuntos de datos más pequeños pertenecen a equipos más pequeños. Ese supuesto se rompe a menudo. Si conserva 200K hallazgos pero tiene 100 personas en la interfaz a la vez, dimensione la capa de aplicación para los usuarios y deje la base de datos donde su número de hallazgos la sitúe. Las dos escalan de forma independiente.

Hay una excepción, en el extremo lejano de la tabla. La importación y la deduplicación se ejecutan en la capa de aplicación en lugar de en la base de datos, así que una vez que un conjunto de datos es lo bastante grande como para que ese trabajo predomine, el número de nodos sigue al volumen de ingesta en lugar de al número de usuarios. Por eso la fila de 500M se sitúa muy por encima de lo que sugeriría por sí sola su cifra de usuarios.

### La forma del nodo es flexible

Kubernetes distribuirá la carga tanto si le da pocos nodos grandes como más nodos pequeños, así que los números de nodos anteriores son una disposición viable y no un requisito. Vale la pena respetar dos cosas. Mantenga al menos dos nodos para que perder uno no derribe la aplicación, y evite nodos más pequeños que 2 vCPU / 8 GB para que los pods individuales se programen con comodidad.

## Almacenamiento

Planifique 20–30 GB de almacenamiento de base de datos por millón de hallazgos. Dónde caiga dentro de ese rango depende de cuánto cuelgue de cada hallazgo. Las descripciones largas y los recuentos de endpoints grandes le empujan hacia la parte superior. Las filas de hallazgos en sí son una parte pequeña de esto. La mayor parte del espacio va a los índices y a las tablas relacionadas que cuelgan de cada hallazgo, así que dimensionar solo a partir de los datos de fila le dejará muy corto.

Cada nivel hasta 10M cabe en unos pocos cientos de GB de SSD de propósito general. El almacenamiento es barato frente al costo de quedarse sin él, así que aprovisione para donde espere estar dentro de un año en lugar de donde está ahora. Si su proveedor ofrece autoescalado de almacenamiento, actívelo.

La fila de 500M está dimensionada en 2.5 TB. Esa cifra asume que el conjunto de datos activo se gestiona de forma activa, con los hallazgos más antiguos archivados fuera de la ruta activa en lugar de acumularse indefinidamente. Aplicada de forma ingenua, la tasa por millón anterior situaría un despliegue de 500M sin gestionar varias veces más alto. Si se dirige hacia esta escala, trate la estrategia de archivado como parte del ejercicio de dimensionamiento en lugar de algo que resolver más adelante.

El almacenamiento a esta escala también necesita atención al rendimiento, no solo a la capacidad. Una vez que el conjunto de trabajo deja de caber en memoria, las IOPS de referencia predeterminadas en los volúmenes de propósito general se convierten en el límite mucho antes que la capacidad.

El almacenamiento de medios es independiente y normalmente mucho más pequeño. Contiene artefactos subidos como capturas de pantalla y documentos de aceptación de riesgo, así que dimensiónelo según sus propios hábitos de carga.

## Qué le hace subir de nivel

El número de hallazgos es la cifra principal, pero varias cosas le harán dimensionar hacia arriba antes de lo que sugiere el número por sí solo.

- **Volumen y frecuencia de importación.** Escaneos grandes que llegan con frecuencia, especialmente varios al mismo tiempo, generan una carga sostenida tanto en la base de datos como en los workers asíncronos. Los pipelines de CI que importan en cada build son la causa habitual.
- **Deduplicación.** La deduplicación compara los hallazgos entrantes con los que ya tiene. Cuantos más hallazgos tenga y más amplia sea su configuración de deduplicación, más trabajo realiza cada importación.
- **Informes y paneles.** Las vistas de métricas y la generación de informes grandes son intensivas en lectura, y golpean la base de datos con más fuerza que el triaje diario.
- **Tráfico de API.** Las integraciones que sondean o extraen grandes conjuntos de resultados añaden carga concurrente que nunca aparece en su número de usuarios interactivos.
- **Retención.** Los despliegues que conservan todo para siempre crecen hacia el siguiente nivel según lo previsto. Archivar o eliminar datos antiguos le mantiene donde está durante más tiempo.

## Despliegues muy grandes

Más allá del nivel de 10M, el hardware deja de ser toda la respuesta. Cambian dos cosas.

La restricción vinculante se traslada de la lectura a la escritura. La deduplicación compara cada hallazgo entrante con lo que ya tiene, así que el costo de una importación crece con el tamaño del conjunto de datos que hay detrás. En la parte superior de la tabla, esto es habitualmente lo primero que se golpea, antes que nada que los usuarios noten en la interfaz. El volumen de importación que sea que haya construido un conjunto de datos tan grande generalmente sigue en funcionamiento, así que ese costo se paga de forma continua en lugar de una sola vez.

Las cifras de memoria asumen que el conjunto activo se mantiene pequeño. Un despliegue trabaja los hallazgos recientes y deja los más antiguos en gran medida sin tocar, que es lo que permite que una base de datos contenga muchos más datos de los que tiene memoria y aun así rinda bien. Si su patrón de acceso está genuinamente distribuido por todo el conjunto de datos, necesitará más memoria de la que lista la tabla, y más allá de cierto punto ninguna instancia individual tendrá suficiente.

Ambas cosas apuntan al mismo trabajo. Particionar y archivar los hallazgos fríos fuera del conjunto de datos activo importa más a esta escala que otro incremento de vCPU, y los informes pesados pertenecen a una réplica de lectura en lugar de a la primaria. Planifique eso junto con el hardware en lugar de después, y hable con nosotros antes de aprovisionar.

## En caso de duda, redondee hacia arriba

Las cifras aquí ya se inclinan hacia lo conservador, y quedarse un tamaño demasiado grande cuesta mucho menos que quedarse un tamaño demasiado pequeño. La presión de memoria de la base de datos en particular no se degrada con elegancia. El rendimiento se mantiene bien hasta que deja de hacerlo.

Añadir capacidad de aplicación más adelante es sencillo, ya que se añaden nodos. Redimensionar una base de datos normalmente implica tiempo de inactividad, así que es lo que vale la pena acertar desde el principio.

## Preguntas o soporte

Estos son puntos de partida, no límites. Si su despliegue se sitúa en la parte superior de la tabla, o su carga de trabajo no se parece a los supuestos aquí presentados, hable con nosotros antes de aprovisionar. Contacte a su representante de cuenta o a [support@defectdojo.com](mailto:support@defectdojo.com).
