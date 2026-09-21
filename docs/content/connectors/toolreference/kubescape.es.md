---
title: "Kubescape"
description: "Cómo configurar el Conector Upstream de Kubescape para DefectDojo"
weight: 85
audience: pro
---
El conector Kubescape lee los resultados de postura (configuraciones incorrectas) de Kubernetes generados por el [operador de Kubescape](https://kubescape.io/docs/install-operator/) directamente desde la API de Kubernetes del clúster — no se requiere ninguna cuenta SaaS de ARMO. Lee los objetos `WorkloadConfigurationScan` que expone la API agregada de almacenamiento dentro del clúster del operador (`spdx.softwarecomposition.kubescape.io/v1beta1`). Cada **namespace** de Kubernetes que tiene resultados de postura se asigna a un Registro (Producto); cada control fallido de una carga de trabajo se convierte en un Hallazgo.

#### Requisitos previos

- El operador de Kubescape debe estar instalado en el clúster de destino con el escaneo de configuración habilitado (consulte [Instalación en su clúster](https://kubescape.io/docs/install-operator/)). Confirme que existen resultados con `kubectl get workloadconfigurationscans -A`.
- Un **kubeconfig** que otorgue acceso de lectura al grupo de API `spdx.softwarecomposition.kubescape.io` (list/get sobre `workloadconfigurationscans`) para el clúster de destino.

#### Asignaciones del conector

1. Introduzca la URL del servidor de API del clúster (o un identificador descriptivo del clúster) en el campo **Location**.
2. Pegue el **kubeconfig** del clúster de destino en el campo `kubeconfig`. Opcionalmente, establezca `kube_context` para seleccionar un contexto dentro de él, y `cluster_name` para etiquetar los Productos detectados.
3. Cada namespace con resultados de postura se detecta como un Registro; mapee los que desee importar a Productos de DefectDojo.

Los hallazgos se derivan por control fallido: el nombre del control y la carga de trabajo identifican el Hallazgo, la severidad proviene del factor de puntuación del control, el ID del control se convierte en el ID de vulnerabilidad, y cada Hallazgo enlaza con su referencia de control en `https://hub.armosec.io/docs/`.
