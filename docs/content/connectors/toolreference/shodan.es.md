---
title: "Shodan"
description: "Cómo configurar el Conector Upstream de Shodan para DefectDojo"
weight: 123
audience: pro
---
El conector de Shodan usa la API REST de Shodan para importar las vulnerabilidades (CVE) que Shodan ha observado en sus hosts expuestos a internet. Usted proporciona una consulta de búsqueda de Shodan que limita la importación a sus propios activos; DefectDojo crea un Record para cada host coincidente e importa sus CVE como hallazgos.

#### Requisitos previos

Necesitará una API key de Shodan, disponible en la página **Account** de Shodan. La búsqueda de hosts con datos de vulnerabilidades requiere una membresía de Shodan o un plan de API de pago: el nivel gratuito no puede paginar los resultados de búsqueda.

#### Asignaciones del conector

1. Ingrese `https://api.shodan.io` en el campo **Location**.
2. Ingrese su API key de Shodan en el campo **API Key**.
3. En el campo **Search Query**, ingrese una consulta de Shodan que limite la importación a los activos de su organización; por ejemplo, `hostname:example.com`, `net:203.0.113.0/24`, u `org:"Example Inc"`. Solo se importan los hosts que coincidan con esta consulta, así que manténgala limitada a la infraestructura que usted posee.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada host coincidente se convierte en un Record, y cada CVE que Shodan detectó en los servicios expuestos de ese host se importa como un hallazgo; la severidad se deriva de la puntuación CVSS, incluyendo el contexto de EPSS y CISA KEV cuando está disponible. Cada página de resultados de búsqueda consume un crédito de consulta de Shodan.
