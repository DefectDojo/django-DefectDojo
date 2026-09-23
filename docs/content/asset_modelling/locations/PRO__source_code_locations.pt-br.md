---
title: Localizações de Código-Fonte
description: Localizações de código modelam onde um achado de análise estática vive
  no código-fonte e registram seu histórico de movimentação à medida que o código
  evolui
weight: 6
audience: pro
---

As **Localizações de Código-Fonte** estendem o modelo de Localizações à análise estática: além de URLs (DAST) e Dependências (SCA), uma localização do tipo **Código** descreve onde um achado de SAST vive no código-fonte — identificado pelo **caminho do arquivo e número da linha**.

> As Localizações de Código-Fonte exigem o recurso de Localizações (Beta). Para habilitar as Localizações na sua instância, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com).

## O Que Elas Modelam

Todo achado estático que reporta um caminho de arquivo recebe uma localização de Código. O valor canônico da localização é `path/to/file.py:42` (ou apenas o caminho do arquivo quando a ferramenta não reporta uma linha). Como todas as Localizações, as localizações de código são objetos compartilhados: dois achados no mesmo arquivo e linha referenciam a mesma localização, e a localização carrega status de referência por achado e por ativo.

As localizações de código são **gerenciadas por varredura**: são criadas e atualizadas por importações e reimportações, não manualmente. Não existe uma ação "Nova Localização de Código-Fonte" — o scanner é a fonte da verdade sobre onde os achados de código vivem.

## Onde Encontrá-las

- **All Source Code** na barra lateral lista todas as localizações de código da instância, com a mesma filtragem e marcação por tags que URLs e Dependências.
- **View Source Code** no menu de Localizações de um Ativo restringe a lista a um único ativo.
- A página de um achado mostra sua localização de código atual e, quando o achado se moveu, seu **histórico de localização**.

## Histórico de Movimentação

O código-fonte se move constantemente: commits deslocam números de linha, refatorações renomeiam arquivos. Quando o [Location Drift Matching](/triage_findings/finding_deduplication/pro__location_drift_matching/) está habilitado para uma ferramenta, um achado que se move mantém sua identidade, e suas referências de localização de código registram o rastro:

- A referência do achado à localização **antiga** é mitigada e marcada com *para onde o achado se moveu* e *por que a correspondência foi feita* (linha mais próxima, fluxo de dados, renomeação de arquivo...).
- Uma referência à localização **nova** é criada e permanece ativa.

O resultado é uma cadeia de substituição navegável — "este achado viveu em `auth.py:42`, depois em `auth.py:57`, depois em `session.py:31`" — renderizada como uma linha do tempo na página do achado. O mesmo mecanismo de histórico cobre movimentações de URL e atualizações de versão de dependência, então os três tipos de localização compartilham uma única interface de linha do tempo.

O histórico é registrado a partir do momento em que as Localizações são habilitadas na instância. Achados que se moveram antes disso mantêm sua localização atual; os saltos anteriores foram aplicados, mas não registrados. Para instâncias com anos de histórico anterior ao recurso, o [comando de consolidação de churn](/triage_findings/finding_deduplication/pro__location_drift_matching/#consolidating-historical-churn) pode reconstruir os rastros ao mesclar cadeias históricas de fechar-e-recriar.

## Correção de Status

Os status de referência de localização de código são mantidos fiéis por meio da reimportação em **todos** os algoritmos de correspondência, independentemente de a correspondência por deriva (drift matching) estar habilitada:

- A referência de código atual de um achado correspondido é sincronizada a cada reimportação, de modo que um achado que se moveu não deixe sua referência antiga ativa para sempre.
- A mesma sincronização independente de configuração se aplica às referências de dependência: quando a versão do pacote de um achado de SCA é atualizada, a referência da versão antiga é mitigada em vez de permanecer ativa junto com a nova.

## Relação com os Campos do Achado

Os próprios campos `file_path` / `line` do achado continuam sendo os valores escalares autoritativos (são eles que os filtros, os hashes e a API expõem); a localização de Código é a visão compartilhada e com contagem de referências dessa mesma coordenada. A reimportação atualiza os escalares a partir da varredura mais recente, e o mecanismo de localizações deriva as localizações a partir deles — os dois não podem divergir.
