---
title: Correspondência por Deriva de Localização
description: Acompanhe achados enquanto suas localizações mudam entre reimportações
  — mudanças de linha, renomeações de arquivo, movimentações de URL e atualizações
  de versão de dependência não fecham mais e recriam achados
weight: 6
audience: pro
---

**Correspondência por Deriva de Localização** permite que a reimportação reconheça um achado cuja *localização* mudou como o **mesmo achado**. Sem isso, a reimportação compara achados por um hash de identidade exato que inclui campos de localização — portanto, cada movimentação de localização fecha o achado antigo e cria um novo idêntico:

- Um commit desloca código e o **número da linha** do achado muda.
- Uma refatoração **renomeia ou move o arquivo**.
- A **URL, porta ou host** de uma aplicação web muda entre varreduras DAST.
- Uma **atualização de versão** de dependência muda a versão do pacote vulnerável relatada por uma ferramenta SCA.

Cada um desses casos anteriormente produzia um achado fechado mais um achado "novo" — perdendo o status, as notas, o relógio de SLA, a aceitação de risco e a vinculação com o JIRA do achado original, e gerando ruído falso de "novo achado crítico". Com a Correspondência por Deriva de Localização ativada, um único achado é mantido no lugar: sua localização é atualizada a partir da varredura mais recente e seu histórico é preservado.

> A Correspondência por Deriva de Localização é um recurso do DefectDojo Pro. Ela vem **desativada por padrão** e é habilitada por ferramenta de segurança.

## Habilitando o Rastreamento de Localização

O rastreamento de localização é configurado por ferramenta em:
**Settings > Finding Workflow > Reimport Deduplication** (**Settings > Pro Settings > Deduplication Settings > Reimport Deduplication** em instâncias que ainda usam o layout de menu anterior)

1. Selecione a **Security Tool**.
2. Defina o **Deduplication Algorithm** como **Hash Code**. O rastreamento de localização se aplica apenas ao algoritmo Hash Code — ferramentas com um **Unique ID From Tool** confiável já rastreiam a movimentação através de seus IDs estáveis e não precisam dele.
3. Ative **Track findings as locations change**.

Salvar a configuração aciona automaticamente um re-hash em segundo plano dos achados existentes da ferramenta (veja [Habilitando em Dados Existentes](#enabling-on-existing-data-upgrades) abaixo), de modo que achados importados antes de ativar a opção participem imediatamente.

## Como a Correspondência Funciona

Com o rastreamento ativado, a correspondência de reimportação acontece em duas etapas:

1. **Identidade estável.** O hash de reimportação é calculado *sem* os campos de localização voláteis (linha, caminho do arquivo, descrição, nome/versão do componente, endpoints) — portanto, a identidade de um achado captura *o que* o achado é, não *onde* ele está atualmente. Achados que não se moveram ainda correspondem exatamente, primeiro, e nunca são perturbados.
2. **Pareamento por evidência.** Dentro de cada grupo de achados que compartilham uma identidade estável, um comparador de localização pareia achados recebidos com achados existentes usando evidências de localização, em passagens determinísticas da mais forte para a mais fraca. Um achado é direcionado a exatamente um comparador com base nos dados de localização que ele carrega.

### Achados de código (SAST)

| Pass | Pairs when | Notes |
|------|-----------|-------|
| Exata | Mesmo arquivo e linha | Sempre vence; um vizinho que se moveu nunca pode "roubar" a correspondência de um achado que não se moveu |
| Fluxo de dados | Mesmos objetos de origem/destino (`sast_source_object` / `sast_sink_object`) | Para ferramentas que relatam fluxo de dados; imune à renumeração de linhas |
| Linha mais próxima | Mesmo arquivo, número de linha mais próximo | Guloso, do mais próximo primeiro; apenas no mesmo arquivo |
| Renomeação de arquivo | Arquivo diferente | Apenas quando restam exatamente **um** achado recebido e **um** achado existente — a ambiguidade falha de forma segura |

### Achados de URL (DAST)

| Pass | Pairs when |
|------|-----------|
| Exata | Conjunto de endpoints idêntico |
| Deriva do conjunto de endpoints | Conjuntos de endpoints sobrepostos (endpoints adicionados/removidos) |
| Mudança de porta | Mesmo host e caminho, porta diferente |
| Deriva de caminho | Mesmo host, caminho semelhante (similaridade de segmento mutuamente ótima) |
| Mudança de host | Host diferente — apenas como um pareamento 1×1 inequívoco, com uma proteção contra DNS curinga |

### Achados de dependência (SCA)

| Pass | Pairs when |
|------|-----------|
| Exata | Mesmo pacote, versão e manifesto |
| Atualização de versão | Mesmo pacote, versão diferente |
| Mudança de manifesto | Mesmo pacote, caminho de lockfile/manifesto diferente |

Quando o mesmo pacote vulnerável aparece em **vários manifestos**, o achado de cada manifesto é rastreado de forma independente — uma atualização de versão em um lockfile nunca absorve o achado de outro.

### Reavaliações de severidade

Ferramentas de segurança reavaliam severidades à medida que seus motores de regras evoluem. Com o rastreamento ativado, uma mudança de severidade relatada pela ferramenta **não** divide a identidade de um achado: o achado corresponde, e sua severidade é atualizada a partir da varredura — a menos que uma pessoa tenha retriado a severidade manualmente, caso em que o valor humano sempre prevalece (veja abaixo).

## O Que É Preservado, O Que É Atualizado

Um achado pareado por deriva mantém tudo o que importa sobre seu ciclo de vida: status, notas, aceitação de risco, datas de SLA, vinculação com o JIRA e seu ID de achado.

Seus **campos de localização** (caminho do arquivo, linha, campos de fluxo de dados, endpoints, versão do componente) são atualizados a partir da varredura recebida.

Seus **campos descritivos** (título, descrição, severidade, versão do componente) são atualizados a partir da varredura *somente quando a varredura ainda os possui*: o DefectDojo registra um digest de cada campo conforme escrito pela última vez pela importação/reimportação. Se o valor atual ainda corresponder a esse digest, foi a ferramenta que o escreveu e a varredura pode atualizá-lo; se uma pessoa editou o campo desde então, o valor humano é preservado permanentemente. Achados criados antes deste recurso não têm digests e são tratados como pertencentes a humanos — a reimportação nunca sobrescreverá seus campos descritivos. A única exceção é a **versão do componente**, que é telemetria de varredura que as pessoas essencialmente nunca editam manualmente: ela é atualizada mesmo sem um digest, de modo que achados de SCA migrados ainda recebem atualizações de versão.

### A identidade sempre acompanha o relatório da ferramenta

Quando um achado correspondido é atualizado, seus hashes de identidade armazenados são **adotados a partir dos valores da varredura recebida** — nunca recalculados a partir dos campos atuais do achado. Essa distinção importa: os campos do achado após uma atualização são uma *mescla* de valores da varredura e edições humanas, e um hash calculado a partir dessa mescla conteria valores que nenhuma varredura jamais relatará novamente, quebrando silenciosamente toda reimportação futura desse achado. A adoção garante que uma pessoa renomear um achado, retriar sua severidade ou editar sua descrição nunca possa comprometer sua capacidade de corresponder à próxima varredura.

## Histórico de Localização

Em **Locations** (Beta), cada correspondência por deriva registra onde o achado costumava estar: a localização de código-fonte, URL ou versão de dependência substituída é mantida como referência no achado, marcada com para onde ele se moveu e por quê. A linha do tempo de localização do achado — "este achado esteve em `auth.py:42`, depois `auth.py:57`, depois `session.py:31`" — fica visível na página do achado. Veja [Localizações de Código-Fonte](/asset_modelling/locations/pro__source_code_locations/).

A Correspondência por Deriva de Localização em si funciona **com ou sem** o recurso Locations: o pareamento ocorre com base nos próprios campos e endpoints do achado, de modo que os achados sobrevivem à movimentação de qualquer forma. O Locations adiciona, por cima disso, o histórico registrado e visível. O histórico começa a ser registrado a partir do momento em que o Locations é ativado — movimentações anteriores foram aplicadas, mas não registradas.

## Habilitando em Dados Existentes (Upgrades)

O recurso foi projetado para se automigrar:

- **Nada muda até que você opte por ativar.** Com a opção desativada, os hashes de reimportação são calculados exatamente como antes.
- **Salvar a opção reprocessa o hash dos achados existentes.** O job em segundo plano recalcula os hashes de reimportação armazenados da ferramenta com a nova identidade (sem localização) e cria quaisquer registros de achado Pro ausentes para dados migrados do open-source. Uma vez concluído, achados antigos e novos falam a mesma linguagem de identidade — um achado importado meses atrás é rastreado exatamente como um importado ontem.
- **Ative entre execuções de varredura em instâncias grandes.** O re-hash é um job em segundo plano sobre toda a população de achados da ferramenta. Uma reimportação que ocorra enquanto ele ainda está em andamento pode ver uma mistura de hashes antigos e novos e reprocessar a fatia ainda não processada uma vez. Ative a opção em um horário tranquilo e deixe o job terminar antes da próxima reimportação agendada.
- **Títulos editados manualmente.** O re-hash de ativação é calculado a partir dos valores atuais do banco de dados. Todo campo comumente editado é excluído da identidade rastreada — edições de severidade são, na verdade, *corrigidas* pelo re-hash — mas se uma pessoa renomeou o **título** de um achado (e o título é um campo de hash para essa ferramenta), esse achado específico será reprocessado uma vez em sua próxima reimportação antes de se estabilizar.

## Escolhendo Campos de Hash para Ferramentas Rastreadas

O rastreamento de localização remove automaticamente os campos de localização voláteis do hash de reimportação — você não precisa remover `line` ou `file_path` da configuração de hash de uma ferramenta manualmente. Duas configurações merecem atenção:

- **Configurações totalmente voláteis.** Se os campos de hash de uma ferramenta forem *inteiramente* campos de localização (por exemplo, apenas `file_path` + `line`), removê-los não deixa nada, e o hash recai para a identidade legada de título+CWE. A correspondência ainda funciona — as passagens de evidência carregam a discriminação — mas a identidade fica muito mais grosseira. Prefira configurações que mantenham pelo menos um campo de conteúdo estável.
- **Localização embutida em campos estáveis.** As exclusões de campo não ajudam quando os dados de localização se escondem *dentro* de um campo que precisa permanecer no hash. Uma ferramenta que intitula achados como "SQL Injection in queries.py:42" muda seu título a cada movimentação de linha — a identidade se divide e o rastreamento não consegue enxergar o par. Para essas ferramentas, escolha campos de hash que evitem o campo vazador; **CWE + Content Fingerprint** é a combinação forte (veja [Content Fingerprint](/triage_findings/finding_deduplication/pro__deduplication_tuning/#content-fingerprint)).

## Interação com a Deduplicação

O rastreamento de localização é um recurso de **reimportação**: a Deduplicação Same Tool e Cross Tool permanecem inalteradas — seus hashes são calculados exatamente como antes, e as exclusões nunca se aplicam a elas. Duas integrações deliberadas:

- **Atualizações de versão não bloqueiam mais a deduplicação de dependências.** O filtro de localização da deduplicação normalmente exige que dois achados de SCA referenciem a versão *idêntica* do pacote. Para ferramentas com rastreamento ativado, uma identidade de pacote compartilhada (ecossistema + nome do pacote, com o namespace comparado sempre que ambos os lados o possuem) já é suficiente — consistente com a reimportação tratando uma atualização de versão como o mesmo achado. Isso se aplica apenas à deduplicação Same Tool sob o Locations.
- **Entradas de identidade limpas.** Como os achados correspondidos adotam os hashes relatados pela varredura, os valores que a deduplicação consome sempre refletem o que a ferramenta relatou por último — edições humanas não podem mais contaminá-los.

## Consolidando o Retrabalho Histórico

Instâncias que rodaram por anos sem rastreamento acumulam cadeias de fechar-e-recriar: o mesmo achado fechado e reaberto como um novo registro toda vez que se movia. Um management command encontra essas cadeias (ligadas passo a passo pelos mesmos comparadores, com uma proteção de sobreposição de tempo de vida para que achados que genuinamente coexistiram nunca sejam mesclados) e consolida cada cadeia em seu achado mais recente, marcando as cópias mais antigas como duplicatas do sobrevivente:

```bash
# Dry run — reports what would be consolidated, changes nothing
./manage.py consolidate_location_churn --product <id>

# Apply, with a confirmation prompt
./manage.py consolidate_location_churn --product <id> --apply
```

O comando é dry-run por padrão, nunca é executado automaticamente e pode ser delimitado com `--test` ou `--product`. Sob o Locations, o histórico de localização do sobrevivente é reconstruído a partir da cadeia.

## Salvaguardas e Limites

- **Correspondências exatas sempre vencem.** Um achado que não se moveu é pareado exatamente antes de qualquer passagem aproximada ser executada; achados que se moveram nunca podem roubar sua correspondência.
- **A ambiguidade falha de forma segura.** Renomeações de arquivo e mudanças de host só pareiam quando resta exatamente um candidato de cada lado. Dois achados que desapareceram enquanto dois novos surgiram permanecem sem correspondência em vez de adivinhar.
- **Grupos muito grandes degradam-se com elegância.** Se um único grupo de identidade exceder o limite de pareamento (40.000 comparações), a correspondência se degrada para apenas-exata nesse grupo, em vez de consumir tempo ilimitado.
- **Compromisso aceito:** as passagens 1×1 de renomeação/mudança de host podem criar uma falsa continuidade quando um achado desaparece e um achado não relacionado com a mesma identidade estável surge na mesma reimportação. Esse é o preço deliberado de rastrear renomeações; a identidade estável (mesma ferramenta, título, CWE, severidade ...) limita o quanto o pareamento pode errar.

## Atualização de Localização Sem a Opção Ativada

Independentemente do rastreamento de localização, a reimportação mantém a localização de todo achado correspondido atualizada em **todos** os algoritmos: um achado correspondido por Unique ID From Tool (ou qualquer outro algoritmo) atualiza seus campos `line`, `file_path`, campos de fluxo de dados e `component_version` a partir do relatório recebido, e endpoints relatados são anexados enquanto os que desapareceram são mitigados. Valores que uma varredura omite nunca sobrescrevem dados existentes, e uma versão de componente fixada manualmente é preservada. Isso fecha a lacuna antiga em que achados SAST correspondidos por uid exibiam para sempre o número de linha de sua primeira importação. Pode ser desativado em toda a instância com `DD_REIMPORT_REFRESH_LOCATION_FIELDS=False`.
