---
title: Guia de Atualização do DefectDojo Pro
description: Atualize uma instalação existente do DefectDojo Pro via Helm, incluindo
  baixar o chart, executar a atualização e fazer a reversão
draft: false
weight: 14
audience: pro
aliases:
- /pt-br/get_started/pro/onprem/upgrading/
---

<!--
  Gerado a partir do repositório do chart Helm do DefectDojo Pro.
  Fonte: docs/UPGRADE_GUIDE.md na versão 3.1.304 do chart.
  Edite o guia de origem, não este arquivo. Edições locais são substituídas
  na próxima vez que o chart for lançado.
-->
Aborda a atualização de uma instalação existente do DefectDojo Pro para uma versão mais recente do chart.
O caminho recomendado é obter o chart diretamente do registro OCI do DefectDojo — sem necessidade de extração de zip. O fluxo de trabalho com zip empacotado usado na instalação também funciona para atualizações e está documentado abaixo.

Este guia aborda:

- [Antes de Atualizar](#before-you-upgrade)
- [Origem do Chart: Registro OCI](#chart-source-oci-registry)
- [Autenticar no Registro](#authenticate-to-the-registry)
- [Atualizar via Registro OCI (recomendado)](#upgrade-via-oci-registry-recommended)
- [Atualizar via Zip Extraído](#upgrade-via-extracted-zip)
- [Atualizar com ArgoCD](#upgrade-with-argocd)
- [Verificar a Atualização](#verify-the-upgrade)
- [Reversão](#rollback)
- [Solução de Problemas](#troubleshooting)

---

## O Que uma Atualização Abrange

Uma versão do DefectDojo Pro é composta por uma versão do chart, um conjunto de versões de imagens de container e os arquivos de configurações do Pro. Eles são construídos e testados juntos e precisam avançar juntos. Atualizar as tags de imagem isoladamente não é suportado e quebrará a implantação.

O mesmo vale para as configurações. Um novo `pro_settings.py` é lançado em quase todas as versões. Nunca leve uma cópia adiante em uma atualização, e nunca aplique patches manuais em uma versão antiga: a aplicação precisa executar o `pro_settings.py` que corresponde à sua versão. Suas próprias personalizações pertencem ao `local_settings.py`, que é preservado entre atualizações e é o único dos dois que você deve editar.

Usar o chart cuida disso para você. Ele envia e monta o `pro_settings.py` correspondente junto com o seu `local_settings.py`, então não há nada para copiar ou migrar manualmente.

## Antes de Atualizar

Toda atualização deve começar da mesma forma. Pular essas etapas é a causa mais comum de atualizações malsucedidas.

1. **Leia as notas de versão** de cada versão entre sua versão atual e a versão de destino. Alterações que quebram compatibilidade, novos campos obrigatórios e pré-requisitos de migração são destacados ali. A página de release do GitHub de cada tag tem um link para o changelog.
2. **Verifique sua versão atual do chart.** Esse é o piso para a atualização:

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **Faça backup do seu banco de dados.** Atualizações de chart podem incluir migrações do Django que alteram o esquema. Faça um dump lógico (ou um snapshot em nível de armazenamento) da instância PostgreSQL antes de prosseguir.
4. **Tenha seus arquivos values disponíveis.** O comando de atualização precisa passar o mesmo preset de plataforma, preset de perfil e arquivo de values do cliente usados na instalação. Arquivos de values ausentes ou desatualizados causam diffs inesperados.
5. **Confirme que as referências de secrets ainda existem.** Se você instalou com `--set dojo.existingSecret=...` ou `--set license.existingSecret=...`, verifique se esses secrets do Kubernetes ainda estão presentes no namespace.
6. **Renderize a atualização localmente primeiro** para detectar campos ausentes, valores inválidos ou erros de template antes de mexer no cluster:

   ```bash
   helm template dojopro $CHART_REF \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/<size>.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     > /tmp/dojopro-upgrade-render.yaml
   ```

   `$CHART_REF` é a referência OCI (veja abaixo) ou o caminho do chart extraído.

> Defina `NAMESPACE` uma vez — todo comando neste guia usa `$NAMESPACE`:
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **O padrão de política de rede mudou.** As NetworkPolicies agora são regidas por
> `networkPolicy.profile`, cujo padrão é `standard`: todo o tráfego de saída, além do
> tráfego de entrada entre os próprios pods desta versão, é permitido (o tráfego de entrada externo continua
> restrito ao caminho de ingress). Isso é mais permissivo do que a antiga
> lista de permissões de saída sempre granular. Para manter o comportamento restrito, defina
> `networkPolicy.profile: aggressive` e revise as exceções
> (`nodeLocalDns`, `dnsSelectors`, `externalAPIs`) — veja
> [Políticas de Rede](/get_started/pro/onprem/installing_on_kubernetes/#network-policies).

> **Requisito de banco de dados do orquestrador.** O orquestrador (`ddorch`) usa um
> segundo banco de dados chamado `<main-db-name>-ddorch` e o cria na inicialização, caso
> ele não exista. Se sua role de aplicação não tiver `CREATEDB`, crie-o previamente
> (`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`) antes de atualizar
> para uma versão do chart que habilite o ddorch — caso contrário, o pod do ddorch falhará com
> `permission denied to create database (SQLSTATE 42501)`. Veja
> [Pré-verificação: Banco de Dados do Orquestrador (ddorch)](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

> **Padrão de renomeação Organization/Asset.** `dojo.V3EnableOrganizationAssetRelabel`
> agora tem como padrão `null` (automático): fica **habilitado em instalações novas** e **desabilitado
> em atualizações**, então a renomeação na UI (Organization/Asset substituindo
> ProductType/Product) nunca é ativada inesperadamente em uma versão existente. Para
> habilitar em uma versão já atualizada, defina `dojo.V3EnableOrganizationAssetRelabel: true`
> explicitamente; um `true`/`false` explícito sempre prevalece sobre o padrão automático.

---

## Origem do Chart: Registro OCI

O chart é publicado no DefectDojo GCP Artifact Registry como um artefato
OCI:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Cada versão é marcada com a versão do chart (por exemplo, `2.57.2`). A
versão do chart corresponde à versão da aplicação em `Chart.yaml`, então a tag que você passa
para `helm upgrade --version` é o mesmo número de versão mostrado na
release do GitHub.

Liste as versões de chart disponíveis:

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **Por que OCI para atualizações?** Os presets (`presets/platforms/*.yaml`,
> `presets/profiles/*.yaml`) são empacotados dentro do chart. Referenciar
> o chart pela sua URL OCI baixa automaticamente as versões corretas de preset para o chart
> de destino — sem etapa de reextração, sem presets desatualizados.

---

## Autenticar no Registro

O registro é privado. O Helm precisa estar autenticado antes de conseguir baixar o
chart. Use uma chave de conta de serviço do GCP ou um token de acesso de curta duração fornecido
pelo suporte do DefectDojo.

**Opção A — chave JSON de conta de serviço:**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**Opção B — login interativo do gcloud (para humanos com acesso ao registro):**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

Tokens de acesso do `gcloud auth print-access-token` expiram após uma hora.
Execute novamente `helm registry login` se você ver um `401 Unauthorized` durante a
atualização.

> **Ambientes air-gapped / com firewall:** se os nós do seu cluster conseguem alcançar
> `us-south1-docker.pkg.dev`, mas sua estação de trabalho não, use o
> fluxo de trabalho com zip extraído abaixo. O fluxo de trabalho OCI só funciona quando o host
> que executa `helm upgrade` consegue alcançar o registro.

---

## Atualizar via Registro OCI (recomendado)

Aponte o `helm upgrade` diretamente para a URL OCI e fixe a versão do chart com
`--version`. Todos os arquivos de values, flags `--set` e flags `--set-file` são os
mesmos usados na instalação original.

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Os caminhos de preset de plataforma e perfil acima são `presets/platforms/...`
> (sem o prefixo `$CHART/`). Quando o Helm baixa um chart do OCI, os presets ficam
> dentro do chart baixado, mas o `-f` aqui aponta para **cópias locais** desses
> arquivos. Se você não mantiver cópias locais dos presets, extraia o chart
> primeiro com `helm pull oci://... --version $VERSION --untar` e referencie-os
> a partir do diretório extraído — ou use o fluxo de trabalho com zip extraído.

**Variante com secrets inline + arquivo de licença:**

```bash
helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Sempre fixe a `--version`. Omiti-la baixa qualquer tag para a qual o registro
> resolver no momento do comando — não é repetível, nem
> auditável. Fixe a versão para que reexecuções, reversões e resposta a incidentes
> sempre referenciem o mesmo artefato.

---

## Atualizar via Zip Extraído

Para estações de trabalho que não conseguem alcançar o registro OCI, ou para clientes que
preferem preparar o chart como um arquivo local, o zip empacotado da release do GitHub
funciona da mesma forma na atualização que na instalação. A
única diferença em relação à instalação é o verbo do comando (`helm upgrade` em vez de
`helm install`).

1. Baixe `dojo-pro-helm-bundled-<version>.zip` (e a assinatura destacada
   `.asc`) da release do GitHub.
2. Verifique a assinatura usando a chave pública
   (`dojo-pro-release-signing.asc`) conforme documentado no guia de instalação.
3. Extraia o chart para um **caminho com versão** para que os presets não colidam com
   extrações anteriores:

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. Execute a atualização usando o caminho do chart extraído — mesmos arquivos de values e
   flags da sua instalação original:

   ```bash
   helm upgrade dojopro $CHART \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/standard.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     --set-file ddorch.tls.rootCa=orch_ca.crt \
     --set-file ddorch.tls.cert=orch_server.crt \
     --set-file ddorch.tls.key=orch_server.key \
     --wait --timeout 15m
   ```

> **Reextraia a cada atualização.** Os arquivos de preset evoluem entre versões
> do chart. Reutilizar uma extração antiga fixa silenciosamente sua atualização nos
> valores padrão antigos dos presets.

---

## Atualizar com ArgoCD

Quando o DefectDojo Pro é gerenciado pelo ArgoCD, a atualização é uma única alteração em
`targetRevision` no spec da Application. Os presets de plataforma e perfil
são versionados dentro do chart, então eles são atualizados em conjunto.

```yaml
spec:
  source:
    repoURL: us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2
    chart: dojopro
    targetRevision: <chart-version>    # bump this
    helm:
      valueFiles:
        - presets/platforms/aws-eks.yaml
        - presets/profiles/standard.yaml
      values: |
        # your environment-specific values
      parameters:
        - name: dojo.existingSecret
          value: dojopro-secrets
        - name: license.existingSecret
          value: dojopro-license
```

Sincronize a Application depois de editar o `targetRevision`. O ArgoCD baixará o
novo chart do registro OCI e fará a reconciliação.

> O ArgoCD precisa de suas próprias credenciais para o registro OCI. Configure o secret
> do repo com `type: helm` e `enableOCI: "true"`. Veja a
> [documentação de Helm OCI do ArgoCD](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support)
> para o formato exato do Secret.

---

## Verificar a Atualização

Depois que o `helm upgrade` retornar (ou o ArgoCD reportar Synced / Healthy), confirme
que a nova revisão está no ar:

```bash
# Chart revision bumped and status is deployed
helm list -n $NAMESPACE

# All pods Running and Ready — expect django, celery worker/beat,
# connectors, ddorch, ddorch-workers, and (if enabled) mcp-server
kubectl get pods -n $NAMESPACE

# Migrations succeeded — the initializer job should show Completed
kubectl get jobs -n $NAMESPACE

# App version matches the target
kubectl get deployment -n $NAMESPACE \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

Acesse a página de login para confirmar que a UI sobe e que o usuário admin consegue
se autenticar. Para verificações programáticas, o endpoint `/login/` retorna 200
quando a aplicação está saudável.

---

## Reversão

O Helm mantém o histórico de releases por revisão. Se a atualização causar regressão de comportamento,
reverta para a revisão anterior:

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **Migrações de banco de dados não são revertidas.** O rollback do Helm restaura o
> estado do manifesto (imagens, configs, secrets), mas não executa
> `migrate --revert`. Se a atualização aplicou uma migração de esquema que você precisa
> reverter, restaure a partir do backup feito em
> [Antes de Atualizar](#before-you-upgrade) ou combine uma reversão manual
> da migração com o suporte do DefectDojo antes de reverter a
> release do Helm.

Usuários do ArgoCD podem reverter revertendo a alteração de `targetRevision` no
git (ou via `argocd app rollback`) e sincronizando.

---

## Solução de Problemas

**`401 Unauthorized` ao baixar o chart.**
O token de acesso expirou. Execute novamente `helm registry login` com um
`gcloud auth print-access-token` atualizado.

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`.**
Um selector ou outro campo imutável foi alterado. O chart fixa labels de
selector estáveis, então isso geralmente significa uma edição anterior feita diretamente em um
Deployment. Capture o diff, exclua o recurso problemático e execute novamente
a atualização para que o Helm o recrie.

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`.**
O Helm 4 usa server-side apply, que rastreia a propriedade dos campos. Esse erro
significa que outro gerenciador — `kubectl edit`, `kubectl scale`, ou o controlador
HPA (`kube-controller-manager`) — alterou um campo que o Helm renderiza,
mais comumente `.spec.replicas`. Retome a propriedade uma vez:

```bash
helm upgrade ... --force-conflicts
```

Versões do chart com essa correção omitem `replicas` de Deployments cujo HPA
está habilitado, então o escalonamento do HPA não entra mais em conflito com as atualizações. Se você
escalonou manualmente um Deployment com `kubectl`, prefira ajustar o valor
correspondente de `replicas`/`horizontalpodautoscaler` para que o
chart continue sendo o proprietário.

**`Error: UPGRADE FAILED: timed out waiting for the condition`.**
Os pods não atingiram o estado Ready dentro da janela de `--timeout`. Inspecione a
carga de trabalho lenta:

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

Causas comuns: falhas ao baixar a imagem (autenticação do registro), migração de esquema
ainda em execução (aumente o `--timeout`), ou probes de readiness falhando contra um
FQDN mal configurado.

**O preset mudou entre versões e meu arquivo de values agora está em conflito.**
Renderize novamente com `helm template` (veja [Antes de Atualizar](#before-you-upgrade))
e reconcilie suas substituições com os novos padrões do preset antes de
executar `helm upgrade`.

**`values don't meet the specifications of the schema ... got string, want boolean`.**
Um valor de liga/desliga na sua substituição está entre aspas. O Helm trata `"false"` como uma
string não vazia, e uma string não vazia é truthy, então o recurso estava
sendo ativado quando a intenção era desativá-lo. O schema agora rejeita
a forma entre aspas em vez de deixá-la passar. Remova as aspas:

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

A mensagem de erro indica o caminho problemático. `false`, `no` e `off` sem aspas
são todos interpretados como um booleano de verdade e são aceitos.
