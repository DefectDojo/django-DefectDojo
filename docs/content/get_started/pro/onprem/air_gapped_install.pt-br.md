---
title: Instalando o DefectDojo Pro em um Ambiente Isolado (Air-Gapped)
description: Prepare os artefatos de instalação do DefectDojo Pro em um host com acesso
  à internet e depois transfira-os para uma rede isolada
draft: false
weight: 8
audience: pro
---

This page is a supplement to the installation instructions supplied with your DefectDojo Pro license. It covers only what changes when the target host has no route to the internet. Everything else, including the host prerequisites and the PostgreSQL setup, follows the standard instructions.

A abordagem usa dois hosts. Um host de preparação com acesso normal à internet baixa os artefatos de implantação e as imagens de contêiner. Em seguida, você move esses artefatos para a rede isolada usando o processo de transferência que seu ambiente permitir, e conclui a instalação no host de destino, que não tem acesso de rede ao DefectDojo.

Planeje manter o host de preparação acessível no futuro. As atualizações repetem o mesmo processo de transferência, então vale a pena mantê-lo.

## O que você precisa

No host de preparação, um host Linux com acesso à internet, Docker instalado e espaço em disco suficiente para o diretório de implantação mais as imagens de contêiner compactadas. As imagens representam a maior parte do espaço e chegam a várias centenas de megabytes cada uma.

No host isolado, Docker instalado e funcionando, e um servidor PostgreSQL já provisionado e acessível, ambos conforme as instruções de instalação padrão.

Em ambos, uma cópia do arquivo `dojo-compose-cli` e do seu arquivo de licença, conforme fornecidos pelo DefectDojo. Use a versão 2.1.0 ou posterior da CLI. Versões anteriores não têm modo isolado e, sem ele, a CLI tenta acessar o registro de contêineres a cada comando e falha com erros de resolução de nome em vez de informar o que está errado.

## Prepare os artefatos

Execute estas etapas no host de preparação.

### 1. Registre a CLI

Instale o Docker primeiro, caso ainda não esteja presente. Consulte a [documentação de instalação do Docker](https://docs.docker.com/engine/install/) para instruções específicas da sua distribuição.

Extraia o arquivo da CLI e, em seguida, registre-a:

```bash
sudo ./dojo-compose-cli register
```

O registro instala a CLI em `/usr/bin`, cria o grupo `dojosrv`, adiciona seu usuário aos grupos `dojosrv` e `docker`, valida a licença e autentica o Docker no registro de contêineres do DefectDojo.

Será solicitado um `DOJO_CLI_KEY`, que criptografa a configuração armazenada da CLI em disco. Defina-o no ambiente para evitar ser solicitado a cada comando:

```bash
export DOJO_CLI_KEY="your-key"
```

A nova associação a grupos não é aplicada ao seu shell atual. Abra uma nova sessão ou aplique os grupos na sessão atual:

```bash
newgrp docker
```

Confirme com `id` que tanto `docker` quanto `dojosrv` estão listados. Depois que seu usuário estiver no grupo `docker`, os comandos restantes não precisam de `sudo`.

Se o host de preparação acessa a internet por meio de um proxy HTTPS de saída, configure as variáveis de proxy antes de baixar qualquer coisa. Consulte [Executando o DefectDojo Atrás de um Proxy HTTPS de Encaminhamento](/onprem_deployment/forward_proxy/).

### 2. Defina a versão

Defina tanto a versão de implantação quanto a versão da aplicação para o release que você pretende instalar, substituindo `x.y.z`:

```bash
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli config set --version x.y.z
```

Use a mesma versão nos dois comandos e mantenha-a consistente pelo restante deste procedimento. Misturar versões entre os artefatos de implantação e as imagens produz uma stack que não inicia ou inicia com as imagens erradas.

### 3. Baixe os artefatos de implantação e as imagens

Baixe o diretório de implantação:

```bash
dojo-compose-cli deploy download
```

Isso popula `/opt/dojo` com o arquivo compose, a configuração do nginx, os modelos do rastreador de issues, o diretório de customizations e um subdiretório versionado para o release selecionado.

Em seguida, baixe as imagens de contêiner:

```bash
dojo-compose-cli app pull-images
```

Confirme o que chegou:

```bash
docker image ls
```

Anote o prefixo de repositório compartilhado pelas imagens do DefectDojo nessa saída. Você precisará dele na próxima etapa, e o conjunto de imagens varia entre releases, então extraia-o da sua própria saída em vez de presumir uma lista.

### 4. Registre a configuração gerada

A instalação padrão gera vários valores de configuração na primeira execução. Em uma instalação isolada, você os define manualmente no host de destino, então capture-os agora:

```bash
dojo-compose-cli environment print | head -n 9
```

Guarde a chave de criptografia de credenciais e a chave secreta. Ambas são strings aleatórias geradas com 64 caracteres, e a chave de credenciais em particular precisa corresponder à que foi usada quando as credenciais foram criptografadas, então registre-a com precisão e armazene-a como um segredo. Os valores de uwsgi e celery na mesma saída são úteis como ponto de partida para o host de destino.

Trate essa saída como sensível. Ela contém as chaves que protegem as credenciais armazenadas da sua implantação.

### 5. Empacote tudo

Crie um diretório para a transferência, usando a versão no nome para que o conteúdo fique inequívoco depois:

```bash
mkdir artifacts-x.y.z
cd artifacts-x.y.z
```

Compacte o diretório de implantação, preservando as permissões:

```bash
sudo tar -czvpf dojo-directory.tar.gz /opt/dojo
sudo chown "$USER:$USER" dojo-directory.tar.gz
```

Salve as imagens de contêiner. Este script usa o prefixo de repositório que você anotou na etapa 3, salva cada imagem correspondente e a compacta:

```bash
#!/bin/bash
set -u

REPO_FILTER="${1:?usage: save-images.bash <image-repository-prefix>}"
BACKUP_DIR="./defectdojo-pro-images"
mkdir -p "$BACKUP_DIR"

images=$(docker image ls --format "{{.Repository}}:{{.Tag}}" \
  | grep -v "<none>" | grep "$REPO_FILTER")

if [ -z "$images" ]; then
    echo "No images matched '$REPO_FILTER'."
    exit 1
fi

for full_image in $images; do
    filename_part="${full_image##*/}"
    dest_path="$BACKUP_DIR/${filename_part//:/_}.tar.gz"

    echo "Saving $full_image to $dest_path"
    docker save "$full_image" | gzip > "$dest_path"

    if [[ ${PIPESTATUS[0]} -eq 0 ]] && [[ ${PIPESTATUS[1]} -eq 0 ]]; then
        du -h "$dest_path" | awk '{print "  ok, " $1}'
    else
        echo "  failed, removing partial file"
        rm -f "$dest_path"
    fi
done
```

Torne-o executável e execute-o com seu prefixo:

```bash
chmod u+x save-images.bash
./save-images.bash <image-repository-prefix>
```

Verifique se cada imagem da etapa 3 gerou um arquivo e, em seguida, empacote o diretório:

```bash
cd ..
tar czvf artifacts-x.y.z.tar.gz artifacts-x.y.z
```

Mova `artifacts-x.y.z.tar.gz` para a rede isolada usando seu processo de transferência normal, junto com o arquivo da CLI e seu arquivo de licença, caso ainda não estejam lá.

## Instale no host isolado

### 6. Instale a CLI e ative o modo isolado

Extraia o arquivo da CLI e coloque a licença onde a CLI espera encontrá-la:

```bash
sudo mkdir /etc/defectdojo/
sudo cp dojopro.lic /etc/defectdojo/
```

Ative o modo isolado. Este é o primeiro comando de CLI que você executa neste host, e ele instala a CLI em `/usr/bin`, valida a licença a partir do arquivo e criptografa a configuração armazenada durante o processo:

```bash
sudo ./dojo-compose-cli config set --air-gapped true
```

Confirme que a alteração entrou em vigor:

```bash
dojo-compose-cli config print
```

A saída inclui `Air Gapped Deploy` definido como true. Defina também `DOJO_CLI_KEY` no ambiente aqui, para que os comandos seguintes não solicitem o valor.

Não execute `register` neste host. O registro existe para autenticar no registro de contêineres, que é inacessível por definição, e no modo isolado a CLI recusa o comando em vez de tentar executá-lo. O mesmo se aplica aos demais comandos que acessam o registro:

| Comando | Comportamento no modo isolado |
| --- | --- |
| `register` | Recusado. A autenticação no registro não está disponível. |
| `deploy download` | Recusado. Execute-o no host de preparação. |
| `app pull-images` | Recusado. Execute-o no host de preparação. |
| `app upgrade` | Recusado. Veja a seção de atualização abaixo. |
| `app start`, `app stop`, `app restart` | Disponível. Esses comandos não acessam o registro. |

Cada comando recusado é encerrado com uma mensagem que menciona o modo isolado, então uma recusa aqui é a CLI funcionando como esperado, não uma falha a ser diagnosticada.

Aplique sua nova associação a grupos antes de continuar:

```bash
newgrp docker
```

### 7. Restaure o diretório de implantação

Extraia o pacote de transferência e mova o arquivo de implantação para o lugar:

```bash
tar -xzvf artifacts-x.y.z.tar.gz
sudo cp artifacts-x.y.z/dojo-directory.tar.gz /opt/
```

A configuração da CLI pode ter criado um `/opt/dojo` quase vazio, contendo apenas a licença. Se ele existir, remova-o primeiro para que o arquivo não seja mesclado nele:

```bash
sudo ls -lah /opt/dojo
sudo rm -rf /opt/dojo
```

Extraia o diretório de implantação real e, em seguida, corrija a propriedade e as permissões de mídia:

```bash
cd /opt
sudo tar xzvf dojo-directory.tar.gz --strip-components 1
sudo chown -R dojosrv:dojosrv /opt/dojo
sudo chmod -R go+w /opt/dojo/media
```

### 8. Defina a configuração manualmente

Uma instalação isolada não usa a primeira instalação interativa, então defina os valores que ela normalmente geraria para você. Use as chaves que você capturou na etapa 4:

```bash
dojo-compose-cli environment add --key "DD_CREDENTIAL_AES_256_KEY" --value "<64-character-key-from-step-4>"
dojo-compose-cli environment add --key "DD_SECRET_KEY" --value "<64-character-key-from-step-4>"
```

Defina a versão para corresponder aos artefatos que você transferiu:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
```

Defina a URL do site e os hosts permitidos. A URL do site precisa ser o endereço que resolve para este host dentro da sua rede:

```bash
dojo-compose-cli environment add --key "DD_SITE_URL" --value "https://defectdojo.internal.example.com"
dojo-compose-cli environment add --key "DD_ALLOWED_HOSTS" --value "*"
```

Defina a conexão com o banco de dados, usando o servidor PostgreSQL que você provisionou anteriormente:

```bash
dojo-compose-cli environment add --key "DD_DATABASE_URL" --value "postgres://<db_user>:<db_password>@<db_host>:5432/<db_name>"
```

### 9. Carregue as imagens de contêiner

Este script carrega todos os arquivos de imagem no diretório de imagens:

```bash
#!/bin/bash
set -u

IMPORT_DIR="./defectdojo-pro-images"

if [ ! -d "$IMPORT_DIR" ]; then
    echo "Directory '$IMPORT_DIR' not found."
    exit 1
fi

files=$(ls "$IMPORT_DIR"/*.tar.gz 2>/dev/null)

if [ -z "$files" ]; then
    echo "No .tar.gz files found in $IMPORT_DIR."
    exit 1
fi

for file in $files; do
    echo "Loading $(basename "$file")"
    if docker load -i "$file"; then
        echo "  ok"
    else
        echo "  failed"
    fi
done
```

Execute-o de dentro do diretório de artefatos extraído:

```bash
chmod u+x load-images.bash
./load-images.bash
```

Em seguida, confirme com `docker image ls` que todas as imagens foram carregadas, na versão esperada.

### 10. Inicie a stack

Inicie a stack com a CLI. Isso funciona no modo isolado, já que o comando lê a configuração definida e opera o arquivo compose local sem contatar o registro:

```bash
dojo-compose-cli app start
```

`app stop` e `app restart` estão disponíveis da mesma forma. Use `app restart` após alterar qualquer valor de ambiente, pois ele recria os contêineres para que os novos valores sejam aplicados.

Duas coisas a verificar se a stack não subir. O comando precisa do diretório de implantação no lugar, então confirme que `/opt/dojo/docker-compose.yml` existe, conforme a etapa 7. E a versão configurada seleciona as tags de imagem, então ela precisa corresponder às imagens carregadas na etapa 9.

O DefectDojo fica então disponível no endereço definido como URL do site.

## Atualizando uma implantação isolada

`app upgrade` faz downloads do registro de contêineres, então é um dos comandos recusados pelo modo isolado. As atualizações seguem o mesmo caminho da instalação, em vez de serem conduzidas por um único comando.

No host de preparação, defina a nova versão e repita as etapas de 3 a 5 para ela. Transfira o novo pacote, carregue as novas imagens e, em seguida, no host isolado, defina a versão para a nova e reinicie:

```bash
dojo-compose-cli config set --version x.y.z
dojo-compose-cli config set --deploy-version x.y.z
dojo-compose-cli app restart
```

Duas coisas costumam pegar as pessoas de surpresa. Reiniciar sem alterar a versão configurada faz a stack voltar com as imagens que você já tinha, porque a versão seleciona as tags de imagem. E o conjunto de imagens pode mudar entre releases, então compare o que você carregou com o que o download da nova versão produziu, em vez de presumir que a lista anterior ainda se aplica.

Seu diretório de implantação existente não incorpora automaticamente o arquivo compose ou a configuração do nginx da nova versão, então restaure o novo conteúdo de `/opt/dojo` como você fez na etapa 7, preservando suas próprias customizations, certificados e mídia.

Faça backup do seu banco de dados antes de qualquer atualização e revise as [notas de atualização](/releases/os_upgrading/upgrading_guide/) de cada versão entre a sua atual e a de destino. Se você estiver muitos releases atrasado, entre em contato com o suporte antes de começar.

## Recursos que precisam de acesso de saída

Uma implantação isolada funciona sem nenhuma conectividade de saída, mas os recursos que acessam serviços externos não podem funcionar enquanto ela estiver desconectada. Isso se aplica aos conectores e integradores que buscam dados de ferramentas hospedadas na nuvem, às integrações com rastreadores de issues como o Jira, às notificações de saída para serviços como Slack e Microsoft Teams, e aos dados de enriquecimento de vulnerabilidades que normalmente são obtidos periodicamente.

Esses recursos são configurados por implantação, em vez de vir ativados por padrão, então uma instalação isolada não fica comprometida pela ausência deles. Se você ativar algum, espere que ele falhe com erros de resolução de nome ou de conexão até que a implantação tenha uma rota até aquele serviço. Quando o caminho de saída existe, mas passa por um proxy, consulte [Executando o DefectDojo Atrás de um Proxy HTTPS de Encaminhamento](/onprem_deployment/forward_proxy/).

### Dados de EPSS e KEV a partir de um espelho interno

O enriquecimento de EPSS e KEV é uma exceção que vale a pena configurar, porque não exige uma rota até a internet pública. Ambos são configurados no Tuner, em Finding Enrichment, e cada um tem seu próprio alternador de ativação e sua própria URL de consulta. Os campos de URL já vêm apontando para as fontes públicas, e você pode redirecioná-los para uma cópia hospedada dentro da sua própria rede.

O espelho precisa servir os mesmos arquivos no mesmo formato que as fontes públicas. As consultas buscam um arquivo específico na URL fornecida, em vez de descobrir o que está disponível ali, então um espelho que reempacota ou reorganiza os dados não funcionará. Atualize suas cópias na frequência que for adequada para você, já que a implantação só lê o que o seu espelho fornece.

## Dúvidas ou suporte

Para obter ajuda com uma instalação ou atualização isolada, entre em contato com seu representante de conta ou com [support@defectdojo.com](mailto:support@defectdojo.com).
