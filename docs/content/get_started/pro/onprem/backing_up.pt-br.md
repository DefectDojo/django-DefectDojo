---
title: Fazendo Backup de uma Implantação Autogerenciada
description: As quatro coisas a capturar, onde cada uma reside em implantações Compose
  e Kubernetes, e como confirmar que um backup pode realmente ser restaurado
draft: false
weight: 12
audience: pro
---

Uma implantação é mais do que seu banco de dados. Um backup que captura apenas o banco de dados restaura um sistema que funciona, mas que está sem os arquivos enviados e não consegue descriptografar as credenciais que mantém para suas outras ferramentas. Esta página aborda o que capturar, onde cada parte reside e como confirmar que o resultado é restaurável.

## As quatro coisas a capturar

O banco de dados armazena suas organizações, ativos, engajamentos, testes, achados, usuários e configuração.

Os arquivos enviados residem fora do banco de dados. Capturas de tela, modelos de ameaça, documentos de aceitação de risco e anexos semelhantes ficam em um sistema de arquivos, e o banco de dados armazena apenas os caminhos para eles.

A configuração de implantação é o que faz a aplicação voltar a funcionar da mesma forma, incluindo suas próprias customizations e certificados TLS.

As chaves de criptografia são a parte mais frequentemente esquecida. A chave de criptografia de credenciais é o que torna legíveis as credenciais armazenadas para suas ferramentas conectadas. Restaure um banco de dados sem ela e essas credenciais ficam intactas, porém indecifráveis, o que significa que cada integração precisa ser reinserida manualmente.

## O banco de dados

A maioria das implantações autogerenciadas aponta para um serviço PostgreSQL gerenciado, que é o padrão do chart e a configuração recomendada. Nesse caso, use os backups automatizados e a recuperação point-in-time do próprio provedor, em vez de criar sua própria solução. Duas coisas valem a pena verificar em vez de presumir: se os backups automatizados estão de fato ativados na instância, já que um banco de dados gerenciado com backups desativados não tem nenhum, e se a janela de retenção corresponde ao que sua organização exige.

Onde você mesmo executa o PostgreSQL, faça um dump compactado em formato customizado:

```bash
pg_dump -h <db_host> -U <db_user> -Fc <db_name> > defectdojo-$(date +%F).dump
```

Restaure-o com `pg_restore`, usando `--no-owner` e `--no-privileges` se o destino tiver roles diferentes das da origem:

```bash
pg_restore -v --no-owner --no-privileges -h <db_host> -U <db_user> -d <db_name> defectdojo-<date>.dump
```

Faça o dump periodicamente, armazene-o fora da máquina que o gerou e mantenha gerações suficientes para sobreviver a um problema que você não perceba imediatamente.

## Arquivos enviados

Em uma implantação com Docker Compose, os arquivos enviados ficam no diretório `media`, dentro do seu diretório de implantação no host. Faça backup desse caminho com seu backup de sistema de arquivos normal. Se você moveu esse diretório para um armazenamento separado, faça backup desse sistema de arquivos, e não do ponto de montagem.

No Kubernetes, o volume de mídia é provisionado de acordo com o backend de armazenamento configurado, e o local físico onde os dados residem determina como protegê-los:

| Backend de armazenamento | Onde os dados residem | Como protegê-los |
| --- | --- | --- |
| `efs` | Um sistema de arquivos Amazon EFS | AWS Backup |
| `filestore` | Uma instância do Google Filestore | Backups do Filestore |
| `gcsfuse` | Um bucket do Cloud Storage | Versionamento de bucket, ou uma cópia agendada para outro bucket |
| `nfs` | Seu servidor NFS | O que quer que proteja esse servidor |
| `pvc` | Um volume da sua storage class | Um snapshot de volume CSI, se o seu driver oferecer suporte |

O chart provisiona o volume, mas não protege o conteúdo. Não há agendamento de snapshot embutido nele, então o backup precisa vir da plataforma ou das suas próprias ferramentas.

## Configuração e chaves

No Compose, capture seu diretório `customizations`, seu diretório `certs` e a configuração e os valores de ambiente armazenados pela CLI. `config print` e `environment print` mostram o que está definido.

No Kubernetes, capture seus arquivos values e o conteúdo dos secrets referenciados pelo seu release.

Em ambos os casos, mantenha a chave de criptografia de credenciais e a chave secreta em algum lugar durável e separado, em um gerenciador de segredos, e não junto com o backup. Qualquer pessoa que tenha tanto o banco de dados quanto a chave de credenciais pode ler as credenciais de todas as ferramentas conectadas, então elas não devem viajar juntas.

## O que não é um backup

O chart anota suas persistent volume claims para que sobrevivam a um `helm uninstall`, o que é ativado por padrão. Isso é uma proteção contra uma desinstalação acidental, não um backup. Não ajuda em nada contra corrupção, uma exclusão dentro da aplicação ou uma atualização que dá errado, porque em todos esses casos o volume sobrevive e o dano está nele.

Snapshots mantidos apenas na mesma conta ou projeto da implantação são igualmente mais frágeis do que parecem. O que quer que consiga excluir a implantação geralmente também consegue excluir esses snapshots.

## Confirmando que um backup é restaurável

Um backup que ninguém restaurou é apenas uma suposição. Teste-o em um ambiente descartável, em vez de sobrepor a produção, e verifique o seguinte:

1. Faça login e confirme que suas organizações, ativos, engajamentos, testes e achados estão presentes nas quantidades esperadas.
2. Abra um achado com um anexo e baixe-o. Isso é o que comprova que a restauração de mídia funcionou, já que o banco de dados sozinho mostraria o anexo listado, mas falharia ao entregá-lo.
3. Abra uma conexão de ferramenta configurada e confirme que suas credenciais estão intactas. Isso é o que comprova que você restaurou corretamente a chave de criptografia de credenciais, e é a verificação com maior probabilidade de revelar uma lacuna.
4. Confirme que os usuários e grupos foram transferidos corretamente. Configurações de autenticação, como SSO, geralmente precisam ser reconfiguradas para um ambiente diferente, então trate diferenças nesse ponto como esperadas, e não como uma falha na restauração.

Execute esse exercício periodicamente, e não apenas quando precisar dele. Fazer uma restauração pela primeira vez durante um incidente é onde os planos de backup costumam falhar.

## Dúvidas ou suporte

Para obter ajuda no planejamento de backups da sua implantação, ou se uma restauração não funcionar como esperado, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com).
