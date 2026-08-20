---
title: 在 OpenShift 上部署 DefectDojo Pro
description: 在 OpenShift 上部署自托管 DefectDojo Pro 时的特有事项:安全上下文约束、Route 和 ReadWriteMany
  存储
draft: false
weight: 8
audience: pro
---

DefectDojo Pro 可在 OpenShift 4.x 上运行,包括 OpenShift Container Platform、ROSA 和 OKD。

本页是对随 DefectDojo Pro 许可证提供的安装指南的补充。该指南包含完整的安装流程,其中有专门的 OpenShift 章节。本页介绍 OpenShift 特有的不同之处,以便您了解开始之前需要准备什么,以及这些平台特定设置会带来怎样的效果。

您的许可证材料中提供了一个 OpenShift 引导脚本。它会安装到现有集群中,并处理本页所述的大部分内容,包括存储、`fsGroup` 值、Route 以及安装本身。该脚本是幂等的,重复运行会复用其已创建的内容,并且支持演练模式,可打印将要执行的操作而不做任何实际更改。无论您使用该脚本还是自行执行安装,本页其余内容均适用。

## 安全上下文约束

DefectDojo Pro 在默认的 `restricted-v2` SCC 下运行。您无需为服务账户授予 `anyuid`、`privileged` 或任何其他提升权限的 SCC。

在针对 OpenShift 进行配置后,DefectDojo Pro 全程以非特权安全上下文运行。容器以无特权方式运行,不能提升权限,并放弃所有能力(capabilities)。用户 ID 由 OpenShift 从分配给您命名空间的范围中指定,而不是固定为某个会被 SCC 拒绝的 UID。

如果 Pod 因未通过 SCC 验证而被拒绝,通常的原因是部署未针对 OpenShift 进行配置,而不是需要额外授予某项约束。

## 存储必须为 ReadWriteMany

Django 和 Celery worker 的 Pod 会读写同一批媒体文件,即上传的扫描文件、截图和生成的报告。它们需要共享卷,因此对于多节点部署而言,ReadWriteOnce 存储是不够的。

在 OpenShift 上,默认方式是针对集群的默认 StorageClass 创建 PersistentVolumeClaim。当默认存储类支持 ReadWriteMany 时(在以 OpenShift Data Foundation 或 NFS 为后端的集群上通常如此),这种方式即可正常工作。对于默认存储类为 ReadWriteOnce 的多节点部署,请改为配置以 NFS 为后端的存储。

### 以 NFS 为后端存储时的 fsGroup

OpenShift 会将 `fsGroup` 限制在分配给命名空间的范围之内。当您使用 NFS 或 EFS 存储时,必须提供该范围内的值,否则卷挂载会因权限错误而失败。

从命名空间注解中读取该范围的起始值,并将其用作 `fsGroup`:

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

该注解中包含一个以起始值和长度表示的范围。请使用起始值。这一步仅在使用 NFS 和 EFS 存储时需要,默认的 PersistentVolumeClaim 方式不需要。

## Route、TLS 与 Cookie

在 OpenShift 上,DefectDojo Pro 通过 Route 而非 Ingress 对外暴露,采用边缘 TLS 终止,并从 HTTP 重定向。

在 ROSA 上,Route 主机名的生成格式为 `<release-name>-<namespace>.apps.<cluster-domain>`,因此 `dojopro` 命名空间中名为 `dojopro` 的发布版本会得到 `dojopro-dojopro.apps.<cluster-domain>`。可通过以下命令获取集群的 apps 域名:

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

集群 apps 域名下的主机名由默认通配符证书覆盖,无需额外配置证书。对于任何其他主机名,请提供您自己的证书,并为该 Route 主机名添加 CNAME 记录。

请在 OpenShift 上将 `dojo.secureCookies` 设置为 `false`。在边缘终止的 Route 中,TLS 在路由器处终止,路由器到 Pod 之间的连接是普通 HTTP,因此标记为 secure 的 Cookie 永远不会被送回,导致登录失败。只要 Route 在边缘终止 TLS,这一设置就是必须的,而非可选项。

## 资源配置文件

提供三种资源配置文件供您在安装时选择。`minimal` 适用于开发、CI 和测试;`standard` 适用于中等负载下的生产环境;`performance` 适用于高负载生产环境,并会启用自动扩缩容。

请通过配置文件设置资源规模,而不是逐项覆盖数值,这样您自己的配置文件就不会与之冲突。

## 开始之前

您已登录的 OpenShift 4.x 集群,并且本地可用 `oc`、`helm`、`openssl` 和 `jq`。

一个命名空间,如果使用 NFS 或 EFS 存储,还需要该命名空间的 supplemental-groups 注解值。

一个可提供 ReadWriteMany 的默认 StorageClass,或一台 NFS 服务器的详细信息。

除评估用途外均需要 PostgreSQL 16。开发环境可使用内置的 PostgreSQL,但在投入生产运行之前,应迁移到外部托管数据库。

您的 DefectDojo Pro 许可证文件。

您计划使用的 Route 主机名。

## 出站网络访问

在有出站限制的集群中,请允许通过 443 端口向托管 DefectDojo Pro 镜像的容器镜像仓库发出出站 HTTPS 请求。镜像仓库的主机名可在随许可证提供的安装指南中找到。镜像仓库的端点位于负载均衡器之后,其地址会发生变化,因此应放行主机名而非固定地址。

集群还需要能够通过 PostgreSQL 端口访问您的数据库。

可利用性数据丰富功能为可选项,需要额外通过 443 端口访问两个目标。EPSS 评分来自 `api.first.org`,CISA KEV 数据来自 `www.cisa.gov`。两者均由内容分发网络提供服务,其地址会发生变化,因此应放行相应主机名。如果不放行,DefectDojo 仍可正常运行,只是发现项不会附加 EPSS 或 KEV 数据。

如果出站流量通过代理而非直连,请参阅[在正向 HTTPS 代理后运行 DefectDojo](/onprem_deployment/forward_proxy/)。

## 初始化作业必须先完成

安装过程会运行一个 Kubernetes 作业,用于应用迁移、创建管理员用户并加载初始数据。该过程大约需要十五分钟。在其完成之前,管理员用户尚不存在,即便此时 Route 已经能够响应,您也无法登录。

可通过以下方式查看其状态:

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

当 `oc get job` 显示 `1/1` 个完成数时,该作业即已完成。

其他 Pod 会通过一个 init 容器等待初始化作业完成。数据库初始化完成后,您可以将 `dojo.skipInitContainer` 设置为 `true`,以便在后续升级时跳过这一等待。

## 验证

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

然后打开 Route 主机名并登录。

## 故障排查

### Pod 被安全上下文约束拒绝

部署很可能未针对 OpenShift 进行配置,因而回退到了固定某个 SCC 不允许的用户 ID 的默认设置。授予 `anyuid` 或 `privileged` 并不能解决问题,也并非必需。

### 登录后被重定向回登录页面

这是因为在边缘终止的 Route 后面,`dojo.secureCookies` 仍为 `true`。请将其设置为 `false` 并升级。

### NFS 上的卷挂载权限错误

这是因为 `fsGroup` 超出了命名空间允许的范围。请读取 supplemental-groups 注解,并使用该范围的起始值。

### 出现 Multi-Attach 错误,或 Pod 卡在 ContainerCreating 状态

这是因为该卷为 ReadWriteOnce,而有多个 Pod 试图挂载它。请检查该声明及其对应的存储类:

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

请改用支持 ReadWriteMany 的存储类,或改用以 NFS 为后端的存储。

### 浏览器中出现证书警告

默认的 Route TLS 使用集群的通配符证书,该证书仅覆盖集群 apps 域名下的名称。对于任何其他主机名,请提供您自己的证书。

### 查看日志

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

如需更详细的输出,`config.logLevel` 和 `celery.logLevel` 均可设置为 `DEBUG`。

## 升级

升级遵循标准流程。请参阅[升级 DefectDojo Pro(本地部署)](/get_started/pro/onprem/upgrading/)。

## 问题或支持

如需获取 OpenShift 部署方面的帮助,请联系您的客户代表或 [support@defectdojo.com](mailto:support@defectdojo.com)。
