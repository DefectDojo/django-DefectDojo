---
title: 安装
description: DefectDojo 支持多种安装方式。
draft: false
weight: 1
audience: opensource
aliases:
- /zh-hans/en/open_source/installation/installation
---

## **推荐选项**
---

### Docker Compose

请参阅 [DOCKER.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md>) 中的说明

### SaaS（包含支持并有助于项目发展）

[SaaS 链接](https://defectdojo.com/platform)

---
## **Docker 镜像变体**
---

DefectDojo 发布多种变体的 Docker 镜像：

| | AMD64 | ARM64 |
|---|---|---|
| **Debian** | ✅ 受支持 | ⚠️ 已进行单元测试 |
| **Alpine** | ⚠️ 社区维护 | ⚠️ 社区维护 |

**AMD64 上的 Debian** 是官方支持并经过测试的配置。所有 CI 测试（单元测试、集成测试和性能测试）都针对此组合运行。

**ARM64 上的 Debian** 会被构建，并在 CI 中接受单元测试的覆盖，但不会针对其运行集成测试和性能测试。

**Alpine** 变体会被构建并发布，但未被任何自动化测试覆盖。使用时风险自负。

---
## **勇敢者的选项（官方不支持）**
---
### Kubernetes

请参阅 [KUBERNETES.md](<https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md>) 中的说明

### 使用 godojo 进行本地安装

请参阅 godojo 代码库中 [README.md](<https://github.com/DefectDojo/godojo/blob/master/README.md>)
的说明

---

## 自定义设置

请参阅[配置](../configuration)
