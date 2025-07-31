---
title: "Files"
description: "Report uploaded to DefectDojo as files"
weight: 2
type: docs
chapter: true

cascade:
- type: "blog"
  # set to false to include a blog section in the section nav along with docs
  toc_root: true
  _target:
    path: "/blog/**"
- type: "docs"
  _target:
    path: "/**"
exclude_search: true
---
