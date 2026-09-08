---
title: "Import SBOM"
description: "Upload SBOMs for PSIRT matching without navigating to each product first."
draft: false
weight: 3
pro-feature: true
---

PSIRT answers "am I vulnerable to this advisory?" by comparing each advisory's
affected version ranges against your dependency inventory. That inventory comes
from SBOMs, so getting them in is the first step.

There are two ways to do it, and they suit different moments.

## From the product page

Each product's page has an SBOM import that attaches the document to that
product. This is the right tool when you are already looking at the product you
want to update.

## From PSIRT → Import SBOM

A build usually produces several SBOMs at once, and visiting each product in turn
to upload them is the slow part. The **Import SBOM** page takes the whole set:

1. Drop one or more SBOM files, or use **Choose**. Up to 25 files at a time.
2. Each file is read far enough to see what it says it describes — CycloneDX's
   own `metadata.component`, or an SPDX document's name and described package —
   and matched against the products you have permission to import into.
3. Confirm the product for each file. Where the document is unambiguous, the
   match is pre-filled and the **Why** column says how it was reached (an exact
   name, a normalized name, or one of several possible matches). Where it is not,
   the row asks rather than guessing.
4. Press **Import**.

Supported formats are **CycloneDX** (JSON/XML) and **SPDX** (JSON, XML, and
tag-value).

Two properties of this page are deliberate:

- **Nothing is written until you press Import.** The inspection step reads the
  files and suggests; it creates no dependencies and modifies no product.
- **A suggestion is never applied on its own.** A wrong suggestion costs you a
  correction in a dropdown, not a wrong inventory.

You can only import into products you already have import permission for, and
the suggestion list is scoped the same way — the page will not offer you a
product you cannot write to.

## Replace or merge

**Replace existing dependencies** applies to every file in the batch. When on,
dependencies absent from the new import are removed unless they are linked to
findings. When off, the import merges into what is already recorded. Leave it off
when you are adding a component SBOM alongside others; turn it on when the SBOM
is the complete, current picture for that product.

## What happens next

Imported dependencies become part of the inventory that PSIRT matching reads. The
next matching pass compares open advisories against the new inventory, so an
import can change the answer on an advisory you looked at yesterday — which is
the intended behavior, not a caching bug.
