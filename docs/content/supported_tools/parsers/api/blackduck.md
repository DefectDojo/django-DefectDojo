---
title: "Blackduck API"
toc_hide: true
---
> **⚠️ Deprecated — removed in DefectDojo 3.5.0.**
>
> The **BlackDuck API** pull parser, and the **Tool Configuration** setup described below, are deprecated as of **3.2.0** and will be **removed in 3.5.0 (November 2026)**. See the [3.2 upgrade notes](/releases/os_upgrading/3.2/).
>
> **Migrate to:** the [Black Duck connector](/connectors/toolreference/black_duck/) (DefectDojo Pro), or import a Black Duck report as a [file](../../file/blackduck) — file import is not affected by this deprecation.

All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

In `Tool Configuration`, select `Tool Type` to "BlackDuck API" and `Authentication Type` "API Key".
Paste your BlackDuck API token in the `API Key` field.

In `Add API Scan Configuration` provide the ID
of the project from which to import findings in the field `Service key 1`.
Provide the version of the project from which to import findings in the field `Service key 2`.