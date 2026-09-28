---
title: "Cobalt.io API Import
"
toc_hide: true
---
> **⚠️ Deprecated — removed in DefectDojo 3.5.0.**
>
> The **Cobalt.io API Import** pull parser, and the **Tool Configuration** setup described below, are deprecated as of **3.2.0** and will be **removed in 3.5.0 (November 2026)**. See the [3.2 upgrade notes](/releases/os_upgrading/3.2/).
>
> **Migrate to:** the [Cobalt.io connector](/connectors/toolreference/cobalt_io/) (DefectDojo Pro), or import a Cobalt.io report as a [file](../../file/cobalt) — file import is not affected by this deprecation.

All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

In `Tool Configuration`, select `Tool Type` to "Cobalt.io" and `Authentication Type` "API Key".
Paste your Cobalt.io API token in the `API Key` field and the desired org token in the `Extras` field.
Currently Defect Dojo only supports [V1 API Keys](https://github.com/DefectDojo/django-DefectDojo/issues/12572).

In `Add API Scan Configuration` provide the ID
of the asset from which to import findings in the field `Service key 1`.
The ID can be found at the end of the URL when viewing the asset in your browser.

If you have more than one asset configured, you
must also select which Cobalt.io API Scan Configuratio to use.