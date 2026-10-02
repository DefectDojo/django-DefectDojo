---
title: "Vulners"
toc_hide: true
---
> **⚠️ Deprecated — removed in DefectDojo 3.5.0.**
>
> The **Vulners** pull parser, and the **Tool Configuration** setup described below, are deprecated as of **3.2.0** and will be **removed in 3.5.0 (November 2026)**. See the [3.2 upgrade notes](/releases/os_upgrading/3.2/).
>
> **Note:** unlike the other deprecated API-pull parsers, Vulners has no file-based parser and there is currently no Vulners connector, so there is no drop-in replacement. If you rely on this integration, you can [request a connector](/connectors/upstream/about/#request-a-connector-from-the-ui-defectdojo-pro-cloud) (DefectDojo Pro Cloud) before 3.5.0.

All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

Import Vulners [Audit](https://vulners.com/docs/API_wrapper/linux_audit/#linux-audit) results, no file required.

In `Tool Configuration`, select `Tool Type` to "Vulners" and add the API Key

In the `Product` settings select `Add API Scan Configuration` and select the previously added Vulners `API Tool Configuration`.

After this is done, you can import the findings by selecting "Vulners" as the scan type.

Detailed installation steps can be found in [vulners documentation](https://vulners.com/docs/plugins/defectdojo/).

Use following [instructions](https://vulners.com/docs/apikey/) to generate Vulners API Key.

More details about DefectDojo-plugin integration can be found at [vulners integrations page](https://vulners.com/plugins).
