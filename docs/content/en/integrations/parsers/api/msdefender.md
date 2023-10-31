---
title: "MS Defender Vulnerability REST API"
toc_hide: true
---
All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

Before you get started, you have to register an App with the API rights "Machine.Read.All" and "Vulnerability.Read.All" inside your Microsoft Azure Account.

In `Tool Configuration`, select `Tool Type` to "MSDefender API" and `Authentication Type` "Username/Password".
Paste your tenantid in the `Extras` field, the AppId in the `User` field and the secret value in the `password` field.

Within an Engagement configuration you have to provide the added API Scan Configuration. In `Add API Scan Configuration` you don't have to do anything.