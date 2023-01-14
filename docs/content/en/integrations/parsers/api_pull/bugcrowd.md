---
title: "Bugcrowd API"
toc_hide: true
---
In `Tool Configuration`, select `Tool Type` to "Bugcrowd API" and `Authentication Type` "API Key".
Paste your BlackDuck API token in the `API Key` field.
Set your API key directly in the format `username:password` in the API Token input, it will be added to the header `'Authorization': 'Token {}'.format(self.api_token),`

For each product, you can configure 2 things:
- `Service key 1`: the bugcrowd program code (it's the slug name in the url for the program, url safe)
- `Service key 2`: the bugcrowd target name (the full name, it will be url-encoded, you can find it in https://tracker.bugcrowd.com/<YOURPROGRAM>/settings/scope/target_groups)
    - It can be left empty so that all program submissions are imported

That way, per product, you can use the same program but separate by target, which is a fairly common way of filtering/grouping Bugcrowd.
Adding support for a 3rd filtering would be possible with `Service Key 3`, feel free to make a PR.
