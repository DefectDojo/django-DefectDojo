---
title: "Reimport scans from a CI/CD pipeline"
# The page that embeds this prompt with {{< prompt "ci-reimport" >}}.
page: "/import_data/import_intro/reimport"
weight: 10
---
If you use an AI assistant (such as Claude, ChatGPT or Copilot) to write CI/CD jobs, give it the prompt below. Fill in the bracketed values first. The prompt lists the API details that assistants usually get wrong, so the job it writes keeps one Test up to date instead of creating a new Test on every run.

```text
Write a [GitHub Actions / GitLab CI / Jenkins / Azure DevOps] job that sends the
results of [Trivy] to DefectDojo after every build of the [main] branch.

Facts about the DefectDojo API. Follow them exactly:
- Base URL: [https://dojo.example.com]. Use only endpoints under /api/v2/.
  Never use /api/vue/ paths; they reject API tokens.
- Authenticate with the header "Authorization: Token <key>". Read the key from a
  CI secret named DD_API_KEY. Never print it.
- Use POST /api/v2/reimport-scan/ with multipart/form-data. Do NOT use
  /api/v2/import-scan/: import creates a new Test every run, so findings pile up.
  Reimport updates one Test and creates it on the first run.
- Send these fields:
    scan_type           = "[Trivy Scan]"   (exact string from the DefectDojo
                                            parser list; it is case-sensitive)
    file                = the report file
    product_type_name   = "[Engineering]"
    product_name        = "[my-service]"
    engagement_name     = "[CI/CD]"
    test_title          = "[Trivy]"        (one Test per scanner)
    auto_create_context = true             (creates the product and engagement
                                            on the first run)
    branch_tag, commit_hash, build_id      = from the CI environment variables
- The UI may call a product an "Asset" and a product type an "Organization".
  The API still uses product_name and product_type_name.
- close_old_findings already defaults to true on reimport (findings missing from
  the report are closed). Leave it on unless the scan covers only part of the
  service.
- Success is HTTP 201. On any other status, print the response body and fail.
- On HTTP 409, another import into the same Test is still running: wait a minute
  and retry once.
- Do not retry on a client timeout without checking first. The server may still
  be processing the first request.

Also show the curl command on its own so I can test it locally first.
```

Check the result before you run it in your pipeline. In particular, confirm that `scan_type` matches the name on the tool's [parser page](/supported_tools/parsers/).
