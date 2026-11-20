---
title: "Pull a simple report from the API"
# The page that embeds this prompt with {{< prompt "simple-report" >}}.
page: "/metrics_reports/reports/PRO__report_builder_llm"
weight: 30
---
An AI assistant (such as Claude, ChatGPT or Copilot) can write a short script that pulls a simple report straight from the [API](/automation/api/api-v2-docs/): a list of Findings, Assets or counts that you can send to a spreadsheet, a chat channel or a dashboard. Give it the prompt below, and describe the report you want in place of the bracketed example. The example, open Critical and High Findings past their SLA, is only an idea to start from. The prompt lists the API details that assistants usually get wrong, such as pagination and the filter names.

```text
Write a [Python 3] script, using the requests library, that pulls this report
from my DefectDojo instance:

  [Describe the report you want. For example: for every product, the open
  Critical and High findings that are past their SLA, oldest breach first.]

Output it as [a CSV file], with a link to each finding.

Facts about the DefectDojo API. Follow them exactly:
- Base URL: [https://dojo.example.com]. Use only /api/v2/ endpoints.
- Header: "Authorization: Token <key>", with the key read from the DD_API_KEY
  environment variable.
- The UI may say "Asset" and "Organization". The API says "product" and
  "product_type".
- Every list endpoint is paginated: the response has "count", "next" and
  "results". Use limit=100 and follow "next" until it is null. Never assume one
  page holds everything.
- GET /api/v2/products/ returns the products (id, name).
- GET /api/v2/findings/ returns findings. Filters it accepts include:
    product=<id>             (one or more product ids, comma-separated)
    prod_type=<id>           (one or more product type ids, comma-separated)
    severity=Critical,High   (comma-separated, case-sensitive)
    active=true              (open findings only)
    outside_of_sla=1         (past SLA. This already excludes inactive,
                              mitigated, false-positive, duplicate, out-of-scope
                              and risk-accepted findings)
    o=<field>                (sort order, for example o=sla_expiration_date)
- For any other filter, read the parameters of GET /api/v2/findings/ in the
  schema at [https://dojo.example.com]/api/v2/oa3/schema/?format=json. Never
  guess a filter name: an unknown filter is ignored, so the script silently
  returns every finding.
- The API only returns what the token's user is allowed to see, so the report
  covers that user's products only.
- Link format for a finding: [https://dojo.example.com]/finding/<id>
- Query with filters, not one request per finding. Sleep briefly between pages
  and stop with a clear message on HTTP 401 or 403.

Before you write the script, restate the report and list the endpoints and
filters you will use, so I can correct them.
```

Every endpoint and filter is also listed in the interactive documentation at `/api/v2/oa3/swagger-ui/` on your instance.
