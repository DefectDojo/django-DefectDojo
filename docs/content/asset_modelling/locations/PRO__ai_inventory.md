---
title: "AI Inventory"
description: "See the AI in every scanned repository: coding assistants, MCP servers, models, AI packages, AI services, agent skills and AI provider keys"
weight: 9
audience: pro
---

**AI Inventory** lists the AI found in every repository DefectDojo scans. It covers coding assistants and their rules files, MCP servers, models, AI SDKs and agent frameworks, AI service endpoints, agent skills, and the AI provider keys that secret scanning finds. Each component is a [Dependency Location](../pro__working_with_sboms/) identified by a Package URL, so it shows up in component search and in SBOM exports, and it can be governed with [AI Governance Policies](/triage_findings/findings_workflows/pro__ai_governance_policies/).

> AI Inventory requires the Locations feature. Turn it on with the **AI Inventory and Governance** flag (beta) on the [Feature Flags page](/admin/feature_flags/pro__feature_flags/). Inventories that arrive while the flag is off are still stored and appear once it is on.

## Where Inventories Come From

The inventory comes from the `ai-inventory` scanner in the DefectDojo scan action and in Sensei hosted scans. It needs no setup: every default-branch scan detects AI in the repository and uploads it to the Asset as a CycloneDX 1.6 document, through the same `/api/v2/sbom-import/` endpoint that SBOM uploads use.

Detection is deterministic. The scanner reads files, manifests and lockfiles, and compares packages against a curated list of AI packages. It calls no model and runs nothing from the repository. It records what is in the repository and never what a developer did.

A pull request scan does not change the Asset's inventory. It reports which AI components the pull request adds, so a reviewer sees a new MCP server before it merges.

Other SBOMs count as well. When you [import an SBOM](../pro__working_with_sboms/) from another tool, DefectDojo marks the AI packages in it (OpenAI, Anthropic, LangChain and so on) using the same package list.

## What Is Detected

| Kind | Found through | Recorded as |
|---|---|---|
| **Coding assistants** | Rules and config files: `CLAUDE.md`, `.claude/`, `AGENTS.md`, `.cursorrules`, `.cursor/`, `.github/copilot-instructions.md`, `.windsurfrules`, `.clinerules`, `.continue/`, `.aider.conf.yml`, `.gemini/`, `GEMINI.md`, `.codex/` | One component per assistant, with the files that prove it |
| **MCP servers** | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.json`, `.gemini/settings.json`, `.windsurf/mcp.json`, `.codex/config.toml`, `mcp_config.json`, `claude_desktop_config.json` | The real npm or PyPI package when the server runs with `npx` or `uvx`, a service for a remote server, and the config key that declares it |
| **Models** | Model ids in SDK calls, `from_pretrained(...)`, Ollama `Modelfile`s, MLflow model URIs, and model files in the tree (`.gguf`, `.safetensors`, `.onnx`, `.pt`) | Hugging Face models by `pkg:huggingface/...`, others by provider and id, model files with their SHA-256 |
| **AI packages** | Manifests and lockfiles for npm, PyPI, Go, Maven, NuGet, Cargo and RubyGems | The package's own Package URL and version, marked as an SDK, agent framework, MCP SDK, ML framework or inference server |
| **AI services** | Provider API hosts in code and config (OpenAI, Anthropic, Google, Azure OpenAI, AWS Bedrock, Mistral, Groq, Cohere) and self-hosted Ollama or vLLM | A service with its endpoint (scheme, host and port only) |
| **Agent skills** | Every directory with a `SKILL.md` | One component per skill |
| **AI provider keys** | Secret scanning (Gitleaks) findings for OpenAI, Anthropic, Hugging Face, Groq, Cohere and Perplexity keys | Not a component: the Findings are tagged `ai-secret` and counted on the page |

### What Is Never Recorded

Evidence is a file path, a config key or a line number. The scanner never stores the arguments or environment values of an MCP server, and DefectDojo drops any evidence that looks like a credential or an environment reference before storing it. Co-author trailers such as `Co-Authored-By: Claude` are read into a single yes-or-no answer per Asset (**AI-assisted commits**) and no author is recorded.

A default-branch scan clones one commit, so AI-assisted commits can be missed on that scan. A pull request scan sees the pull request's commits. Once the answer is yes, it stays yes for the Asset.

## Where to Find It

- **Locations > AI Inventory** lists every AI component on the Assets you can see.
- On an Asset, open **Locations > View AI Inventory** to see that Asset's components.

Across the top, seven tiles count coding assistants, MCP servers, models, AI packages, AI services, agent skills and AI provider keys. Click a tile to filter the table to that kind. The AI provider keys tile opens the Findings list filtered to `ai-secret`. Below the tiles, the authorization counts (authorized, unauthorized, needs review) and the **Shadow AI only** toggle filter the table to what no policy has allowed.

Each row shows the component's kind, category, provider, authorization decision and evidence. Expand a row to see why it has that decision: the policy that decided it, the policy's scope and justification, or that no policy matched. If the decision raised a Finding, the row links to it. On an Asset, the page also shows whether AI-assisted commits were seen, and the branch and commit of the last inventory.

The page follows your permissions. You see a component when you can see its Asset.

## Using the API

The inventory is available to automation with an API token:

```http
GET /api/v2/ai_inventory/?ai_kind=mcp-server&authorization=unauthorized
GET /api/v2/ai_inventory/summary/?product=12
```

Filters include `ai_kind`, `ai_category`, `authorization`, `shadow`, `provider_exact`, `product` and `product_type`. To upload an inventory yourself, post a CycloneDX document to `/api/v2/sbom-import/`. Name `defectdojo-ai-inventory` in `metadata.tools`, and pass `source_ref` (branch@commit) to record where it came from.

## Related

- [AI Governance Policies](/triage_findings/findings_workflows/pro__ai_governance_policies/): decide which AI components are allowed.
- [Exporting an AIBOM](../pro__exporting_an_aibom/): export the inventory as a CycloneDX AI bill of materials.
