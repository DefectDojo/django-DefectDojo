# Translated documentation

The docs site is multilingual. English is the source of truth; every other
language is a translation of an English page and is regenerated from it.

## How translations are stored

Translations live **beside** their English page using Hugo's filename-suffix
layout:

```
content/get_started/about/about_defectdojo.md      <- English (source)
content/get_started/about/about_defectdojo.de.md   <- German
```

We deliberately do not use a per-language `contentDir`, because that would
require moving all 466 English pages into `content/en/` and would break
existing tooling and any open docs PR.

A translated page keeps the English page's `slug`, `weight`, `aliases`, and
`audience` values, so URLs, ordering, and the Open Source / Pro version
toggle behave identically in every language. Only `title`, `description`,
`summary`, and the body text are translated.

## What is translated

The core guides: `get_started`, `import_data`, `triage_findings`,
`asset_modelling`, `metrics_reports`, `issue_tracking`, `admin`, `automation`,
`help`, `navigation`, and the site home page. 160 pages, about 102,000 words.

Deliberately **not** translated:

- `releases/` changelogs - they change with every release, and stale
  translations of a changelog are worse than an English one.
- `supported_tools/` parser reference - 219 pages that are mostly tables,
  scanner names, and CWE/CVE identifiers, which are the same in any language.
- `archived_docs/`.

Navigation entries for untranslated sections point at the English URL, so
nothing in the nav 404s in a translated language.

## Site chrome

UI text that lives in templates rather than content (navigation labels,
homepage cards, footer, screen-reader labels) is looked up with Hugo's
`i18n` function and translated in `i18n/<lang>.toml`. English values are in
`i18n/en.toml`; adding a key there without adding it to every language is
safe (missing keys fall back to English).

Terminology comes from the product UI catalogs (`dojo/locale/<lang>/`), so a
severity or status word reads the same in the docs as it does in DefectDojo.

## Adding a language

Languages are added to `config/_default/languages.toml` **only once their
translated content exists** - the switcher must never offer a language with
nothing behind it. Per language you need:

1. `content/**/<page>.<lang>.md` for the translated pages.
2. `i18n/<lang>.toml` for the chrome strings.
3. `config/_default/menus/menus.<lang>.toml` - translated labels, same URLs,
   prefixed with `/<lang>` for sections that exist in that language.
4. The `[<lang>]` block in `languages.toml`, plus
   `languageDirection = "rtl"` for Arabic, Hebrew, Persian, and Urdu.

The pipeline that produces 1-3 is the `i18n-translate` skill: it exports
pages to JSON, fans translation out to per-language agents, and applies the
results only after checking that code fences, shortcodes, link URLs, heading
structure, and protected frontmatter survived unchanged.

## Keeping translations current

**Refresh quarterly.** English pages change constantly; a translation that
silently rots tells non-English readers we do not care about them. The
refresh is incremental - export only the pages whose English source changed
since the last run:

```bash
export_docs.py --content content --work <work> --langs de \
    --changed-since <git-ref-of-last-refresh>
```

Everything downstream is unchanged, because pages are addressed by path.

## Provenance

These translations are machine-generated and integrity-checked (structure,
tokens, and terminology are verified automatically), but they have **not**
been reviewed by native speakers. Treat a native-speaker pass as the next
step for any language you intend to promote heavily.
