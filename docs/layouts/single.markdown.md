{{- /*
  <page>/index.md: the page's source as plain Markdown, for AI assistants and
  the "Copy page as Markdown" button (layouts/_partials/main/page-actions.html).
  The body is the raw source with the site's shortcodes turned into plain
  Markdown: highlight becomes a fenced code block, each tab becomes a bold
  label, and quiz (interactive only) is dropped. Root-relative links and the
  images/ paths the image render hook resolves to /images/ become absolute, so
  the file still works once it is copied out of the site.
*/ -}}
{{- $base := strings.TrimSuffix "/" site.BaseURL -}}
{{- $md := .RawContent -}}
{{- $md = replaceRE `\{\{<\s*highlight\s+(\S+)\s*>\}\}` "```$1" $md -}}
{{- $md = replaceRE `\{\{<\s*/highlight\s*>\}\}` "```" $md -}}
{{- $md = replaceRE `\{\{<\s*tab\s+"([^"]*)"\s*>\}\}` "\n**$1**\n" $md -}}
{{- $md = replaceRE `\{\{<\s*/?tabs?(\s+"[^"]*")?\s*>\}\}` "" $md -}}
{{- $md = replaceRE `\{\{<\s*quiz\s[^>]*>\}\}` "" $md -}}
{{- $md = replaceRE `\n{3,}` "\n\n" $md -}}
{{- $md = replaceRE `\]\(/` (printf "](%s/" $base) $md -}}
{{- $md = replaceRE `\]\((\.\./)*images/` (printf "](%s/images/" $base) $md -}}
{{- $title := .Title -}}
{{- with .Params.audience }}{{ if eq . "opensource" }}{{ $title = printf "%s (Open Source)" $title }}{{ else if eq . "pro" }}{{ $title = printf "%s (Pro)" $title }}{{ end }}{{ end -}}
# {{ $title }}
{{ with .Description }}
> {{ . | plainify | replaceRE `\s+` " " | strings.TrimSpace }}
{{ end }}
Source: {{ .Permalink }}

{{ $md | strings.TrimSpace }}
