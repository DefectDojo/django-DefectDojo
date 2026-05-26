# DefectDojo UI Migration Notes

## Project Goal
Replace/stabilize UI styling architecture.
NOT a full redesign.

## Core Constraints
- Keep Bootstrap 3 structure
- Keep DataTables
- Preserve templates
- Preserve layout behavior

## Migration Rules

Prefer reusing existing semantic tokens before creating new ones.

Only create new tokens when:
- a true semantic distinction exists
- AND the distinction is visually/functionally meaningful

Avoid token duplication and token sprawl.

## CSS File Responsibilities

### dojo.css
Legacy compatibility layer.

### open-props-theme.css
Semantic tokens only.

### bootstrap-bridge.css
Bootstrap-to-token mappings.

### component-overrides.css
Isolated modernizations only.

## High Risk Areas
- Tables
- Forms
- Sidebar layout
- Bootstrap grid

## Safe Early Changes
- Colors
- Typography
- Buttons
- Severity styles
- Panel styling

## Migration Strategy
1. Tokenization
2. Bootstrap bridge
3. Incremental overrides
4. QA/stabilization

## Semantic Token Philosophy

Tokens should represent intent, not appearance.

Preferred:
- --color-success
- --color-panel-heading-bg
- --color-commercial-hover

Avoid:
- --blue-2
- --dark-gray
- --orange-border

Goal:
- enable theming
- preserve semantic meaning
- reduce visual drift
- centralize UI decisions

## Token Categories

### Foundation Tokens
Base primitives:
- text colors
- border colors
- spacing
- radii

### Semantic Tokens
Reusable UI meaning:
- success
- danger
- warning
- info
- highlight

### Component Tokens
Component-scoped surfaces:
- panel-heading-bg
- filter-header-bg
- tag-bg

### Domain Tokens
Business/context-specific:
- commercial-bg
- benchmark-pass
- benchmark-fail

## Current Migration Status

Completed:
- severity tokenization
- panel styling tokenization
- highlight system tokenization
- support/commercial styling tokenization
- navigation/tab tokenization
- dropdown/action tokenization

In Progress:
- spacing normalization
- radius modernization
- Bootstrap bridge mapping

Pending:
- component override isolation
- responsive audit
- accessibility audit