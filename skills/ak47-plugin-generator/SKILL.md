---
name: ak47-plugin-generator
description: Generate AK47 plugin YAML from vulnerability details using the official syntax docs. Use this skill for plugin authoring, conversion, or refinement.
---

# AK47 Plugin Generation

## Overview

Generate AK47 plugin YAML using the official syntax docs. Focus on correctness, minimal defaults, and a closed exploitation flow.

## Language Handling

Apply these internationalization rules:

- If the user explicitly requests a language, follow it.
- Otherwise, detect language from the latest user message.
- If Chinese and English are mixed, prefer the language used for the primary task description.
- Keep the output language consistent within a single response.
- Use the matching syntax doc:
  - Chinese: [references/SYNTAX.zh.md](references/SYNTAX.zh.md)
  - English: [references/SYNTAX.en.md](references/SYNTAX.en.md)

## Workflow

1. Scope the plugin.
   - Collect vendor/product, vulnerability name, exploit type (U/C/D/M), and protocol (http/tcp/udp/ws/websocket).
   - Define the expected outcome (command output, file download, upload verification, memshell confirmation).
2. Map the attack chain.
   - List request sequence, required headers/cookies/tokens, and extraction points.
   - Identify what must be stored in `vars` for reuse.
3. Design defaults.
   - Provide minimal but runnable `default` values.
   - Do not add parameters that are not used by the exploit flow.
4. Build rules.
   - Each rule performs one step and has explicit success conditions.
   - Use `vars` in rules to capture dynamic data for later steps.
5. Compose `expr`.
   - Orchestrate the rule flow and ensure it returns a boolean.
6. Validate structure.
   - Use `plugin_check` when MCP is available.
   - Also re-check all fields against the selected syntax doc.
   - Ensure template strings use only `{{}}` interpolation.

## Required Rules

- File naming format: `Product/VulnName#Type.yml` where Type is `U/C/D/M`.
- `default` must only use allowed fields from syntax docs.
- Request templates only allow `{{}}` interpolation.
- `expr` must be boolean and orchestrate rule flow.
- For MemShell plugins, use [assets/MemShell.json](assets/MemShell.json) to select valid tool/server/method combinations.

## Output Conventions

- Output only the final YAML unless the user asks for explanations.
- Keep tags concise and relevant.

## Resources

- [references/SYNTAX.zh.md](references/SYNTAX.zh.md): Chinese syntax doc.
- [references/SYNTAX.en.md](references/SYNTAX.en.md): English syntax doc.
- [assets/MemShell.json](assets/MemShell.json): Local memshell mapping.
