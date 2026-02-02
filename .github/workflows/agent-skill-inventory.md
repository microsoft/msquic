---
description: Inventory custom agents and skills in the repository and report to a GitHub Discussion
on:
  workflow_dispatch:
  pull_request:
    types: [opened, synchronize]
    branches:
      - meiyang/installaw
permissions:
  contents: read
  discussions: read
tools:
  github:
    toolsets: [default]
safe-outputs:
  create-discussion:
    max: 1
    title-prefix: "${{ github.workflow }} report"
    category: General
  noop:
---

{{#runtime-import agentics/agent-skill-inventory.md}}
