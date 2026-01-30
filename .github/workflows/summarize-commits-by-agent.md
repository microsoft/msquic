---
description: Summarize the latest 10 commits and count new features, updates, and bug fixes.
on:
  push:
    branches:
      - 'meiyang/**'
  workflow_dispatch:
permissions: read-all
tools:
  github:
    toolsets: [default]
safe-outputs:
  noop:
---

{{#runtime-import agentics/summarize-commits-by-agent.md}}
