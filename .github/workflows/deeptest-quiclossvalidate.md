---
description: Generate tests for QuicLossValidate using Copilot CLI with DeepTest custom agent
on:
  workflow_dispatch:
  pull_request:
    types: [opened, synchronize]
    branches:
      - master
permissions:
  contents: read
  pull-requests: read
  issues: read
strict: false
engine:
  id: custom
  steps:
    - name: Install Copilot CLI
      run: |
        gh extension install github/gh-copilot || echo "Copilot CLI already installed"
    - name: Run DeepTest via Copilot CLI
      env:
        GH_TOKEN: ${{ github.token }}
        COPILOT_GITHUB_TOKEN: ${{ secrets.COPILOT_TOKEN }}
      run: |
        echo "Invoking DeepTest custom agent for QuicLossValidate..."
        gh copilot --agent DeepTest -p "Generate comprehensive tests for the focal function QuicLossValidate in src/core/loss_detection.c. The function validates QUIC_LOSS_DETECTION internal state including SentPackets and LostPackets linked lists, PacketsInFlight counter, and tail pointers. Follow MsQuic test patterns in src/test/." --allow-all-tools
safe-outputs:
  create-pull-request:
    title-prefix: "[DeepTest] "
    labels: [automation, tests]
  noop:
---

{{#runtime-import agentics/deeptest-quiclossvalidate.md}}
