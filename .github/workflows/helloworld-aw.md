---
name: Hello World Agentic
description: Run helloworld.ps1 script using Copilot agent

on:
  workflow_dispatch:
  pull_request:
    branches:
      - master

runs-on: ubuntu-24.04

tools:
  bash:
---

# Hello World Agentic Workflow

Run the PowerShell script `scripts/helloworld.ps1` and report the output.

## Steps

1. First install PowerShell:
   ```bash
   sudo apt-get update && sudo apt-get install -y wget apt-transport-https software-properties-common
   wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
   sudo dpkg -i packages-microsoft-prod.deb
   sudo apt-get update && sudo apt-get install -y powershell
   ```

2. Run the script using: `pwsh scripts/helloworld.ps1`

3. Report the output in a summary
