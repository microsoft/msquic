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
  bash: ["pwsh"]
---

# Hello World Agentic Workflow

Run the PowerShell script `scripts/helloworld.ps1` and report the output.

## Steps

Run the script using: `pwsh scripts/helloworld.ps1`
