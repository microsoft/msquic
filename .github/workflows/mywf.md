---
on:
  workflow_dispatch:
  issues:
    types: [opened]
permissions:
  contents: read
  issues: read
  pull-requests: read
tools:
  github:
    toolsets: [default]
---

# Create a PR

Create a new file named `test-create-pr.txt` in the repository with the content `This is a test file.` and create a pull request to merge this change into the `master` branch. Include Run-Id in the PR body.