#!/bin/bash
# Creates a new branch from the current branch, stages src/ changes, and commits them.
# Usage: ./scripts/create-commit-for-safe-outputs.sh <branch-name>

set -euo pipefail

BRANCH_NAME="${1:?Usage: $0 <branch-name>}"

# 1. Create a new branch from the current branch
git checkout -b "$BRANCH_NAME"

# 2. Stage only src/ changes
git add src/

# 3. Commit
git commit -m "add generated test changes"

# 4. List files in the commit
echo "Files in commit:"
git diff-tree --no-commit-id --name-only -r HEAD
