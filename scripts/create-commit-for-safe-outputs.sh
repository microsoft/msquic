#!/bin/bash
# Stages src/ changes, and commits them.
# Usage: ./scripts/create-commit-for-safe-outputs.sh

set -euo pipefail

# 2. Stage only src/ changes
git add src/

# 3. Commit
git commit -m "add generated test changes"

# 4. List files in the commit
echo "Files in commit:"
git diff-tree --no-commit-id --name-only -r HEAD
