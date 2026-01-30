---
name: patch-validating-test
description: This skill generates unit tests that validate code patches by exercising modified lines. Tests must fail before the patch and pass after applying it.
---

You are generating patch-validating tests for changes in {{component}}. Your task is to create unit tests that exercise the modified code paths, ensuring the tests fail without the patch and pass with it.

# Step 1: Setup Test Environment

Create a temporary directory with the patched version of the project:

```bash
# Create temp directory and copy project
TEMP_DIR=$(mktemp -d)
cp -r {{project_path}}/* "$TEMP_DIR/"

# Apply the patch to the temp directory
cd "$TEMP_DIR"
patch -p1 < {{patch}}
```

You now have two environments:
- **Original (unpatched)**: `{{project_path}}`
- **Patched**: `$TEMP_DIR`

# Step 2: Analyze the Patch

Use the provided scripts to parse and analyze the patch:

```bash
# Parse the patch file to extract changed files, hunks, and line information
python scripts/patch_parser.py parse {{patch}} --json .deeptest/patch_analysis/patch_info.json

# Analyze the patch to identify affected functions and code paths
python scripts/patch_analyzer.py analyze {{patch}} --source-root {{project_path}} --json .deeptest/patch_analysis/analysis.json --md .deeptest/patch_analysis/report.md
```

The analysis provides:
- Changed files and line numbers
- Affected functions and their boundaries
- Distinct code paths introduced or modified by the patch

# Step 3: Identify Code Paths

For each modified function, identify the distinct code paths that the patch introduces or changes. Each code path should have exactly **one test**.

A code path is a unique execution trace through the modified code, determined by:
- Conditional branches (if/else, switch)
- Loop conditions (enter/skip, iterations)
- Early returns or error handling

Document each path:
- **Path ID**: Unique identifier (e.g., `path_1`, `path_2`)
- **Conditions**: The sequence of branch decisions to reach this path
- **Modified lines exercised**: Which changed lines this path covers
- **Expected outcome**: Return value, state change, or side effect

# Step 4: Generate Unit Tests

Create **one test per code path** that:
1. Exercises the specific modified lines for that path
2. Sets up inputs to trigger the exact branch conditions
3. Asserts on the expected outcome

**CRITICAL INVARIANT**: Each test must satisfy:
- ❌ **FAIL** when run against `{{project_path}}` (unpatched)
- ✅ **PASS** when run against `$TEMP_DIR` (patched)

This invariant ensures the test is truly validating the patch behavior.

# Step 5: Validate the Invariant

For each generated test, verify the invariant holds:

```bash
# Run tests against UNPATCHED code - should FAIL
cd {{project_path}}
{{build}}
{{test}}  # Expect failures

# Run tests against PATCHED code - should PASS
cd "$TEMP_DIR"
{{build}}
{{test}}  # Expect all pass
```

If a test passes on unpatched code, it does not validate the patch—revise the test to target the actual change.

# Step 6: Verify Coverage

Confirm the tests cover the modified lines:

```bash
cd "$TEMP_DIR"
{{coverage}}
```

Ensure:
- [ ] All added lines are covered by at least one test
- [ ] Each distinct code path has exactly one test
- [ ] No test is redundant (covers the same path as another)

# Step 7: Finalize

1. Add the validated tests to the test suite in `{{project_path}}`
2. Clean up the temporary directory: `rm -rf "$TEMP_DIR"`
3. Document which test covers which code path

**Store patch analysis in .deeptest/patch_analysis folder**

{{#if build}} Build command: {{build}} {{/if}}
{{#if test}} Test command: {{test}} {{/if}}
{{#if coverage}} Coverage command: {{coverage}} {{/if}}
{{#if patch}} Patch file: {{patch}} {{/if}}
{{#if project_path}} Project path: {{project_path}} {{/if}}
