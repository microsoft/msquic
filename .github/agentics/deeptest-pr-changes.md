<!-- This prompt will be imported in the agentic workflow .github/workflows/deeptest-pr-changes.md at runtime. -->
<!-- Edit this file to tweak agent behavior without recompiling the workflow. -->

# DeepTest: Generate Tests for PR-Changed Files

This workflow invokes the Copilot CLI with the DeepTest custom agent to generate tests focused on the files changed in a pull request.

## Inputs

- **pr_number**: Pull request number (required for workflow_dispatch; inferred for pull_request runs)
- **max_files**: Max number of changed files to consider (default: 10)
- **include_regex / exclude_regex**: Filters applied to changed file paths

## Instructions for DeepTest Agent

You are operating on a PR branch checkout.

1. Read the list of changed files provided in the prompt (and/or the `$CHANGED_FILES` environment variable).
2. Prioritize source files under `src/` that affect QUIC behavior (core, platform, datapath, crypto, etc.).
3. Generate or update tests following MsQuic test patterns in `src/test/`.
   - Prefer adding focused tests for behavior changes and bug fixes.
   - Cover negative/error paths and boundary conditions.
   - Avoid brittle tests that depend on timing.
4. If a changed file is not testable directly (e.g., platform glue), add tests at the closest testable layer.
5. Create a single PR containing all new/updated test files.
   - Include the workflow run ID `${{ github.run_id }}` in the PR title.

## MsQuic Test Conventions

- Tests live in `src/test/lib/` (helpers) and `src/test/bin/` (functional tests)
- Prefer existing helper patterns (`TestConnection`, `TestStream`, `TestListener`)
- Use `TEST_QUIC_SUCCEEDED()` / `TEST_TRUE()` style assertions

## Safe Outputs

- If tests were generated: Use `create-pull-request` with the changes.
- If nothing to do / cannot proceed: Use `noop` and explain why.
