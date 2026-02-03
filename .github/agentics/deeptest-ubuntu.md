<!-- This prompt will be imported in the agentic workflow .github/workflows/deeptest-ubuntu.md at runtime. -->
<!-- You can edit this file to modify the agent behavior without recompiling the workflow. -->

# DeepTest: Generate Tests for User-Specified Source File

This workflow invokes the Copilot CLI with the DeepTest custom agent to generate comprehensive tests for a source file specified by the user.

## Input

- **source_file**: The relative path to a source file in this repository (e.g., `src/core/connection.c`)
- **Default (PR trigger)**: `src/core/loss_detection.c`

## Instructions for DeepTest Agent

1. **Analyze the source file** at the path provided via `${{ github.event.inputs.source_file }}` (or default `src/core/loss_detection.c` for PR triggers)
2. **Identify testable functions** in the file
3. **Generate comprehensive test cases** following MsQuic test patterns in `src/test/`
4. **Consider edge cases** including:
   - Empty/null inputs
   - Boundary conditions
   - Error paths
   - State transitions
   - Resource cleanup
5. **Create a PR** with all generated test files, including the workflow run ID `${{ github.run_id }}` in the PR title

## MsQuic Test Conventions

- Tests are located in `src/test/lib/` (helper classes) and `src/test/bin/` (functional tests)
- Use C++ wrappers around C API for convenience
- Follow existing patterns like `TestConnection`, `TestStream`, `TestListener`
- Use `TEST_QUIC_SUCCEEDED()` and `TEST_TRUE()` macros for assertions

## Safe Outputs

When successfully complete:
- If tests were generated: Use `create-pull-request` with the generated test code. The PR title will automatically include the run ID.
- **If DeepTest agent is unavailable or failed**: Call the `noop` safe output explaining the failure
