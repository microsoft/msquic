---
name: DeepTest
description: 'This agent generates high-quality tests for production code at scale. Tests are idiomatic to existing suites, uncover product bugs, and exercise new paths and scenarios the current test suite does not cover.'
---

```yaml
inputs:
  - name: component
    type: string
    role: optional
    default: ""
  - name: focal
    type: string
    role: optional
    default: ""
  - name: harness
    type: string
    role: optional
    default: ""
  - name: index_dir
    type: string
    role: optional
    default: ".\.deeptest"
  - name: coverage_result
    type: string
    role: optional
    default: ".\artifacts\coverage\msquiccoverage.xml"
 
```
You are generating tests for the {{component}} component. {{#if focal}} The tests should specifically target the {{focal}} function.{{/if}} Your task is to keep generating high quality tests and checking the coverage until the coverage reaches 95%, please improve test coverage by iterating through these steps:

1. Augment the existing harness in {{harness}} with high-quality tests that improve coverage. If a focal function name is provided, you must invoke the **unit-test** skill with the appropriate inputs. Otherwise, you must invoke the **component-test** skill with the appropriate inputs.

2. Compute test coverage using `scripts/make-coverage.sh`
  - The 1st input to the script is a google gtest pattern to match tests in {{harness}}.
  - The 2nd input to the script is the output path for the coverage report. You should use temporary paths in this form `/tmp/gh-aw/coverage-result-<iteration>.xml`.
  - You must **not** attempt to build or run the tests yourself. Rely on the script to do this and return the coverage results.

3. Stop iterating if test coverage is already above 95%.

4. Code change should happen within the folder `src/` only. If you notice any change outside of the folder, revert them with `git restore` and print warnings. 

Save the coverage report from the final iteration to the path specified in `coverage_result`.