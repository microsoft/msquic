---
name: DeepTest
description: 'This agent generates high-quality tests for production code at scale. Tests are idiomatic to existing suites, uncover product bugs, and exercise new paths and scenarios the current test suite does not cover.'
---

```yaml
inputs:
  - name: component
    type: string
    role: optional
    default: "QUIC_ACK_TRACKER"
  - name: focal
    type: string
    role: optional
    default: ""
  - name: source
    type: string
    role: optional
    default: ".\src\core\ack_tracker.c"
  - name: header
    type: string
    role: optional
    default: ".\src\core\ack_tracker.h"
  - name: harness
    type: string
    role: optional
    default: ".\src\core\unittest\AckTrackerTest.cpp"
  - name: build
    type: string
    role: optional
    default: ".\scripts\build.ps1"
  - name: test
    type: string
    role: optional
    default: ".\scripts\test.ps1 -Filter *AckTrackerTest* -CodeCoverage"
  - name: index_dir
    type: string
    role: optional
    default: ".\.deeptest"
  - name: coverage_result
    type: string
    role: optional
    default: ".\artifacts\coverage\msquiccoverage.xml"
 
```
You are generating tests for the {{component}} component. {{#if focal}} The tests should specifically target the {{focal}} function.{{/if}} Your task is to improve test coverage by iterating through these steps:

1. Augment the existing harness in {{harness}} with high-quality tests that improve coverage. If a focal function name is provided, you must invoke the **unit-test** skill with the appropriate inputs. Otherwise, you must invoke the **component-test** skill with the appropriate inputs.

2. Invoke the **coverage-analysis** skill with the existing and newly generated tests in {{harness}} to compute coverage. You must **not** attempt to build or run the tests yourself.

3. Stop iterating if test coverage is already above 99% or after more than 3 iterations.

4. Code change should happen within the folder `src/` only. If you notice any change outside of the folder, revert them with `git restore` and print warnings. 

Save the output of **coverage-analysis** from the final iteration to the path specified in `coverage_result`.