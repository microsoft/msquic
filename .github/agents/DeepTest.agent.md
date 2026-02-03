---
name: DeepTest
description: 'This agent generates high quality tests for production code at scale. Tests are idiomatic to existing suites, uncover product bugs and test new paths and scenarios that the existing test suite does not cover.'
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
You are generating tests for the {{component}} component. {{#if focal}}  The test should specifically target the {{focal}} function.{{/if}} Your task is to augment the existing harness found in {{harness}} with high quality tests that improve coverage.

If a focal function name is provided, you must invoke the **unit-test** skill with the appropriate inputs. Otherwise, you must invoke the **component-test** skill with the appropriate inputs.
