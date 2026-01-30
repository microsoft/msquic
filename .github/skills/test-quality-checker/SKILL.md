---
name: test-quality-checker
description: This skill evaluates the quality of a single test by analyzing assertion strength, mutant detection ability, coverage differential, and test design quality. Outputs a structured JSON assessment.
---

You are evaluating the quality of a test. Your task is to analyze the test and produce a JSON quality assessment.

# Inputs

- **Source file**: {{source_file}}
- **Test harness**: {{test_harness}}
- **Test name**: {{test_name}}
- **Build command** (optional): {{build}}
- **Test command with Coverage** (optional): {{coverage}}

# Step 1: Extract Test Information

Use the provided scripts to extract the test code and patterns:

```bash
# Extract assertions from the test
python scripts/assertion_analyzer.py extract {{test_harness}} --test {{test_name}} --json .deeptest/quality/assertions.json

# Extract the test code and patterns
python scripts/test_design_analyzer.py extract {{test_harness}} --test {{test_name}} --json .deeptest/quality/test_code.json
```

## What the scripts extract (deterministic):

**assertion_analyzer.py:**
- All assertions with line numbers, code, type (equality/null_check/exception/etc.), and operands
- Summary flags: has_exception_handling, has_null_checks, has_equality_checks, has_boundary_checks
- **Raw test code lines** for additional analysis

**test_design_analyzer.py:**
- All numbers found (with line and context)
- All function calls found (with line and context)
- Language keywords found (global, static, extern, etc.)
- **All comments found**:
  - `description_comment`: The comment block immediately before the test (docstring, block comment, or consecutive line comments)
  - `inline_comments`: Single-line comments within the test (// or #)
  - `block_comments`: Multi-line /* */ comments within the test
- **Raw test code lines** for additional analysis

## What you (the agent) must analyze:

The scripts provide raw data and deterministic pattern matches. You must interpret this data to determine:

- **Assertion quality**: Are the extracted assertions checking exact values? Are they comprehensive?
- **Test structure**: Looking at the raw code, identify setup/arrange, action/act, assertion/verify, cleanup phases
- **Magic numbers**: From the numbers found, which are problematic vs acceptable constants?
- **External dependencies**: From function calls, identify file I/O, network, database access
- **Flakiness risks**: From function calls, identify sleep, rand, time, etc.
- **Design issues**: From keywords and structure, identify global state, missing cleanup, etc.
- **Comment-test conformity**: Do the comments accurately describe what the test actually does?
  - Does the description comment match the actual test behavior?
  - Are inline comments accurate descriptions of the code?
  - If comments describe certain scenarios or expectations, are those actually tested?

**Note**: The raw code is included so you can extract any additional patterns or information not covered by the deterministic extraction.

# Step 2: Measure Coverage

{{#if coverage}}
Use the provided coverage commands:

```bash
{{build}}
{{coverage}}
```
{{else}}
Use the coverage-analysis skill to simulate coverage:

```
Invoke coverage-analysis skill with:
- source_file: {{source_file}}
- test_file: {{test_harness}}
- test_case: {{test_name}}
```
{{/if}}

Collect:
- Lines covered in {{source_file}}
- Branches covered
- Total lines and branches in the target function

# Step 3: Analyze and Score

Based on the extracted information, evaluate each dimension:

## Assertion Quality (1-10)
Review the assertions from Step 1 and consider:
- **Specificity**: Do assertions check exact expected values or just non-null/truthy?
- **Completeness**: Are all observable outcomes (return values, side effects, state changes) verified?
- **Relevance**: Do assertions directly relate to the behavior being tested?
- **Negative testing**: Are error conditions and edge cases checked?

## Coverage Differential (1-10)
Based on coverage from Step 2:
- What percentage of the target function's lines does this test cover?
- What percentage of branches are exercised?

## Mutant Detection Ability (1-10)
Analyze the test's ability to detect code mutations:
- Review each assertion and determine what code changes it would catch
- Consider: arithmetic operators, relational operators, logical operators, constants, return values
- Estimate what percentage of realistic mutants this test would kill

## Test Design Quality (1-10)
Based on structure from Step 1:
- **Structure**: Is there clear Arrange-Act-Assert separation?
- **Naming**: Is the test name descriptive of scenario and expectation?
- **Maintainability**: Are there magic numbers? Is cleanup present where needed?
- **Robustness**: Are there flakiness risks (timing, randomness, external dependencies)?
- **Comment-test conformity**: Do comments accurately describe what the test does?
  - If the description comment says "test that X throws exception", does the test actually verify that?
  - If inline comments describe setup or assertions, is that accurate?
  - Are there misleading or outdated comments?

# Step 4: Generate JSON Output

Produce the final assessment as JSON with **equal weights** for all four measurements:

```json
{
  "test_file": "{{test_harness}}",
  "test_name": "{{test_name}}",
  "source_file": "{{source_file}}",
  "assertion_quality": {
    "score": <1-10>,
    "specificity": <1-10>,
    "completeness": <1-10>,
    "relevance": <1-10>,
    "negative_testing": <1-10>,
    "issues": [
      {"type": "<issue_type>", "description": "<description>", "line": <line_number>}
    ]
  },
  "mutant_detection_ability": {
    "score": <1-10>,
    "estimated_kill_rate": <0.0-1.0>,
    "detectable_mutant_types": ["<type1>", "<type2>"],
    "undetectable_mutant_types": ["<type1>", "<type2>"],
    "analysis": "<explanation of detection capability>"
  },
  "coverage_differential": {
    "score": <1-10>,
    "lines_covered": <count>,
    "total_lines": <count>,
    "branches_covered": <count>,
    "total_branches": <count>,
    "line_coverage_percent": <0.0-100.0>,
    "branch_coverage_percent": <0.0-100.0>
  },
  "test_design_quality": {
    "score": <1-10>,
    "structure": <1-10>,
    "naming": <1-10>,
    "maintainability": <1-10>,
    "robustness": <1-10>,
    "comment_conformity": <1-10>,
    "issues": [
      {"type": "<issue_type>", "description": "<description>"}
    ],
    "comment_analysis": {
      "has_description": <true/false>,
      "description_matches_behavior": <true/false>,
      "misleading_comments": [
        {"line": <line_number>, "comment": "<comment text>", "issue": "<why misleading>"}
      ]
    }
  },
  "overall_assessment": {
    "score": <1-10>,
    "grade": "<A/B/C/D/F>",
    "summary": "<one sentence summary>",
    "strengths": ["<strength1>", "<strength2>"],
    "weaknesses": ["<weakness1>", "<weakness2>"],
    "recommendations": [
      {"priority": "<high/medium/low>", "action": "<specific improvement>"}
    ]
  }
}
```

## Overall Score Calculation (Equal Weights)

```
overall_score = (
    assertion_quality.score +
    mutant_detection_ability.score +
    coverage_differential.score +
    test_design_quality.score
) / 4
```

## Grade Mapping
- A: 9-10 (Excellent)
- B: 7-8 (Good)
- C: 5-6 (Acceptable)
- D: 3-4 (Poor)
- F: 1-2 (Failing)

**Save the JSON output to .deeptest/quality_reports/{{test_name}}_quality.json**
