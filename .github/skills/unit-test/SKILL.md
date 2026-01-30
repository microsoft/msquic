---
name: unit-test
description: This skill generate high quality unit tests for production code at scale for a focal function. Tests are idiomatic to existing suites, uncover product bugs and test new paths of the function that the existing test suite does not cover.
---

# Step 1
1. Locate the focal function {{focal}} and map it to the existing test suite in {{harness}}. You can use the query-repo skill to location the focal function. Query the semantic index db to learn about what the focal function does in context of it's callers and callees. Its very important that you consider the function summary and preconditions and postconditions of the focal function and its callees when generating tests, throughout this process.

Schema of the semantic index is as follows:
```
Functions Table:
function_id, name, file, start_line, end_line, source_code, summary

Call_Edges Table:
caller_id, callee_id

pre_conditions Table:
function_id, text, sequence_order

post_conditions Table:
function_id, text, sequence_order
```

# Step 2
2. Evaluate the focal function {{focal}} for all paths that a test suite should cover. YOU MUST use the semantic index db to learn about context of the function and all its callees! If there is no semantic index you must first build one by using the semantic-indexer skill

If the summary for the focal function is not sufficent, query the semantic index for summaries of its callees to build context about what the focal function does in more detail.

# Step 3
3. For each test in the test suite, evalaute which path is covered for {{focal}} and then collect and save all of the paths that are still uncovered.

**CRITICAL INSTRUCTION**: Do not group related conditions. Each individual condition that leads to a distinct outcome or program branch must be its own separate path. For example, if a function checks for three different invalid parameters in sequence (e.g., `if (p1 == NULL)`, then `if (p2 == NULL)`, then `if (p3 == NULL)`), you must list three separate paths, not one single "invalid parameter" path.

For each distinct path, provide the following details:
- **Test [num]:** A short, descriptive title for the specific test case.
- **Conditions:** The complete and ordered sequence of logical conditions that must be met to follow this path. This must be the **FULL** path. Do not reference previous paths as a subpath, these paths must be undertood as standalone paths, and all paths conditions must be expressed as top level conditions of the focal function, not its callees.
- **Outcome:** What happens as a result of this path (e.g., "returns STATUS_INVALID_PARAMETER", "calls helper function X and returns its result", "a loop is entered and processes data").
- **lines executed:** The lines of code that are executed to follow this path. The format should be like this: [1,2,3,4,5]. If a looping condition exists, for example lines 3,4 are executed twice you can store the lines like this [1,2,(3,4)^2,5. All lines of code executed must be in this array because they will be compared to the actual code executed. Dont skip any lines.

Example of a well-structured response:

Test 2: Status-code assertion fails  
Conditions (in order):  
  1. `client.get("/")` executes without raising an exception.  
  2. `response.status_code != 200`.  
Outcome: The first `assert` fails, raising `AssertionError`; the second `assert` is never reached.

You've done a good job if:
- All paths in the focal function are represented as a test path
- Tests build on provided harness to exercise additional scenarios or trigger bugs with undefined behaviors, i.e. , paths that might exercise deeper paths in callees.
- Your paths will be used to generate tests that trigger explicit bugs or undefined behavior. It is ok if the tests you generate trigger undefined behaviors or crashes, you must include the bug or undefined behavior in the path description and annotate the test case. For example a test that tries to trigger a NULL pointer dereference along a certain path. 
- Tests cover all edge cases, invalid input, memory saftey issues, and other scenarios that are not covered by the current test suite. 
- Tests exercise preconditions and postconditions of the focal function and its callees.

**store path analysis in .deeptest/path_analysis folder**


# Step 4
4. Generate tests for all uncovered paths extracted in step 3 stored in the .deeptest/path_analysis folder.

Beyond **path** coverage, you should also add tests that could potentially expose security issues in the focal function, when applicable:

### Security OBJECTIVES:
- **Detect Memory Safety Issues** - Buffer overflows, use-after-free, memory leaks, double-free
- **Identify Input Validation Flaws** - Injection attacks, path traversal, format string vulnerabilities
- **Expose Race Conditions** - Concurrency issues, thread safety problems

For example, you **should** generate a test that intentionally triggers a buffer overflow and violated a pre-condition when the focal function has no input validation. These security focused tests are more liekly to catch bugs than the happy path tests, do your best to reason about callee pre and post conditions and how the focal function might trigger error paths.

# Step 5
5. Add these tests to the test suite. All deeptest tests you contribute must be indicated as such eithe rin a leading comment or in the test name. However. be sure to be idomatic and follow test suite conventions. 

Attempt to build and run the new tests, using any feedback to refine your output.
{{#if build}} Hints on how to build tests:  {{build}}  {{/if}}
{{#if test}} Hints on how to execute tests: {{test}} {{/if}}