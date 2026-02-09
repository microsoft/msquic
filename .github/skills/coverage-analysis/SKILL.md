---
name: coverage-analysis
description: Use this skill to Simulate execution of C/C++ test cases to produce coverage.xml using static, semantic, and state-based reasoning
---

# Test case Coverage Analyzer
The coverage-analysis skill simulates the execution of a given test case on a specified C/C++ source file **without compiling or running the program**. It uses code structure, language semantics, and symbolic reasoning to infer:
- Which lines are executed
- Which branches are taken
- Which loops iterate
- What helper functions are invoked
- How control flows during test execution

## Skill outputs: 
1. coverage.xml (Cobertura-compatible) 
2. covered_lines.txt (optional helper)

Required structure (illustrative):
```
<?xml version="1.0" ?>
<coverage lines-valid="{int}" lines-covered="{int}" line-rate="{float}"
          branches-valid="{int}" branches-covered="{int}" branch-rate="{float}"
          version="neural-executor/1.0" timestamp="{epoch_millis}">
  <sources>
    <source>{repo_path}</source>
  </sources>
  <packages>
    <package name="{inferred.package.or.module}">
      <classes>
        <class name="{inferred.class.or.module}"
               filename="{relative/path/to/source_file}"
               line-rate="{float}" branch-rate="{float}">
          <methods>
            <!-- Optional per-method coverage -->
          </methods>
          <lines>
            <!-- For each executable line in source_file -->
            <line number="{int}" hits="{int}"
                  branch="{true|false}"
                  condition-coverage="{percent}% ({covered}/{total})" />
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>
```

**Guidelines:** The <lines> section must include **ALL** executable lines in **{source_file}**, starting from the first line, all the way to the last line, even if not executed. 
  - The <line> entries should be sorted in ascending order by line number. Remember, line numbers are 1-based. 
  - hits increments when the simulated path executes the line. 
  - For branching lines, set branch="true" and include condition-coverage. 
  - Ensure lines-valid, lines-covered, branches-valid, branches-covered, and rates are arithmetically consistent. 
  - Only include source_file in Cobertura metrics unless the test mutates coverage of other files (do not assume it does). 
  - The file must be self-contained, deterministic, and reflect the simulated execution of {test_case} over {source_file} as driven by {test_file}.

# High-Level Responsibilities
- Discover and read files within {repo_path}; analyze **only local repository content**.
- Identify and isolate **{test_case}** inside **{test_file}** and determine how it drives **{source_file}**.
- Infer **execution path(s)**, **control-flow**, and **state transitions** under widely accepted semantics for the language.
- Produce **deterministic**, **well-formed** XML outputs (no malformed tags, consistent attributes, valid numeric rates).
- Be explicit about **assumptions** (e.g., default values, mocks for environment, seeds for randomness).
- Prefer **precision** where feasible; when ambiguity arises, choose a **single canonical path** and document assumptions.

## Full Algorithm with Tool Support

### Phase 1: Pre-Execution Analysis (REQUIRED)

**Step 1.1: Analyze Source Structure**

Use `scripts/source_analyzer.py` to identify all executable lines and branch points:

```bash
python scripts/source_analyzer.py analyze {source_file} --json analysis.json --txt executable.txt
```

This generates:
- `analysis.json`: Complete mapping of functions, executable lines, and branches
- `executable.txt`: Human-readable list for reference

**Step 1.2: Read and Understand the Test**

Manually read the test case to understand:
- What is the test trying to verify?
- What initial state does it set up?
- What functions does it call?
- What assertions does it make?
- Document: "This test verifies [X] by setting up [Y] and calling [Z]"

**Step 1.3: Create Tracing Guide (Optional)**

Use `scripts/path_tracer.py` to generate a template for systematic tracing:

```bash
python scripts/path_tracer.py create-guide {source_file} {test_file} {test_case} guide.txt
```

This creates a guided template with:
- Expected function calls
- Branch points to evaluate
- Placeholder for your trace notes

**Step 1.4: Identify the Call Graph**

- Starting from test, list all direct function calls
- For each function, identify what it calls (use `source_analyzer.py show-function` to inspect)
- Create a call tree (can be mental or written)

```bash
# Optional: Inspect specific functions
python scripts/source_analyzer.py show-function {source_file} {function_name}
```

**Step 1.5: Check for Initialization and Setup Code**
- Test setup matters: The test may manually set state variables before calling functions
- Mock initialization: Tests often bypass normal initialization sequences
- Track overrides: Note when tests directly assign values (e.g., object->state = SPECIFIC_STATE)

### Phase 2: Systematic Execution Trace (REQUIRED)

Execute with **incremental verification** - create a trace document as you go:

**Trace Document Format:**
```
EXECUTION TRACE:
Test line T1: Initialize object
  → Calls InitFunction
    Lines: [list lines]
    State after: {key variables and values}

Test line T2: Set state variable
  Direct assignment: variable = value
  State after: {updated state}

Test line T3: Call FunctionA(param)
  → Enters FunctionA at line L1
    Line L2: if (condition) → Evaluate: [show computation] → Result: TRUE/FALSE
    Line L3-L5: [executed if TRUE, skipped if FALSE]
    Calls: FunctionB at line L4
      → [trace FunctionB recursively]
    Line L10: return value
  ← Returns to test line T3
  State after: {updated state}
```

**Use Python tools to inspect code during tracing:**

```bash
# Show specific line with context
python scripts/path_tracer.py show-line {source_file} {line_number} [context_lines]
```

**For EACH function call:**
* immediately trace into it and document what lines execute
* Follow the complete call chain: If function A calls B which calls C, trace all three in order
* Document each call: Write down: "Line X calls FunctionY → executes lines A-B"
* No assumptions: Don't guess that a function "probably does X" - read its implementation

Example of correct tracing:
```
Line X: FunctionA(param)
  → Enters FunctionA (lines A1-A20)
  → Line A2: Variable initialization
  → Line A3: Variable initialization
  → Line A7: Calls FunctionB(param)
    → Enters FunctionB (lines B1-B30)
    → Lines B2-B5: Local variable setup
    → Line B10: if (state_check) → TRUE
    → Line B11: return computed_value;
    → Returns to line A7
  → Line A12: Calls FunctionC(param)
    → [trace this function...]
- Document entry: "→ Entering FunctionX at line N"
- Trace line by line
- Document exit: "← Returning from FunctionX to line M"
```

**For EACH conditional**:
- Read the condition carefully: Understand what it checks (`&&`, `||`, `!`, comparisons)
- Evaluate with actual values: Substitute real values and compute the result.
- Handle short-circuiting: For && and ||, evaluate left-to-right and stop when result is determined
- Track both taken and not-taken: Document which branch executed and why

Example branch analysis:
```
Line L: else if (
    !flagA ||              // FALSE (flagA=TRUE)
    !setting.enabled ||    // FALSE (enabled=TRUE)
    value == MAX_VALUE ||  // FALSE (value=actualValue)
    value < THRESHOLD)     // FALSE (actualValue >= THRESHOLD)

Overall: FALSE || FALSE || FALSE || FALSE = FALSE
→ else branch NOT taken
→ continue to next branch or statement
```

**For EACH loop**:
- Document: `"Loop at line L: condition is [C]"`
- Iteration 0: Check condition, evaluate to `TRUE/FALSE`
- If TRUE: Iteration 1: [trace body], increment/update, check condition again
- Continue until condition FALSE
- Document: "Loop executed N iterations, covering lines X-Y N times each"
- Record loop condition values on each check. If the loop executes n times, include n iteration snapshots. Show break/continue effects explicitly.

**Maintain State Table**:
* Track variable values: Maintain a mental (or written) state table with current values
* Calculate expressions: For every conditional, compute the actual boolean result
* Don't guess branch directions: Use actual values to determine TRUE/FALSE

Example state tracking:
```
After initialization:
  WindowSize = InitialValue * Multiplier
             = X * Y = Z
  MaxValue = WindowSize / 2 = Z / 2 = W
  CurrentValue = 0

After operation(N):
  CurrentValue = 0 + N = N
  
Checking line L: if (MaxValue < CurrentValue)
  → if (W < N)
  → Evaluate to TRUE or FALSE based on actual values
  → If FALSE: Branch NOT taken, dependent lines NOT executed
```
### Phase 3: Coverage Accumulation

**Step 3.1: Collect Covered Lines**

From your trace document, create a simple list of executed line numbers:

```
# covered_lines.txt format (one line number per line)
1094
1096
1098
...
```

**Step 3.2: Track Branch Coverage**

For each branch point (from `analysis.json`):
- Mark which direction taken: "Line L: branch TRUE taken, FALSE not taken"
- Calculate coverage: "1 of 2 branches = 50%"

**Step 3.3: Verify Consistency**
- Every line in coverage list must appear in trace
- Every branch marked covered must have evaluation in trace

### Phase 4: Self-Verification (REQUIRED)

Before generating XML, answer:
1. Can I trace a path from test entry to every covered line?
2. For every covered line with a condition, did I evaluate it?
3. For every function call in the trace, did I enter it?
4. For any uncovered lines, can I explain why they weren't reached?
5. Did I check initialization and cleanup (logging, teardown)?

Before generating coverage.xml, verify: 
  - [ ] Every function call in the test is traced 
  - [ ] Every function called by those functions is traced (recursive) 
  - [ ] All initialization code is included (including end-of-init logging) 
  - [ ] All state variable values are computed with actual numbers 
  - [ ] All branch conditions are evaluated with actual values 
  - [ ] No lines are included that couldn't execute based on branch analysis 
  - [ ] All helper function calls are traced (logging, getters, etc.)

### Phase 5: Generate Coverage Output

**Option A: Generate from Simple Line List (Recommended for manual tracing)**

```bash
python scripts/coverage_generator.py generate-simple {repo_path} {source_file} analysis.json covered_lines.txt coverage.xml
```

This produces:
- `coverage.xml`: Cobertura-format coverage report
- Automatically calculates line/branch rates
- Marks all lines from `covered_lines.txt` as hit=1

**Option B: Generate from Detailed Trace JSON (For advanced workflows)**

If you created a detailed JSON trace with branch information:

```bash
python scripts/coverage_generator.py generate {repo_path} {source_file} analysis.json trace.json coverage.xml
```

**Option C: Generate Execution Trace XML (Optional detailed output)**

For human-readable execution trace in XML format:

```bash
python scripts/trace_generator.py generate {repo_path} {source_file} {test_file} {test_case} trace.json execution_info.xml
```

## Simulation Constraints
  - No code compilation or dynamic execution.
  - All reasoning is static, semantic, and state-aware.
  - Language-specific constructs (C/C++) follow conventional semantics:
  - Short-circuiting for && and ||
  - Standard evaluation order
  - Function calls substitute with code-level reasoning
  - Loops analyzed symbolically
  - Struct/field initialization inferred

## Allowed Actions
The skill may: 
  - Browse all files inside repo_path 
  - Load and analyze source code 
  - Parse and interpret the test file 
  - Identify call graph paths from test to source 
  - Track symbolic variable state 
  - Infer reachable/executable lines 
  - Produce coverage.xml using standard Cobertura schema


## Tips for Accurate Tracing
  - Start with test code: Read the test to understand the sequence of calls
  - Trace systematically: Follow each function call into the source
  - Track branches: For each if, determine which path is taken based on values
  - Note helper functions: Don't forget to trace into utility/helper functions
  - Check loops: Determine iteration count and trace each iteration
  - Verify with source: Cross-reference line numbers with actual source code
  - Compute actual values: Don't guess - calculate variable values at each step
  - Verify every assumption: If you think "probably executes", stop and verify

## Self-Review Questions Before Submitting:

   1. Did I perform pre-execution analysis to understand the test's intent?
   2. Did I create a systematic trace document (even mentally)?
   3. Did I trace every function call mentioned in the test case?
   4. Did I follow every nested function call within those functions?
   5. Did I compute actual numeric values for all state variables?
   6. Did I evaluate every branch condition with those actual values?
   7. Did I mark which branch direction was taken (TRUE/FALSE)?
   8. Did I handle loops correctly (count iterations, trace body)?
   9. Did I track early returns and control flow changes?
   10. Can I justify why each covered line is reachable from the trace?
   11. Can I justify why each uncovered line is NOT reachable?
   12. Did I check for initialization and teardown code (logging, etc.)?
   13. Did I classify and trace helper functions (getters, setters, logging)?
   14. Is my state table consistent throughout the execution?
   15. Does my branch coverage accurately reflect which paths were taken?
   16. Did I handle type conversions and arithmetic correctly (unsigned, pointers, etc.)?
   17. Did I expand macros where necessary (#define constants, function-like macros)?
   18. Did I document assumptions about external/library function behavior?
   19. Did I handle recursive functions properly (if any)?
   20. Did I break down complex expressions step-by-step?
   21. Would my traced execution make all test assertions pass?
   22. Did I document any ambiguities or uncertainties encountered?