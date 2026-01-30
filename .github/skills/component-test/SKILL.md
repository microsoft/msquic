---
name: component-test
description: This skill generates high-quality, production-scenario tests for production code at scale. Tests are idiomatic, strictly interface-driven, contract-safe (no precondition violations), and iteratively added/refined to reach 100% coverage of the specified source file.
---

You are generating tests for the **{{component}}** component defined in **{{source}}**{{#if header}} using **{{header}}** as an API/header hint{{/if}}. Your task is to augment the existing test harness at **{{harness}}** with high-quality, scenario-based tests that achieve **100% coverage** of **{{source}}** while remaining strictly interface-driven and contract-safe.


# Step 1 — Build/Load the Repository Contract Index (RCI)

Before writing or modifying any tests, you MUST build an index describing the repository for the transitive closure of {{source}}, bounded as follows:
- Include repo-local headers/sources and symbols actually referenced by {{source}} or required by public APIs in {{source}}.
- Exclude system/standard library headers except for documenting observable contract constraints they impose (best-effort).
- Approximate pointer/virtual/callback edges if needed; document each assumption in the RCI.


## 1.1 What the index must contain

Create a **Repository Contract Index (RCI)** that includes, at minimum:

### A) Public API inventory
For every **public function/method** implemented in **{{source}}**:
- fully qualified signature (incl. namespaces/classes)
- where it is declared (public header, export macro, etc.)
- a natural language summary (“what it does”)
- parameter preconditions (nullability, ranges, aliasing, ownership, lifetime rules)
- return/value postconditions (what is guaranteed on success/failure)
- side effects (state changes, IO, logging if part of contract)
- error contracts (error codes/exceptions/errno) and when they occur **within the contract**
- thread-safety/concurrency contract (if relevant)
- resource/ownership rules (alloc/free responsibilities, refcounts, borrowed vs owned pointers)

### B) Type/object invariants
For every relevant data structure (struct/class) in the closure:
- **object invariants** (must always hold for valid instances)
- valid state machine (if applicable): allowed states and transitions via public APIs
   - **State Invariants**: For every state in the state machine, also articulate the invariants w.r.t. all the objects in scope. 
- ownership/lifetime invariants for internal resources (buffers, handles, file descriptors, sockets, etc.)

### C) Environment invariants
List invariants the code must preserve (examples):
- global/module state constraints
- allocator or initialization requirements
- “must call init before use” constraints
- “must not leak” constraints
- locking discipline if concurrency exists


### D) Dependency map (for reasoning and scenario building)
- If **{{component}}** defined in the **{{source}}** {{#if header}} (and **{{header}}**){{/if}} implements any state machine, you should figure out the state transition diagram from the code, with valid infered states, transition API(s). The summary document must draw the state transtition. 
- call relationships among public APIs in **{{source}}** and the key internal dependencies they rely on
- notes on indirect calls/callback registration points (documented assumptions if approximated)

## 1.2 Persist the index

Persist to disk:
- If `{{index_dir}}` is provided, store under that directory.
- Otherwise store under: `./.deeptest/repo_contract_index/`

Files to create/update:
1) `rci_{component}.json` (or `rci.yaml`) — machine-readable
2) `rci_{component}_summary.md` — human-readable quick scan
3) `test_reflection_{component}.md` — append reflections after each new test (see Step 5)

**Important:** The index is a first-class artifact. You MUST consult it while generating tests, and update it if you learn something new during compilation/runtime/coverage runs.

---

# Step 2 — Identify test targets: ALL public functions in {{source}}

## 2.1 Define “public” precisely

Treat as public:
- functions declared in public headers
- exported symbols (export macros / visibility attributes)
- C++ public methods (as part of the class’s public API)

Treat as private/internal:
- `static` functions in C/C++
- unnamed-namespace helpers
- functions not declared in public headers (or only in internal headers)
- private/protected methods and any internal-only utilities

## 2.2 Derive scenario catalog per public API

For each public API in the inventory, derive set of realistic scenarios such as:
- canonical “happy path” usage
- boundary-but-valid inputs (within preconditions)
- stateful sequences (init → operate → finalize)
- error outcomes that are explicitly part of the contract (e.g., returns `EINVAL` for null *if* documented/observed as allowed)
- concurrency scenarios *only if* thread-safety is claimed/required by contract

Each scenario MUST:
- be achievable by calling only public APIs,
- preserve object invariants at all times,
- avoid precondition violations.

---

# Step 3 — Load the harness and map existing coverage & scenarios

1) Load **{{harness}}** and enumerate existing tests.
2) For each existing test, map:
   - which public APIs it calls,
   - which scenario it represents,
   - which parts of **{{source}}** it likely covers (use RCI + code reading),
   - what assumptions it makes (inputs/state) and whether they are contract-safe.

3) Identify gaps:
   - uncovered public APIs
   - missing scenario categories
   - uncovered lines/regions in **{{source}}**

---

# Step 4 — Coverage-driven test generation 

You do NOT need to enumerate paths. Instead, drive toward 100% coverage with iterative, scenario-based testing.

## 4.1 Iteration loop

Repeat until you achieve **100% coverage of {{source}}**

1. Pick a **single uncovered coverage region** in **{{source}}**.
2. Identify which **public API + scenario** (from the scenario catalog) can reach it while respecting contracts.
3. Write exactly **one** new test for that scenario:
   - minimal but realistic setup via public APIs
   - exercise behavior
   - assert observable outcomes (return values, output buffers, public getters, externally visible effects)
4. Add a **scenario comment** at the top of the test (idiomatic to repo style).
5. Append a reflection entry to `test_reflection` document (Step 5).

## 4.2 Test design rules

- Prefer clear setup → action → assertion.
- If a scenario naturally exercises multiple public functions, that is fine, but keep the narrative focused on **one scenario**.
- Avoid asserting internal state. Assert only what is observable via public APIs or stable outputs.
- Keep tests idiomatically consistent with the repo:
  - match fixture patterns
  - match naming conventions
  - match assertion style
  - match file organization
- Each test MUST include an idiomatic comment (matching repo style) describing the scenario describing 
   - **What** scenario is being tested
   - **How** is it being tested, and 
   - **Assertions** that are being made in the test. 

---

# Step 5 — Per-test reflection and differentiation (REQUIRED)

After adding each new test, append an entry to `test_reflection` document with:

- **Test name**
- **Scenario summary** (one paragraph)
- **Primary public API target(s)** (from the RCI public API inventory)
- **Contract reasoning**:
  - which preconditions you relied on and how you ensured them
  - which object/environment invariants are maintained
- **Expected coverage impact**:
  - list the key functions/regions/line ranges in **{{source}}** you expect to cover (best-effort from reading)
- **Non-redundancy**:
  - why this test is meaningfully different from existing tests

---

# Step 6 — Integrate, build, run, measure coverage; refine

1) Add tests to **{{harness}}**.
2) Build and run:
   {{#if build}}Build hints: {{build}}{{/if}}
   {{#if test}}Run hints: {{test}}{{/if}}

3) Use coverage tooling available in the repo to measure coverage of **{{source}}**.
   - If `{{coverage_result}}` is provided, use it as the baseline/ground truth.
   - Otherwise, produce/inspect coverage output produced by the repo’s tooling.

4) Iterate on tests until:
   - coverage reaches **100%** for **{{source}}**, OR
   - any remaining uncovered lines are proven **contract-unreachable** without precondition violation.

---

# Step 7 — Quality Validation with test-quality-checker

After generating each test, use the **test-quality-checker** skill to validate test quality. High-quality tests are not just about coverage—they must also have strong assertions, good design, and the ability to detect bugs (mutations).

## 7.1 Invoke test-quality-checker for each new test

For each test you generate, invoke the test-quality-checker skill:

```
Invoke test-quality-checker skill with:
- source_file: {{source}}
- test_harness: {{harness}}
- test_name: <name_of_the_new_test>
- build: {{build}} (if provided)
- coverage: (coverage command if available)
```

## 7.2 Quality thresholds

Each generated test MUST meet these minimum quality thresholds:

| Dimension | Minimum Score | Description |
|-----------|---------------|-------------|
| **Assertion Quality** | 7/10 | Assertions must check specific expected values, not just non-null/truthy |
| **Mutant Detection** | 6/10 | Test should catch common code mutations (operators, constants, conditions) |
| **Test Design Quality** | 7/10 | Clear structure, no magic numbers, proper cleanup, accurate comments |
| **Overall Score** | 7/10 | Average of all dimensions must be at least 7 |

## 7.3 Iterate to improve quality

If a test scores below thresholds:

1. **Review the quality report** - Check `issues` and `recommendations` in the JSON output
2. **Improve assertions** - Add more specific value checks, not just existence checks
   - ❌ `ASSERT_NE(result, nullptr)` alone
   - ✅ `ASSERT_NE(result, nullptr); ASSERT_EQ(result->status, EXPECTED_STATUS); ASSERT_EQ(result->count, 5);`
3. **Improve mutant detection** - Add assertions that would fail if code logic changes
   - Check return values precisely
   - Verify state changes with exact expected values
   - Test boundary conditions
4. **Fix design issues** - Address magic numbers, missing cleanup, flakiness risks
5. **Fix comment-test conformity** - Ensure comments accurately describe what the test does
6. **Re-run test-quality-checker** until thresholds are met

## 7.4 Quality-driven test refinement loop

```
for each new test:
    generate_test()
    quality = invoke_test_quality_checker()
    
    while quality.overall_score < 7:
        for issue in quality.recommendations:
            apply_fix(issue)
        quality = invoke_test_quality_checker()
    
    commit_test()
```

## 7.5 Quality rules (anti-gaming policy):
- No oracle duplication: do not compute expected values by re-implementing production logic.
- At least one contract-meaningful assertion per test (not just non-null/no-crash).
- Avoid flakiness: no reliance on timing races, real network, nondeterministic randomness.

## 7.5 Document quality in test_reflection_{component}.md

After quality validation passes, add to the test reflection:
- **Quality score**: overall score and breakdown
- **Key assertions**: what specific values/behaviors are verified

---

**Keep adding passing test cases until the coverage is 100%. Do everything you need to do to achieve 100% coverage, which being contract safe.**

---

# Non-negotiable constraints (read carefully)

1. **Public surface only (STRICT).**
   - Tests MUST call only **public** functions/methods that are part of the module’s supported API.
   - Tests MUST NOT call private/internal helpers (e.g., `static` functions in C, unnamed-namespace functions, non-exported symbols, “internal” headers, private/protected methods, test-only hooks).
   - Tests MUST NOT access private/protected fields or poke internal struct/class layout. No offset hacks, `#define private public`, friend injections, reflection-like tricks, or direct state mutation.

2. **Contract-safe tests only (STRICT).**
   - Tests MUST NOT violate any API precondition.
   - If a behavior requires invalid inputs (null where disallowed, empty buffer where object invariant requires non-empty, out-of-range values, calling methods in the wrong state), that is **not** a valid test scenario unless the API contract explicitly states such inputs/states are supported and returns a defined error outcome.
   - Error-handling tests are allowed **only** when the contract explicitly defines behavior for that error condition.

3. **Scenario-based tests, one scenario per test (STRICT).**
   - Each test must cover **exactly one** scenario of realistic product usage.
   - Scenario setup MUST be achieved via a **sequence of public API calls** (e.g., “receive packet” then “send packet”), not by direct state manipulation.

4. **100% coverage of {{source}} is the north-star goal.**
   - You MUST still drive coverage to 100% for statements/lines in **{{source}}**, using iterative, coverage-guided test creation.
   - Cover **all** scenario you identified in step 1. 

5. **Quality validation (REQUIRED).**
   - Each test MUST pass quality validation with the test-quality-checker skill.
   - Each test MUST achieve a minimum overall score of 7/10.
   - Tests with weak assertions (only null checks, no value verification) MUST be improved.

---
# You've succeeded if:

- Tests are generated for scenarios that collectively cover **all public functions** implemented in **{{source}}**.
- Tests never call internal/private functions or access private data.
- Tests never violate preconditions and always preserve object/environment invariants as per the RCI.
- Each test is a single, realistic scenario and includes an idiomatic scenario comment.
- Coverage for **{{source}}** is **100%**.
- Each test achieves a quality score of at least 7/10 from the test-quality-checker skill.
- Tests have strong, specific assertions that would detect code mutations (not just null checks).