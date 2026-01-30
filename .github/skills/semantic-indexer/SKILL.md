---
name: semantic-indexer
description: Build semantic code indexes using tree-sitter parsing and nested call graphs. Extract focal functions with their complete call graphs into SQLite database, then perform bottom-up summarization using actual source code + callee summaries. Database grows incrementally as you index more focal functions.
---

# Semantic Code Indexer

Parse codebases with tree-sitter, extract focal functions with nested call graphs, and perform bottom-up summarization using **actual source code** and callee context. Create the db in the .deeptest/ folder.

## Complete Workflow

### Step 1: Build Focal Function Call Graph

```bash
python scripts/build_focal.py \
  --focal "DnsQueryEx" \
  --file "querystub.c" \
  --project ~/dns_full \
  --db dns.db
```

### Step 2: Bottom-Up Summarization and pre-/post-condition Annotation [long running task]
This step involves bottom up summarization, up the call graph, using actual source code and callee summaries to build context.
Follow the instructions exactly, this is a long running task where you need to iteratively call scripts. Do not attempt to optimize by writing your own scripts to speed up the process.

#### Step 2a: Get next function to summarize

Find the next function to summarize

```bash
python scripts/summarizer.py --db dns.db --project ~/dns_full next
```

```json
{
  "status": "needs_summary",
  "function": "LogError",
  "file": "/home/user/dns_full/log.cpp",
  "source_code": "void LogError(const char* fmt, ...) {\n    va_list args;\n    va_start(args, fmt);\n    fnsVaLog(LOG_ERROR, fmt, args);\n    va_end(args);\n}",
  "callees": [
    {
      "function": "va_start",
      "summary": "Initializes variable argument list processing"
    },
    {
      "function": "fnsVaLog",
      "summary": "Core logging function that formats messages with va_list"
    },
    {
      "function": "va_end",
      "summary": "Cleans up variable argument processing"
    }
  ]
}
```

**You have:**
- ✅ Actual source code of `LogError`
- ✅ Summaries of all callees

**Read the code!** You can see it:
1. Takes variable arguments (`...`)
2. Initializes va_list with `va_start`
3. Calls `fnsVaLog` with LOG_ERROR level
4. Cleans up with `va_end`

Write a summary using this context and *update* the database:

#### Tips for Good Summaries

**Summary Format:**
Write a concise paragraph summary  covering the function's purpose, how outputs depend on inputs, any global or shared state it reads or mutates, and which callees have side effects, can fail, or contain complex branching that a test might need to exercise. Focus on these aspects:
1. **Function's purpose** - What does it do?
2. **Input/output relationship** - How outputs depend on inputs
3. **State mutations** - Any global or shared state it reads or mutates
4. **Callee behavior** - Which callees have side effects, can fail, or contain complex branching that a test might need to exercise

**Best Practices:**
1. **Actually read the source code** - Don't just rely on function names
2. **Use callee summaries** - They tell you what dependencies do and their important behaviors
3. **Look for control flow** - Loops, conditions, error handling
4. **Note side effects** - File I/O, global state, logging, network calls
5. **Be specific** - "Validates X by checking Y" not "Validates input"
6. **Include callee context** - Mention which callees do the heavy lifting or can possibly fail


```bash
python scripts/summarizer.py --db dns.db update \
  --function "LogError" \
  --summary "Logs error messages by initializing variable argument processing with va_start, passing formatted arguments to fnsVaLog at LOG_ERROR level, then cleaning up with va_end"
```


#### Step 2b: Add Preconditions and Postconditions
**Annotate precondition**
```bash
python scripts/summarizer.py --db dns.db annotate \
  --function "LogError" \
  --type precondition \ # or postcondition
  --text "fmt is a valid format string"
```
pre-conditions should cover:
Required contracts on the input parameters (e.g., non-empty list, non-null fields)
Required environment/state
Assumptions about invariants (e.g., IDs are unique, timestamps are monotonic)
Any conditions that gate deeper branches (e.g., feature flag enabled, debug mode on)

post-conditions should cover:
Return value guarantees (type/shape, relationships between fields, sentinel values)
State changes (files written, DB rows updated, caches mutated, globals modified)
Error behavior (what exceptions/errors can occur and under what inputs/states)

Continue calling `next` and `update` to summarize and annotate more functions until the focal function you called build_focal.py on is fully summarized.

### Check Progress

```bash
python scripts/summarizer.py --db dns.db status
```

```json
{
  "total_functions": 89,
  "summarized": 67,
  "remaining": 22,
  "progress_percent": 75.3,
  "leaf_functions": 18,
  "call_edges": 234
}
```

-------------
