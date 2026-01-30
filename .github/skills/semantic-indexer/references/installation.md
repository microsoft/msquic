# Installation

## Requirements

```bash
pip install tree-sitter tree-sitter-c tree-sitter-cpp tree-sitter-python
```

## Quick Start

```bash
# 1. Extract focal function
python scripts/build_focal.py \
  --focal "SetupDnsServer" \
  --project ~/myproject \
  --db myproject.db

**What happens:**
1. Parses entire codebase with tree-sitter (`query_repo.init()`)
2. Builds nested call graph (`query_repo.build_call_graph("SetupDnsServer")`)
3. Walks graph recursively and adds to database:
   - SetupDnsServer + all its callees
   - Call edges (who calls whom)
   - File paths and line numbers

# 2. Summarize
python scripts/summarizer.py --db myproject.db next
python scripts/summarizer.py --db myproject.db update --function "..." --summary "..."

# 3. Query
python scripts/indexer.py --db myproject.db stats
```

See SKILL.md for complete documentation.



## Scripts

### build_focal.py

Extract focal function to database:

```bash
python scripts/build_focal.py \
  --focal FUNCTION_NAME \
  --project PROJECT_PATH \
  --db DATABASE_FILE \
  [--file FILE_HINT]
```

**Arguments:**
- `--focal` - Function name to extract
- `--project` - Project root directory
- `--db` - SQLite database (created if doesn't exist, grows if exists)
- `--file` - Optional file hint (e.g., "common.cpp")

### summarizer.py

Bottom-up summarization:

**Commands:**
- `next` - Get next function to summarize (**WITH SOURCE CODE!**)
- `update` - Update function summary
- `status` - Show progress
- `annotate` - Add precondition/postcondition

**Arguments:**
- `--db` - Database file
- `--project` - Project path (needed for source code retrieval in `next`)

**Examples:**
```bash
# Get next target (returns source code!)
python scripts/summarizer.py --db dns.db --project ~/dns_full next

# Update summary
python scripts/summarizer.py --db dns.db update \
  --function "LoadConfig" \
  --summary "Parses config file and validates settings"

# Add annotation
python scripts/summarizer.py --db dns.db annotate \
  --function "LoadConfig" \
  --type precondition \
  --text "Config file must exist and be readable"

# Check progress
python scripts/summarizer.py --db dns.db status
```

### indexer.py

Query and manage database:

**Commands:**
- `query` - Get function with call tree
- `stats` - Database statistics
- `list` - List all functions

## Database Schema

```sql
functions (
  function_id, name, file, start_line, end_line, summary
)

call_edges (
  caller_id, callee_id  -- Normalized, each function stored once
)

preconditions/postconditions (
  function_id, condition_text, sequence_order
)
```


## Troubleshooting

### "Function code not found"
- Function might be external (system library)
- Just write a simple summary based on the name
- Example: "va_start" → "Initializes variable argument list processing"

### "Project data not initialized"
- Make sure `--project` path is correct
- Check tree-sitter packages are installed

### Database grows too large
- This is normal! Only contains what you've indexed
- Each focal function adds its entire call tree
- Shared functions stored once (normalized)

See `references/installation.md` for setup details.