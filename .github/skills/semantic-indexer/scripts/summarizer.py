#!/usr/bin/env python3
"""
Bottom-up summarization workflow
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

import query_repo
from indexer import SemanticIndex


def find_next_summary_target(index: SemanticIndex, entry_id: int, visited: set) -> Tuple[Optional[Dict], bool]:
    """
    Post-order traversal to find next node to summarize.
    
    Returns (target_node, is_subtree_summarized)
    - target_node: First unsummarized node whose callees are all summarized
    - is_subtree_summarized: True if this subtree is fully summarized
    """
    if entry_id in visited:
        # Already visited - check if it's summarized
        func = index.get_function_info(entry_id)
        if func and func["summary"].strip():
            return None, True
        return None, False
    
    visited.add(entry_id)
    
    # Get function info
    func = index.get_function_info(entry_id)
    if not func:
        return None, True  # Unknown function treated as summarized
    
    # Get callees
    callees = index.get_callees(entry_id)
    
    # Check if this node is already summarized
    is_summarized = bool(func["summary"].strip())
    
    if is_summarized:
        # Already summarized - check callees to continue traversal
        all_callees_done = True
        for callee in callees:
            target, subtree_done = find_next_summary_target(index, callee["function_id"], visited)
            if target:
                return target, False
            if not subtree_done:
                all_callees_done = False
        return None, all_callees_done
    
    # Not summarized yet - check if all callees are done (post-order)
    all_callees_summarized = True
    for callee in callees:
        target, subtree_done = find_next_summary_target(index, callee["function_id"], visited)
        if target:
            # Found a target in subtree - return it
            return target, False
        if not subtree_done:
            all_callees_summarized = False
    
    # If all callees are summarized (or no callees), this is our target
    if all_callees_summarized:
        return func, False
    
    # Some callees not summarized yet
    return None, False


def build_callee_tree(index: SemanticIndex, callee: Dict, depth: int, max_depth: int, visited: set = None) -> Dict:
    """
    Build nested callee tree up to max_depth.
    Returns callee info with nested 'calls' array.
    """
    if visited is None:
        visited = set()
    
    func_id = callee.get("function_id")
    if func_id in visited:
        return {
            "function": callee.get("function", "unknown"),
            "file": callee.get("file", "unknown"),
            "summary": callee.get("summary", ""),
            "cycle": True
        }
    
    visited.add(func_id)
    
    result = {
        "function": callee.get("function", "unknown"),
        "file": callee.get("file", "unknown"),
        "summary": callee.get("summary", "")
    }
    
    # Stop at max depth
    if depth >= max_depth:
        return result
    
    # Get sub-callees
    sub_callees = index.get_callees(func_id) if func_id else []
    if sub_callees:
        # Limit to first 5 callees per level to avoid explosion
        result["calls"] = [
            build_callee_tree(index, sc, depth + 1, max_depth, visited.copy())
            for sc in sub_callees[:5]
        ]
    
    return result


def get_next_target(index: SemanticIndex) -> Dict[str, Any]:
    """
    Find next function to summarize (bottom-up)
    RETURNS ACTUAL SOURCE CODE for the agent to read!
    """
    
    # Get all functions (roots of any focal trees)
    cursor = index.conn.execute("SELECT DISTINCT function_id FROM functions")
    all_funcs = [row[0] for row in cursor]
    
    if not all_funcs:
        return {
            "status": "error",
            "message": "No functions in database"
        }
    
    # Try each function as a potential root
    visited = set()
    for func_id in all_funcs:
        target, complete = find_next_summary_target(index, func_id, visited)
        if target:
            # Get callee summaries
            callees = index.get_callees(target["function_id"])
            
            # Get source code using query_repo
            source_code = query_repo.query_function(
                target["name"], 
                target["file"] if target["file"] != "unknown" else None
            )
            
            if not source_code:
                source_code = "Function code not found."
            
            # Get pre/postconditions
            cursor = index.conn.execute(
                """SELECT condition_text FROM preconditions 
                   WHERE function_id = ? ORDER BY sequence_order""",
                (target["function_id"],)
            )
            preconditions = [row[0] for row in cursor]
            
            cursor = index.conn.execute(
                """SELECT condition_text FROM postconditions 
                   WHERE function_id = ? ORDER BY sequence_order""",
                (target["function_id"],)
            )
            postconditions = [row[0] for row in cursor]
            
            # Get callee summaries with their callees (nested up to depth 5 for context)
            callees_with_context = []
            for c in callees:
                callee_info = build_callee_tree(index, c, depth=1, max_depth=5)
                callees_with_context.append(callee_info)
            
            return {
                "status": "needs_summary",
                "function_id": target["function_id"],
                "function": target["name"],
                "file": target["file"],
                "start_line": target["start_line"],
                "end_line": target["end_line"],
                "source_code": source_code,  # ← ACTUAL SOURCE CODE!
                "preconditions": preconditions,
                "postconditions": postconditions,
                "callees": callees_with_context,
                "summary_instructions": "Write a concise paragraph summary covering the function's purpose, how outputs depend on inputs, any global or shared state it reads or mutates, and which callees have side effects, can fail, or contain complex branching that a test might need to exercise."
            }
    
    # All functions summarized
    return {
        "status": "complete",
        "message": "All functions in database are summarized"
    }


def update_summary(index: SemanticIndex, function_name: str, summary: str, function_id: int = None) -> Dict:
    """Update function summary. If function_id provided, use it directly."""
    
    if function_id:
        func_id = function_id
    else:
        # Find function by name
        cursor = index.conn.execute(
            "SELECT function_id FROM functions WHERE name = ? LIMIT 1",
            (function_name,)
        )
        row = cursor.fetchone()
        func_id = row[0] if row else None
    
    if not func_id:
        return {
            "status": "error",
            "message": f"Function not found: {function_name}"
        }
    
    index.update_summary(func_id, summary)
    
    return {
        "status": "ok",
        "function_id": func_id,
        "function": function_name,
        "summary": summary
    }


def add_annotation(
    index: SemanticIndex,
    function_name: str,
    ann_type: str,
    text: str,
    function_id: int = None
) -> Dict:
    """Add precondition or postcondition. If function_id provided, use it directly."""
    
    if function_id:
        func_id = function_id
    else:
        # Find function by name
        cursor = index.conn.execute(
            "SELECT function_id FROM functions WHERE name = ? LIMIT 1",
            (function_name,)
        )
        row = cursor.fetchone()
        func_id = row[0] if row else None
    
    if not func_id:
        return {
            "status": "error",
            "message": f"Function not found: {function_name}"
        }
    
    table = "preconditions" if ann_type == "precondition" else "postconditions"
    
    # Get next sequence number
    cursor = index.conn.execute(
        f"SELECT COALESCE(MAX(sequence_order), -1) + 1 FROM {table} WHERE function_id = ?",
        (func_id,)
    )
    seq = cursor.fetchone()[0]
    
    # Insert
    index.conn.execute(
        f"INSERT INTO {table} (function_id, condition_text, sequence_order) VALUES (?, ?, ?)",
        (func_id, text, seq)
    )
    index.conn.commit()
    
    return {
        "status": "ok",
        "function": function_name,
        "type": ann_type,
        "text": text
    }


def get_status(index: SemanticIndex) -> Dict:
    """Get summarization progress"""
    stats = index.get_stats()
    
    total = stats["total_functions"]
    summarized = stats["summarized_functions"]
    remaining = total - summarized
    progress = (summarized / total * 100) if total > 0 else 0
    
    return {
        "total_functions": total,
        "summarized": summarized,
        "remaining": remaining,
        "progress_percent": round(progress, 1),
        "leaf_functions": stats["leaf_functions"],
        "call_edges": stats["total_call_edges"]
    }


def get_ready_batch(index: SemanticIndex, max_batch: int = 50) -> Dict[str, Any]:
    """
    Find ALL functions ready to summarize (callees all summarized).
    Returns a batch that can be processed in parallel.
    """
    
    # Get all unsummarized functions
    cursor = index.conn.execute("""
        SELECT function_id, name, file, start_line, end_line 
        FROM functions 
        WHERE summary IS NULL OR summary = ''
    """)
    unsummarized = {row[0]: {
        "function_id": row[0],
        "name": row[1],
        "file": row[2],
        "start_line": row[3],
        "end_line": row[4]
    } for row in cursor}
    
    if not unsummarized:
        return {"status": "complete", "message": "All functions summarized", "batch": []}
    
    # For each unsummarized function, check if all callees are summarized
    ready = []
    for func_id, func_info in unsummarized.items():
        callees = index.get_callees(func_id)
        
        # Check if all callees are summarized (or not in our DB)
        all_callees_ready = True
        for callee in callees:
            callee_id = callee.get("function_id")
            if callee_id in unsummarized:
                # Callee exists but not summarized yet
                all_callees_ready = False
                break
        
        if all_callees_ready:
            ready.append(func_info)
            if len(ready) >= max_batch:
                break
    
    if not ready:
        # This shouldn't happen in a DAG, but handle circular deps
        return {
            "status": "error", 
            "message": "No functions ready - possible circular dependencies",
            "batch": []
        }
    
    return {
        "status": "ok",
        "batch_size": len(ready),
        "total_remaining": len(unsummarized),
        "batch": ready
    }


def get_function_context(index: SemanticIndex, func_id: int) -> Dict[str, Any]:
    """Get full context for a single function (for parallel processing)."""
    func = index.get_function_info(func_id)
    if not func:
        return {"status": "error", "message": f"Function {func_id} not found"}
    
    callees = index.get_callees(func_id)
    
    # Get source code
    source_code = query_repo.query_function(
        func["name"],
        func["file"] if func["file"] != "unknown" else None
    )
    if not source_code:
        source_code = "Function code not found."
    
    # Get callee context
    callees_with_context = []
    for c in callees:
        callee_info = build_callee_tree(index, c, depth=1, max_depth=3)
        callees_with_context.append(callee_info)
    
    return {
        "status": "needs_summary",
        "function_id": func_id,
        "function": func["name"],
        "file": func["file"],
        "start_line": func["start_line"],
        "end_line": func["end_line"],
        "source_code": source_code,
        "callees": callees_with_context
    }


def main():
    parser = argparse.ArgumentParser(
        description="Bottom-up summarization with SOURCE CODE context"
    )
    parser.add_argument("--db", required=True, help="Database file")
    parser.add_argument("--project", help="Project path (for query_repo if not already initialized)")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # next
    subparsers.add_parser("next", help="Get next function to summarize (WITH SOURCE CODE!)")
    
    # next-batch
    batch_parser = subparsers.add_parser("next-batch", help="Get batch of functions ready to summarize in parallel")
    batch_parser.add_argument("--max", type=int, default=50, help="Maximum batch size")
    
    # context
    context_parser = subparsers.add_parser("context", help="Get full context for a function by ID")
    context_parser.add_argument("--function-id", type=int, required=True, help="Function ID")
    
    # update
    
    # update
    update_parser = subparsers.add_parser("update", help="Update function summary")
    update_parser.add_argument("--function", required=True, help="Function name")
    update_parser.add_argument("--function-id", type=int, help="Function ID (optional, more precise than name)")
    update_parser.add_argument("--summary", required=True, help="Summary text")
    
    # annotate
    ann_parser = subparsers.add_parser("annotate", help="Add annotation")
    ann_parser.add_argument("--function", required=True, help="Function name")
    ann_parser.add_argument("--function-id", type=int, help="Function ID (optional, more precise than name)")
    ann_parser.add_argument("--type", required=True, choices=["precondition", "postcondition"])
    ann_parser.add_argument("--text", required=True, help="Condition text")
    
    # status
    subparsers.add_parser("status", help="Show summarization progress")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize query_repo if needed (for source code retrieval)
    if args.command in ("next", "next-batch", "context") and args.project:
        query_repo.init(args.project)
    
    index = SemanticIndex(args.db)
    
    if args.command == "next":
        result = get_next_target(index)
        print(json.dumps(result, indent=2))
    
    elif args.command == "next-batch":
        result = get_ready_batch(index, args.max)
        print(json.dumps(result, indent=2))
    
    elif args.command == "context":
        result = get_function_context(index, args.function_id)
        print(json.dumps(result, indent=2))
    
    elif args.command == "update":
        func_id = getattr(args, 'function_id', None)
        result = update_summary(index, args.function, args.summary, func_id)
        print(json.dumps(result, indent=2))
    
    elif args.command == "annotate":
        func_id = getattr(args, 'function_id', None)
        result = add_annotation(index, args.function, args.type, args.text, func_id)
        print(json.dumps(result, indent=2))
    
    elif args.command == "status":
        result = get_status(index)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
