#!/usr/bin/env python3
"""
Extract focal function and its call graph from codebase into database
Uses query_repo.py for tree-sitter parsing and call graph building
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Dict, Set

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent))

import query_repo
from indexer import SemanticIndex


def walk_call_graph(graph: Dict, func_map: Dict[tuple, int], index: SemanticIndex) -> int:
    """
    Recursively walk nested call graph and populate database
    Returns function_id of root, or -1 if function has unknown file path
    """
    func_name = graph["function"]
    file_path = graph.get("file", "unknown")
    start_line = graph.get("start_line", 0)
    end_line = graph.get("end_line", 0)
    
    # Skip functions with unknown file paths (external/system functions)
    if file_path == "unknown":
        return -1
    
    # Add function to DB
    func_id = index.add_function(func_name, file_path, start_line, end_line)
    func_map[(func_name, file_path)] = func_id
    
    # Recursively process callees
    calls = graph.get("calls", [])
    if isinstance(calls, str):
        # Handle "Already visited (cycle)" case
        return func_id
    
    for callee_graph in calls:
        callee_id = walk_call_graph(callee_graph, func_map, index)
        # Add call edge only if callee was added to DB
        if callee_id != -1:
            index.add_call_edge(func_id, callee_id)
    
    return func_id


def count_functions_in_graph(graph: Dict) -> int:
    """Count total functions in nested call graph (excludes unknown file paths)"""
    file_path = graph.get("file", "unknown")
    count = 0 if file_path == "unknown" else 1
    calls = graph.get("calls", [])
    if isinstance(calls, str):
        return count
    for callee in calls:
        count += count_functions_in_graph(callee)
    return count


def main():
    parser = argparse.ArgumentParser(
        description="Extract focal function call graph to database"
    )
    parser.add_argument("--focal", required=True, help="Focal function name")
    parser.add_argument("--project", required=True, help="Project root directory")
    parser.add_argument("--db", required=True, help="SQLite database file")
    parser.add_argument("--file", help="File hint (e.g., 'common.cpp')")
    
    args = parser.parse_args()
    
    # Validate project path
    project_path = Path(args.project)
    if not project_path.exists():
        print(f"Error: Project path does not exist: {project_path}")
        sys.exit(1)
    
    print(f"Parsing project: {project_path}")
    
    # Initialize query_repo with project
    query_repo.init(str(project_path))
    
    # Build call graph for focal function
    print(f"\nBuilding call graph for: {args.focal}")
    file_hint = args.file if args.file else None
    
    call_graph = query_repo.build_call_graph(args.focal, file_path=file_hint)
    
    if call_graph["file"] == "unknown":
        print(f"\nError: Focal function '{args.focal}' not found in project")
        if args.file:
            print(f"  (searched with file hint: {args.file})")
        sys.exit(1)
    
    # Count functions in graph
    func_count = count_functions_in_graph(call_graph)
    print(f"\nExtracted {func_count} functions from call graph")
    
    # Initialize database
    index = SemanticIndex(args.db)
    index.init_schema()
    
    # Walk graph and populate DB
    print(f"\nAdding to database: {args.db}")
    func_map = {}
    walk_call_graph(call_graph, func_map, index)
    
    # Get stats
    stats = index.get_stats()
    
    print(f"\nComplete!")
    print(f"  Functions in DB: {stats['total_functions']}")
    print(f"  Call edges in DB: {stats['total_call_edges']}")
    print(f"  Leaf functions: {stats['leaf_functions']}")


if __name__ == "__main__":
    main()
