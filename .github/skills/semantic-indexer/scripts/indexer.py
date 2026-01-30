#!/usr/bin/env python3
"""
Core semantic index with SQLite storage
"""

import sqlite3
import json
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List


class SemanticIndex:
    """Normalized semantic index with call graph storage"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.row_factory = sqlite3.Row
        
    def init_schema(self):
        """Initialize database schema"""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS functions (
                function_id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                file TEXT NOT NULL,
                start_line INTEGER,
                end_line INTEGER,
                summary TEXT DEFAULT '',
                UNIQUE(name, file)
            );
            
            CREATE TABLE IF NOT EXISTS preconditions (
                function_id INTEGER NOT NULL,
                condition_text TEXT NOT NULL,
                sequence_order INTEGER NOT NULL,
                FOREIGN KEY (function_id) REFERENCES functions(function_id) 
                    ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS postconditions (
                function_id INTEGER NOT NULL,
                condition_text TEXT NOT NULL,
                sequence_order INTEGER NOT NULL,
                FOREIGN KEY (function_id) REFERENCES functions(function_id) 
                    ON DELETE CASCADE
            );
            
            CREATE TABLE IF NOT EXISTS call_edges (
                caller_id INTEGER NOT NULL,
                callee_id INTEGER NOT NULL,
                PRIMARY KEY (caller_id, callee_id),
                FOREIGN KEY (caller_id) REFERENCES functions(function_id) 
                    ON DELETE CASCADE,
                FOREIGN KEY (callee_id) REFERENCES functions(function_id) 
                    ON DELETE CASCADE
            );
            
            CREATE INDEX IF NOT EXISTS idx_func_name ON functions(name);
            CREATE INDEX IF NOT EXISTS idx_func_file ON functions(file);
            CREATE INDEX IF NOT EXISTS idx_callees ON call_edges(caller_id);
            CREATE INDEX IF NOT EXISTS idx_callers ON call_edges(callee_id);
        """)
        self.conn.commit()
    
    def add_function(
        self, 
        name: str, 
        file: str, 
        start_line: int = 0,
        end_line: int = 0,
        summary: str = ""
    ) -> int:
        """Add function, return function_id"""
        try:
            cursor = self.conn.execute(
                """INSERT INTO functions (name, file, start_line, end_line, summary) 
                   VALUES (?, ?, ?, ?, ?)""",
                (name, file, start_line, end_line, summary)
            )
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Already exists
            cursor = self.conn.execute(
                """SELECT function_id FROM functions 
                   WHERE name = ? AND file = ?""",
                (name, file)
            )
            row = cursor.fetchone()
            return row[0] if row else None
    
    def add_call_edge(self, caller_id: int, callee_id: int):
        """Record call relationship"""
        try:
            self.conn.execute(
                "INSERT INTO call_edges (caller_id, callee_id) VALUES (?, ?)",
                (caller_id, callee_id)
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass  # Edge already exists
    
    def get_function_info(self, function_id: int) -> Optional[Dict]:
        """Get function details"""
        cursor = self.conn.execute(
            """SELECT function_id, name, file, start_line, end_line, summary
               FROM functions WHERE function_id = ?""",
            (function_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        
        return {
            "function_id": row[0],
            "name": row[1],
            "file": row[2],
            "start_line": row[3],
            "end_line": row[4],
            "summary": row[5]
        }
    
    def update_summary(self, function_id: int, summary: str):
        """Update function summary"""
        self.conn.execute(
            "UPDATE functions SET summary = ? WHERE function_id = ?",
            (summary, function_id)
        )
        self.conn.commit()
    
    def get_callees(self, function_id: int) -> List[Dict]:
        """Get all callees with their summaries"""
        cursor = self.conn.execute("""
            SELECT f.function_id, f.name, f.file, f.summary
            FROM call_edges ce
            JOIN functions f ON ce.callee_id = f.function_id
            WHERE ce.caller_id = ?
        """, (function_id,))
        
        return [
            {
                "function_id": row[0],
                "function": row[1],
                "file": row[2],
                "summary": row[3]
            }
            for row in cursor
        ]
    
    def get_function_tree(self, function_id: int, max_depth: Optional[int] = None) -> Dict:
        """Build nested tree of function with all callees"""
        return self._build_tree(function_id, max_depth, 0, set())
    
    def _build_tree(self, func_id: int, max_depth: Optional[int], depth: int, visited: set) -> Dict:
        """Recursive tree builder"""
        if func_id in visited:
            return {"cycle_detected": True}
        
        if max_depth is not None and depth >= max_depth:
            return {"max_depth_reached": True}
        
        visited.add(func_id)
        
        func = self.get_function_info(func_id)
        if not func:
            return {"error": "function not found"}
        
        # Get preconditions
        cursor = self.conn.execute(
            """SELECT condition_text FROM preconditions 
               WHERE function_id = ? ORDER BY sequence_order""",
            (func_id,)
        )
        preconditions = [row[0] for row in cursor]
        
        # Get postconditions
        cursor = self.conn.execute(
            """SELECT condition_text FROM postconditions 
               WHERE function_id = ? ORDER BY sequence_order""",
            (func_id,)
        )
        postconditions = [row[0] for row in cursor]
        
        # Get callees
        callees = []
        for callee in self.get_callees(func_id):
            callee_tree = self._build_tree(callee["function_id"], max_depth, depth + 1, visited.copy())
            callees.append(callee_tree)
        
        result = {
            "function": func["name"],
            "file": func["file"],
            "summary": func["summary"],
            "start_line": func["start_line"],
            "end_line": func["end_line"]
        }
        
        if preconditions:
            result["preconditions"] = preconditions
        if postconditions:
            result["postconditions"] = postconditions
        if callees:
            result["callees"] = callees
        
        return result
    
    def get_stats(self) -> Dict:
        """Database statistics"""
        stats = {}
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM functions")
        stats["total_functions"] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM call_edges")
        stats["total_call_edges"] = cursor.fetchone()[0]
        
        cursor = self.conn.execute(
            "SELECT COUNT(*) FROM functions WHERE summary != ''"
        )
        stats["summarized_functions"] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("""
            SELECT COUNT(*) FROM functions
            WHERE function_id NOT IN (SELECT DISTINCT caller_id FROM call_edges)
        """)
        stats["leaf_functions"] = cursor.fetchone()[0]
        
        return stats


def main():
    parser = argparse.ArgumentParser(description="Semantic Code Indexer")
    parser.add_argument("--db", required=True, help="Database file")
    subparsers = parser.add_subparsers(dest="command")
    
    # init
    subparsers.add_parser("init", help="Initialize database")
    
    # query
    query_parser = subparsers.add_parser("query", help="Query function tree")
    query_parser.add_argument("--focal", required=True, help="Focal function name")
    query_parser.add_argument("--depth", type=int, help="Max depth")
    query_parser.add_argument("--output", help="Output JSON file")
    
    # stats
    subparsers.add_parser("stats", help="Show statistics")
    
    # list
    subparsers.add_parser("list", help="List all functions")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    index = SemanticIndex(args.db)
    
    if args.command == "init":
        index.init_schema()
        print(f"Initialized: {args.db}")
    
    elif args.command == "query":
        # Find function
        cursor = index.conn.execute(
            "SELECT function_id FROM functions WHERE name = ? LIMIT 1",
            (args.focal,)
        )
        row = cursor.fetchone()
        
        if not row:
            print(f"Function not found: {args.focal}")
            return
        
        func_id = row[0]
        tree = index.get_function_tree(func_id, args.depth)
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(tree, f, indent=2)
            print(f"Wrote to: {args.output}")
        else:
            print(json.dumps(tree, indent=2))
    
    elif args.command == "stats":
        stats = index.get_stats()
        print("Database Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    elif args.command == "list":
        cursor = index.conn.execute("SELECT name, file FROM functions ORDER BY name")
        print("Functions in database:")
        for row in cursor:
            print(f"  {row[0]} ({row[1]})")


if __name__ == "__main__":
    main()
