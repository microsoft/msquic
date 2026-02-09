#!/usr/bin/env python3
"""
C/C++ Source Code Analyzer
==========================

PURPOSE:
    Analyzes C/C++ source code to identify executable lines, branch points,
    and function boundaries. Provides structural information for coverage analysis.

WHAT THIS SCRIPT DOES:
    1. Parses source files to identify function definitions and boundaries
    2. Identifies executable lines (lines that can be covered)
    3. Identifies branch points (if, switch, ternary, while, for)
    4. Exports analysis as JSON for further processing
    5. Provides statistics about code structure

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT execute or compile the code
    - Does NOT perform semantic analysis (type checking, etc.)
    - Does NOT determine which lines SHOULD be covered (that's a judgment)
    - Does NOT assess code quality
    - Does NOT handle all edge cases in complex C++ code

LIMITATIONS (agent should be aware):
    - Function detection uses heuristics, may miss complex templates
    - Executable line detection is approximate (macros, preprocessor directives)
    - Branch counting for switch statements scans for 'case' keywords
    - Does not handle all C++ constructs (lambdas, constexpr, etc.)

OUTPUT:
    JSON containing:
    - statistics: line counts, function counts, branch counts
    - executable_lines: list of line numbers that can be covered
    - functions: map of function name -> {start_line, end_line, signature}
    - branches: map of line number -> {type, condition, branch_count}

USAGE:
    python source_analyzer.py analyze <source_file> [--json out.json] [--txt out.txt]
    python source_analyzer.py show-function <source_file> <function_name>
    python source_analyzer.py stats <source_file>

DESIGN NOTE:
    This script extracts STRUCTURAL FACTS from source code. The agent uses
    these facts to:
    - Know which lines can be covered
    - Identify branch points for branch coverage
    - Find function boundaries for targeted analysis
"""

import re
import sys
import json
from pathlib import Path
from typing import Set, Dict, List
from dataclasses import dataclass, asdict


@dataclass
class FunctionInfo:
    """
    Information about a function in the source code.
    
    Attributes:
        name: Function name (identifier)
        start_line: First line of the function (1-based)
        end_line: Last line of the function (1-based)
        signature: Full function signature text
    """
    name: str
    start_line: int
    end_line: int
    signature: str


@dataclass
class BranchInfo:
    """
    Information about a branch point in the code.
    
    Attributes:
        line: Line number of the branch (1-based)
        type: Type of branch - 'if', 'switch', 'ternary', 'while', 'for'
        condition: The condition expression (if extractable)
        branch_count: Number of possible paths (2 for if, N for switch)
    """
    line: int
    type: str  # 'if', 'switch', 'ternary', 'while', 'for'
    condition: str
    branch_count: int  # Number of possible paths


class SourceAnalyzer:
    """
    Analyzes C/C++ source code structure.
    
    This class performs STRUCTURAL EXTRACTION:
    - Finds functions using pattern matching (heuristic)
    - Identifies executable lines (approximate)
    - Locates branch points
    
    LIMITATIONS the agent should know:
    - Complex macros may confuse line detection
    - Templates and complex C++ may not parse correctly
    - Inline assembly is not handled
    - Preprocessor conditions (#if) are not tracked
    """
    
    def __init__(self, source_file: str):
        """
        Initialize analyzer with a source file.
        
        Args:
            source_file: Path to the C/C++ source file
        """
        self.source_file = Path(source_file)
        self.lines: List[str] = []
        self.executable_lines: Set[int] = set()
        self.branches: Dict[int, BranchInfo] = {}
        self.functions: Dict[str, FunctionInfo] = {}
        
    def load_source(self):
        """Load source file contents into memory."""
        with open(self.source_file, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
    
    def analyze(self):
        """
        Run full structural analysis on the source file.
        
        This performs three passes:
        1. Find function definitions and boundaries
        2. Identify executable lines
        3. Identify branch points
        """
        self.load_source()
        self.find_functions()
        self.find_executable_lines()
        self.find_branches()
    
    def find_functions(self):
        """
        Find all function definitions in the source file.
        
        ALGORITHM:
        - Look for lines containing '(' that might be function signatures
        - Look ahead for opening brace '{'
        - Extract function name using regex
        - Track brace depth to find function end
        
        LIMITATIONS:
        - May be confused by macros that look like functions
        - Complex C++ templates may not parse correctly
        - Function pointers in parameters may cause issues
        """
        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            
            # Look for function definition pattern
            # Pattern: _IRQL_requires_max_ or other attributes, then return_type func_name(
            # or just: return_type func_name(
            
            # Check if this looks like a function signature
            if '(' in line and not line.strip().startswith('//'):
                # Look ahead for opening brace
                brace_line = None
                for j in range(i, min(i + 10, len(self.lines))):
                    if '{' in self.lines[j]:
                        brace_line = j
                        break
                
                if brace_line is not None:
                    # Extract function name
                    func_match = re.search(r'\b(\w+)\s*\(', line)
                    if func_match:
                        func_name = func_match.group(1)
                        
                        # Skip common keywords
                        if func_name in ['if', 'while', 'for', 'switch', 'sizeof', 'return']:
                            i += 1
                            continue
                        
                        # Find closing brace
                        brace_depth = 0
                        end_line = brace_line
                        for j in range(brace_line, len(self.lines)):
                            brace_depth += self.lines[j].count('{') - self.lines[j].count('}')
                            if brace_depth == 0:
                                end_line = j
                                break
                        
                        # Get signature (combine lines until opening brace)
                        signature_lines = []
                        for j in range(i, brace_line):
                            signature_lines.append(self.lines[j].strip())
                        signature = ' '.join(signature_lines)
                        
                        self.functions[func_name] = FunctionInfo(
                            name=func_name,
                            start_line=i + 1,
                            end_line=end_line + 1,
                            signature=signature
                        )
                        
                        i = end_line + 1
                        continue
            
            i += 1
    
    def find_executable_lines(self):
        """
        Identify all executable lines of code.
        
        ALGORITHM:
        - Track multi-line comments
        - Skip preprocessor directives (#define, #include, etc.)
        - Skip pure declarations without initialization
        - Include control flow statements (if, while, for, etc.)
        - Include statements with assignments, calls, or operators
        - Include return statements
        
        WHAT COUNTS AS EXECUTABLE:
        - Statements ending with ';' that have side effects
        - Control flow keywords (if, while, for, switch, else)
        - Function calls
        - Assignments
        - Return statements
        
        WHAT DOES NOT COUNT:
        - Comments
        - Blank lines
        - Preprocessor directives
        - Type definitions (typedef, struct, enum declarations)
        - Pure declarations without initialization
        - Standalone braces { }
        - Labels and case labels
        
        NOTE: This is APPROXIMATE. The agent should verify if specific
        lines are truly executable for their analysis.
        """
        in_multiline_comment = False
        in_function_body = False
        brace_depth = 0
        
        for i, line in enumerate(self.lines, 1):
            stripped = line.strip()
            
            # Handle multi-line comments
            if '/*' in stripped and '*/' not in stripped:
                in_multiline_comment = True
            if in_multiline_comment:
                if '*/' in stripped:
                    in_multiline_comment = False
                continue
            
            # Remove inline comments for analysis
            if '//' in stripped:
                stripped = stripped.split('//')[0].strip()
            if '/*' in stripped and '*/' in stripped:
                # Remove inline /* */ comments
                stripped = re.sub(r'/\*.*?\*/', '', stripped).strip()
            
            # Skip empty lines
            if not stripped:
                continue
            
            # Skip preprocessor directives
            if stripped.startswith('#'):
                continue
            
            # Track brace depth
            brace_depth += stripped.count('{') - stripped.count('}')
            if brace_depth > 0:
                in_function_body = True
            elif brace_depth == 0:
                in_function_body = False
            
            # Skip lines outside function bodies
            if not in_function_body and brace_depth == 0:
                # Could be global variables/constants - check if they have initialization
                if '=' in stripped and ';' in stripped and not stripped.startswith('typedef'):
                    # Global initialization might be executable
                    pass
                else:
                    continue
            
            # Skip standalone braces and labels
            if stripped in ['{', '}', '};']:
                continue
            if re.match(r'^\w+:$', stripped):  # Labels
                continue
            if re.match(r'^(case\s+.*|default)\s*:$', stripped):  # Case labels
                continue
            
            # Skip type definitions
            if stripped.startswith('typedef '):
                continue
            if re.match(r'^(struct|enum|union)\s+\w+\s*{', stripped):
                continue
            
            # Skip function declarations (not definitions)
            if ';' in stripped and '{' not in stripped and '(' in stripped:
                # Likely a declaration
                if not any(op in stripped for op in ['=', '++', '--', '+=', '-=', 'return']):
                    continue
            
            # Now check if line is executable
            is_executable = False
            
            # Control flow statements
            if any(kw in stripped for kw in [
                'if (', 'else if', 'while (', 'for (', 'do ', 'switch ('
            ]):
                is_executable = True
            
            # else keyword
            if stripped == 'else' or stripped.startswith('else ') or stripped.startswith('else{'):
                is_executable = True
            
            # Statements with semicolons
            if ';' in stripped:
                # Exclude pure declarations (heuristic)
                if any(indicator in stripped for indicator in [
                    '=', '(', 'return', '++', '--', '+=', '-=', '*=', '/=',
                    'break', 'continue', 'goto'
                ]):
                    is_executable = True
            
            # Function calls (even without semicolon on same line)
            if '(' in stripped and ')' in stripped:
                # Check if it's a function call, not a declaration
                if not stripped.endswith(';') and not stripped.endswith('{'):
                    # Could be multi-line call
                    pass
                elif '=' in stripped or brace_depth > 0:
                    is_executable = True
            
            # return statements
            if stripped.startswith('return'):
                is_executable = True
            
            if is_executable:
                self.executable_lines.add(i)
    
    def find_branches(self):
        """
        Identify branch points in the code.
        
        BRANCH TYPES DETECTED:
        - if statements (2 branches: then, else)
        - switch statements (N branches based on case count)
        - ternary operators ? : (2 branches)
        - while loops (2 branches: enter, skip)
        - for loops (2 branches: enter, skip)
        
        NOTE: This counts DECISION POINTS, not all possible paths.
        For full path coverage, the agent must analyze combinations.
        """
        for i, line in enumerate(self.lines, 1):
            stripped = line.strip()
            
            if i not in self.executable_lines:
                continue
            
            # if statements
            if re.search(r'\bif\s*\(', stripped):
                cond_match = re.search(r'if\s*\((.+)', stripped)
                condition = cond_match.group(1) if cond_match else ""
                self.branches[i] = BranchInfo(
                    line=i,
                    type='if',
                    condition=condition,
                    branch_count=2
                )
            
            # switch statements
            elif re.search(r'\bswitch\s*\(', stripped):
                # Count case statements
                case_count = 0
                for j in range(i + 1, min(i + 100, len(self.lines))):
                    if re.search(r'\bcase\s+', self.lines[j]):
                        case_count += 1
                    if stripped == '}':
                        break
                
                self.branches[i] = BranchInfo(
                    line=i,
                    type='switch',
                    condition="",
                    branch_count=max(case_count, 2)
                )
            
            # Ternary operators
            elif '?' in stripped and ':' in stripped:
                self.branches[i] = BranchInfo(
                    line=i,
                    type='ternary',
                    condition="",
                    branch_count=2
                )
            
            # while loops (have branches - enter or skip)
            elif re.search(r'\bwhile\s*\(', stripped):
                self.branches[i] = BranchInfo(
                    line=i,
                    type='while',
                    condition="",
                    branch_count=2
                )
            
            # for loops
            elif re.search(r'\bfor\s*\(', stripped):
                self.branches[i] = BranchInfo(
                    line=i,
                    type='for',
                    condition="",
                    branch_count=2
                )
    
    def get_statistics(self) -> Dict:
        """
        Get summary statistics about the analyzed code.
        
        Returns dict with:
        - total_lines: Total lines in file
        - executable_lines: Count of executable lines
        - function_count: Number of functions found
        - branch_points: Number of branch decision points
        - total_branches: Sum of all possible branch paths
        """
        total_branches = sum(b.branch_count for b in self.branches.values())
        
        return {
            'total_lines': len(self.lines),
            'executable_lines': len(self.executable_lines),
            'function_count': len(self.functions),
            'branch_points': len(self.branches),
            'total_branches': total_branches
        }
    
    def export_json(self, output_file: str):
        """
        Export analysis results to JSON format.
        
        JSON structure:
        {
            "source_file": "path/to/file.c",
            "statistics": {...},
            "executable_lines": [1, 5, 7, ...],
            "functions": {"func_name": {start, end, signature}, ...},
            "branches": {"line": {type, condition, branch_count}, ...}
        }
        
        Args:
            output_file: Path to write JSON output
        """
        data = {
            'source_file': str(self.source_file),
            'statistics': self.get_statistics(),
            'executable_lines': sorted(list(self.executable_lines)),
            'functions': {name: asdict(info) for name, info in self.functions.items()},
            'branches': {str(line): asdict(info) for line, info in self.branches.items()}
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def export_executable_lines(self, output_file: str):
        """
        Export executable lines in human-readable format for review.
        
        Output format:
          line_number | code
        
        Lines can be marked with '*' prefix to indicate coverage,
        then imported back using import_marked_lines().
        
        Args:
            output_file: Path to write text output
        """
        with open(output_file, 'w') as f:
            f.write(f"# Executable lines in: {self.source_file.name}\n")
            f.write(f"# Total: {len(self.executable_lines)} lines\n")
            f.write("# Format: line_number | code\n")
            f.write("# Mark covered lines with '*' prefix to import later\n\n")
            
            for line_num in sorted(self.executable_lines):
                line_text = self.lines[line_num - 1].rstrip()
                f.write(f"  {line_num:4d} | {line_text}\n")
    
    def import_marked_lines(self, marked_file: str) -> Set[int]:
        """
        Import lines that were marked as covered.
        
        Reads a file created by export_executable_lines() where
        lines prefixed with '*' indicate they were covered.
        
        Args:
            marked_file: Path to the marked file
            
        Returns:
            Set of line numbers that were marked as covered
        """
        covered = set()
        
        with open(marked_file, 'r') as f:
            for line in f:
                if line.strip().startswith('*'):
                    # Extract line number
                    match = re.search(r'\*?\s*(\d+)\s*\|', line)
                    if match:
                        covered.add(int(match.group(1)))
        
        return covered


def main():
    if len(sys.argv) < 2:
        print("""
C/C++ Source Code Analyzer

Usage:
  python source_analyzer.py <command> <source_file> [options]

Commands:
  analyze <source_file> [--json <output.json>] [--txt <output.txt>]
    Analyze source file and export results
    
  show-function <source_file> <function_name>
    Display a specific function with line numbers
    
  show-executable <source_file>
    List all executable lines
    
  stats <source_file>
    Show analysis statistics

Examples:
  python source_analyzer.py analyze bbr.c --json bbr_analysis.json
  python source_analyzer.py show-function bbr.c BbrCongestionControlInitialize
  python source_analyzer.py stats bbr.c
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'analyze':
        if len(sys.argv) < 3:
            print("Usage: source_analyzer.py analyze <source_file> [--json out.json] [--txt out.txt]")
            sys.exit(1)
        
        source_file = sys.argv[2]
        json_output = None
        txt_output = None
        
        # Parse optional arguments
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == '--json' and i + 1 < len(sys.argv):
                json_output = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--txt' and i + 1 < len(sys.argv):
                txt_output = sys.argv[i + 1]
                i += 2
            else:
                i += 1
        
        analyzer = SourceAnalyzer(source_file)
        analyzer.analyze()
        
        stats = analyzer.get_statistics()
        print(f"Analyzed: {source_file}")
        print(f"  Total lines: {stats['total_lines']}")
        print(f"  Executable lines: {stats['executable_lines']}")
        print(f"  Functions: {stats['function_count']}")
        print(f"  Branch points: {stats['branch_points']}")
        print(f"  Total branches: {stats['total_branches']}")
        
        if json_output:
            analyzer.export_json(json_output)
            print(f"\nJSON exported to: {json_output}")
        
        if txt_output:
            analyzer.export_executable_lines(txt_output)
            print(f"Executable lines exported to: {txt_output}")
    
    elif command == 'show-function':
        if len(sys.argv) < 4:
            print("Usage: source_analyzer.py show-function <source_file> <function_name>")
            sys.exit(1)
        
        source_file = sys.argv[2]
        func_name = sys.argv[3]
        
        analyzer = SourceAnalyzer(source_file)
        analyzer.analyze()
        
        if func_name in analyzer.functions:
            func = analyzer.functions[func_name]
            print(f"\nFunction: {func.name}")
            print(f"Lines: {func.start_line}-{func.end_line}")
            print(f"Signature: {func.signature}\n")
            
            # Show function code
            for i in range(func.start_line - 1, min(func.end_line, len(analyzer.lines))):
                line_num = i + 1
                is_exec = "✓" if line_num in analyzer.executable_lines else " "
                is_branch = "B" if line_num in analyzer.branches else " "
                print(f"  [{is_exec}{is_branch}] {line_num:4d} | {analyzer.lines[i].rstrip()}")
        else:
            print(f"Function '{func_name}' not found")
            print(f"Available functions: {', '.join(sorted(analyzer.functions.keys())[:10])}...")
    
    elif command == 'show-executable':
        if len(sys.argv) < 3:
            print("Usage: source_analyzer.py show-executable <source_file>")
            sys.exit(1)
        
        source_file = sys.argv[2]
        
        analyzer = SourceAnalyzer(source_file)
        analyzer.analyze()
        
        print(f"Executable lines in {source_file}:")
        for line_num in sorted(analyzer.executable_lines):
            print(f"  {line_num:4d} | {analyzer.lines[line_num - 1].rstrip()}")
    
    elif command == 'stats':
        if len(sys.argv) < 3:
            print("Usage: source_analyzer.py stats <source_file>")
            sys.exit(1)
        
        source_file = sys.argv[2]
        
        analyzer = SourceAnalyzer(source_file)
        analyzer.analyze()
        
        stats = analyzer.get_statistics()
        print(f"\n=== Analysis Statistics ===")
        print(f"File: {source_file}")
        print(f"Total lines: {stats['total_lines']}")
        print(f"Executable lines: {stats['executable_lines']}")
        print(f"Functions: {stats['function_count']}")
        print(f"Branch points: {stats['branch_points']}")
        print(f"Total branches: {stats['total_branches']}")
        
        print(f"\n=== Functions ===")
        for name, info in sorted(analyzer.functions.items()):
            print(f"  {name:40s} lines {info.start_line:4d}-{info.end_line:4d}")
    
    else:
        print(f"Unknown command: {command}")
        print("Run without arguments for help")
        sys.exit(1)


if __name__ == "__main__":
    main()
