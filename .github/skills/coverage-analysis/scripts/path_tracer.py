#!/usr/bin/env python3
"""
Execution Path Tracer
=====================

PURPOSE:
    Helps trace execution paths through code by providing utilities
    for navigating source code and creating execution trace guides.

WHAT THIS SCRIPT DOES:
    1. Displays source code lines with context
    2. Extracts conditions from control flow statements
    3. Finds matching else blocks for if statements
    4. Finds block boundaries (function/loop ends)
    5. Creates interactive tracing guides for manual analysis

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT actually execute or run the code
    - Does NOT automatically trace paths (agent does this)
    - Does NOT determine which paths should be traced
    - Does NOT make coverage decisions

DESIGN NOTE:
    This is a HELPER TOOL for the agent's manual tracing process.
    The agent uses this to:
    - Navigate to specific lines
    - Extract conditions for branch analysis
    - Create structured guides for systematic tracing
    
    The actual path analysis is performed by the agent, who decides:
    - Which paths to trace
    - What values variables have
    - Which branches are taken
    - What the execution order is

USAGE:
    python path_tracer.py create-guide <source> <test> <test_name> <output>
    python path_tracer.py show-line <source> <line_num> [context]
    python path_tracer.py extract-condition <source> <line_num>
"""

import re
import json
import sys
from pathlib import Path
from typing import Set, Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict


@dataclass
class ExecutionStep:
    """
    Represents a single step in an execution trace.
    
    This is a DATA STRUCTURE for recording what the agent determines
    happens at each step of execution.
    
    Attributes:
        step_index: Sequential step number (1, 2, 3, ...)
        file: Source file containing this step
        line: Line number (1-based)
        code: The code being executed
        variables_before: Variable state before this step
        variables_after: Variable state after this step
        branch_taken: For conditionals - 'then', 'else', or None
        branch_condition: The condition expression
        branch_reason: Why this branch was taken (agent's explanation)
        notes: Any additional notes from the agent
    """
    step_index: int
    file: str
    line: int
    code: str
    variables_before: Dict[str, Any] = field(default_factory=dict)
    variables_after: Dict[str, Any] = field(default_factory=dict)
    branch_taken: Optional[str] = None  # 'then', 'else', None
    branch_condition: Optional[str] = None
    branch_reason: Optional[str] = None
    notes: str = ""


@dataclass
class ExecutionTrace:
    """
    Complete execution trace for a test.
    
    This is a CONTAINER for the trace data that the agent produces
    through manual analysis. The agent fills this in step by step.
    
    Attributes:
        test_name: Name of the test being traced
        source_file: Main source file being traced
        test_file: Test file containing the test
        steps: List of execution steps
        covered_lines: Set of lines that were covered
        covered_branches: Map of line -> set of branches taken
    """
    test_name: str
    source_file: str
    test_file: str
    steps: List[ExecutionStep] = field(default_factory=list)
    covered_lines: Set[int] = field(default_factory=set)
    covered_branches: Dict[int, Set[str]] = field(default_factory=dict)
    
    def add_step(self, step: ExecutionStep):
        """
        Add a step to the trace and update coverage.
        
        Automatically tracks:
        - Which lines were covered
        - Which branches were taken at each decision point
        
        Args:
            step: The execution step to add
        """
        self.steps.append(step)
        self.covered_lines.add(step.line)
        
        if step.branch_taken:
            if step.line not in self.covered_branches:
                self.covered_branches[step.line] = set()
            self.covered_branches[step.line].add(step.branch_taken)
    
    def export_json(self, output_file: str):
        """
        Export the trace to JSON format.
        
        Args:
            output_file: Path to write JSON output
        """
        data = {
            'test_name': self.test_name,
            'source_file': self.source_file,
            'test_file': self.test_file,
            'total_steps': len(self.steps),
            'covered_lines': sorted(list(self.covered_lines)),
            'covered_branches': {str(k): list(v) for k, v in self.covered_branches.items()},
            'steps': [asdict(step) for step in self.steps]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def export_covered_lines(self, output_file: str):
        """
        Export just the covered line numbers.
        
        Args:
            output_file: Path to write line numbers
        """
        with open(output_file, 'w') as f:
            f.write(f"# Covered lines from trace: {self.test_name}\n")
            f.write(f"# Total: {len(self.covered_lines)} lines\n\n")
            for line_num in sorted(self.covered_lines):
                f.write(f"{line_num}\n")


class PathTracer:
    """
    Interactive helper for path tracing.
    
    This class provides NAVIGATION utilities for the agent:
    - Show code at specific lines
    - Extract conditions from control flow
    - Find block boundaries
    
    The agent uses these utilities while manually tracing execution paths.
    """
    
    def __init__(self, source_file: str):
        """
        Initialize with a source file.
        
        Args:
            source_file: Path to the source file to navigate
        """
        self.source_file = Path(source_file)
        self.lines: List[str] = []
        
        with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
    
    def show_line(self, line_num: int, context: int = 2):
        """
        Display a line with surrounding context.
        
        Shows lines before and after to help understand code flow.
        The target line is marked with '>>>'.
        
        Args:
            line_num: Line number to display (1-based)
            context: Number of lines before/after to show
        """
        start = max(1, line_num - context)
        end = min(len(self.lines), line_num + context)
        
        for i in range(start - 1, end):
            num = i + 1
            marker = ">>>" if num == line_num else "   "
            print(f"{marker} {num:4d} | {self.lines[i].rstrip()}")
    
    def extract_condition(self, line_num: int) -> Optional[str]:
        """
        Extract the condition from a control flow statement.
        
        Handles:
        - if/while/for conditions: extracts content in parentheses
        - Ternary operators: extracts the condition before '?'
        
        Args:
            line_num: Line number to extract from (1-based)
            
        Returns:
            The condition expression, or None if not found
        """
        line = self.lines[line_num - 1]
        
        # if/while/for condition
        match = re.search(r'(if|while|for)\s*\((.+?)\)(?:\s*{)?', line)
        if match:
            return match.group(2).strip()
        
        # Ternary
        match = re.search(r'(.+?)\s*\?\s*(.+?)\s*:\s*(.+)', line)
        if match:
            return match.group(1).strip()
        
        return None
    
    def find_matching_else(self, if_line: int) -> Optional[int]:
        """
        Find the else block for an if statement.
        
        Tracks brace depth to find where the if block ends,
        then looks for 'else' keyword.
        
        Args:
            if_line: Line number of the if statement (1-based)
            
        Returns:
            Line number of the else, or None if no else exists
        """
        brace_depth = 0
        found_open = False
        
        for i in range(if_line - 1, len(self.lines)):
            line = self.lines[i]
            
            if '{' in line:
                found_open = True
            
            if found_open:
                brace_depth += line.count('{') - line.count('}')
                
                if brace_depth == 0:
                    # Check next non-empty line for else
                    for j in range(i + 1, min(i + 5, len(self.lines))):
                        if 'else' in self.lines[j]:
                            return j + 1
                    return None
        
        return None
    
    def find_block_end(self, start_line: int) -> int:
        """
        Find the end of a code block (function, loop, etc.).
        
        Tracks brace depth to find the closing brace.
        
        Args:
            start_line: Line number where block starts (1-based)
            
        Returns:
            Line number where block ends
        """
        brace_depth = 0
        found_open = False
        
        for i in range(start_line - 1, len(self.lines)):
            line = self.lines[i]
            
            if '{' in line:
                found_open = True
                brace_depth += line.count('{')
            
            if found_open:
                brace_depth -= line.count('}')
                
                if brace_depth == 0:
                    return i + 1
        
        return start_line


def create_interactive_guide(source_file: str, test_file: str, test_name: str, output_file: str):
    """
    Create an interactive tracing guide for a test.
    
    This generates a structured document that helps the agent
    systematically trace through a test's execution.
    
    The guide includes:
    - The test code with line numbers
    - Skeleton for each function call to fill in
    - Placeholders for covered lines, branches, and variables
    
    The agent then fills in the guide manually by analyzing
    the code and determining what happens at each step.
    
    Args:
        source_file: Path to the source file being tested
        test_file: Path to the test file
        test_name: Name of the test to trace
        output_file: Path to write the guide
    """
    
    with open(test_file, 'r') as f:
        test_lines = f.readlines()
    
    # Find test
    test_start = None
    for i, line in enumerate(test_lines):
        if f'{test_name}' in line and 'TEST' in line:
            test_start = i + 1
            break
    
    if not test_start:
        print(f"Test {test_name} not found")
        return
    
    # Find test end
    brace_count = 0
    test_end = test_start
    for j in range(test_start, len(test_lines)):
        brace_count += test_lines[j].count('{') - test_lines[j].count('}')
        if brace_count == 0:
            test_end = j + 1
            break
    
    # Create guide
    with open(output_file, 'w') as f:
        f.write(f"# Interactive Execution Trace Guide\n")
        f.write(f"# Test: {test_name}\n")
        f.write(f"# Source: {source_file}\n")
        f.write(f"# Test file: {test_file}\n\n")
        
        f.write("=" * 80 + "\n")
        f.write("TEST CODE\n")
        f.write("=" * 80 + "\n\n")
        
        for i in range(test_start - 1, test_end):
            f.write(f"{i+1:4d} | {test_lines[i].rstrip()}\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("EXECUTION TRACE - Fill in the blanks\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("""
Instructions:
1. Go through test code line by line
2. When a function is called, trace into source
3. Mark each line executed
4. For branches (if/while/for), note which path taken
5. Track variable values at key points

Format:
  CALL: <function_name> at source line <line>
    COVERED: <line1>, <line2>, <line3>, ...
    BRANCH <line>: <condition> => <then|else|symbolic>
    VARS: <var>=<value>, ...

""")
        
        # Extract function calls
        step_num = 1
        for i in range(test_start - 1, test_end):
            line = test_lines[i]
            
            # Look for function calls to source code
            patterns = [
                r'(\w*CongestionControl\w+)\s*\(',
                r'(Setup\w+)\s*\(',
                r'(Bbr\w+)\s*\(',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    func_name = match.group(1)
                    f.write(f"\n--- Step {step_num}: {test_lines[i].strip()[:70]} ---\n")
                    f.write(f"CALL: {func_name}\n")
                    f.write(f"  Source lines covered:\n")
                    f.write(f"  Branches:\n")
                    f.write(f"  Variables after:\n")
                    f.write(f"\n")
                    step_num += 1
                    break
    
    print(f"Guide created: {output_file}")
    print("Fill in the execution details manually")


def main():
    if len(sys.argv) < 2:
        print("""
Execution Path Tracer

Usage:
  python path_tracer.py <command> [options]

Commands:
  create-guide <source_file> <test_file> <test_name> <output>
    Create interactive tracing guide
    
  show-line <source_file> <line_num> [context]
    Show a specific line with context
    
  extract-condition <source_file> <line_num>
    Extract and display condition from control flow

Examples:
  python path_tracer.py create-guide bbr.c BbrTest.cpp StateTransition_DrainToProbeRtt_RttExpired guide.txt
  python path_tracer.py show-line bbr.c 797 5
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'create-guide':
        if len(sys.argv) < 6:
            print("Usage: path_tracer.py create-guide <source> <test> <test_name> <output>")
            sys.exit(1)
        
        create_interactive_guide(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    
    elif command == 'show-line':
        source_file = sys.argv[2]
        line_num = int(sys.argv[3])
        context = int(sys.argv[4]) if len(sys.argv) > 4 else 2
        
        tracer = PathTracer(source_file)
        tracer.show_line(line_num, context)
    
    elif command == 'extract-condition':
        source_file = sys.argv[2]
        line_num = int(sys.argv[3])
        
        tracer = PathTracer(source_file)
        condition = tracer.extract_condition(line_num)
        
        if condition:
            print(f"Line {line_num} condition: {condition}")
        else:
            print(f"No condition found at line {line_num}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
