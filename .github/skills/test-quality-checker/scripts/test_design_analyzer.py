#!/usr/bin/env python3
"""
Test Code Extractor
===================

PURPOSE:
    Extracts test code and deterministic patterns for analysis by an agent.
    Provides raw data without making any quality judgments.

WHAT THIS SCRIPT DOES:
    1. Detects programming language from file extension
    2. Locates test function boundaries (if test name provided)
    3. Extracts all numeric literals found in the code
    4. Extracts all function/method calls found in the code
    5. Extracts language-specific keywords (global, static, etc.)
    6. Extracts all comments (description, inline, block)
    7. Provides raw test code lines for additional analysis

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT identify "magic numbers" (agent decides what's magic vs acceptable)
    - Does NOT classify functions as "dangerous" or "safe"
    - Does NOT determine if sleep/rand/time calls are problematic
    - Does NOT identify setup/teardown/assertion phases
    - Does NOT judge test structure or design quality
    - Does NOT assess comment-test conformity (agent does this)
    - Does NOT score or rate anything
    - Does NOT make any qualitative judgments

OUTPUT:
    JSON containing:
    - Raw code lines with line numbers
    - All numbers found (agent decides which are "magic")
    - All function calls found (agent decides which are external/risky)
    - All language keywords found (agent decides implications)
    - All comments found (agent assesses comment-test conformity)

WHY RAW DATA:
    The script extracts FACTS. The agent applies JUDGMENT.
    
    Example: Script finds "sleep(100)" on line 15
    - Script reports: {line: 15, name: "sleep", context: "sleep(100)"}
    - Agent decides: Is this a flakiness risk? Is it intentional? Is it acceptable?
    
    Example: Script finds comment "// Test that divide by zero throws exception"
    - Script reports: {line: 5, type: "inline", content: "Test that divide by zero throws exception"}
    - Agent decides: Does the test actually test divide by zero? Does it check for exception?

USAGE:
    python test_design_analyzer.py extract <test_file> [--test <test_name>] [--json <output.json>]
"""

import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class TestInfo:
    """
    Extracted information from a test file.
    
    This dataclass holds FACTUAL data only - no quality judgments.
    
    Attributes:
        test_file: Path to the analyzed file
        test_name: Name of specific test function (if provided)
        language: Detected programming language
        start_line: First line of the test (1-based)
        end_line: Last line of the test
        line_count: Number of lines in the test
        code: Complete test code as a string
        lines: List of {number, content} for each line
        numbers_found: All numeric literals found - agent decides which are "magic"
        function_calls: All function calls found - agent decides which are risky
        keywords_found: Language keywords found - agent decides implications
        comments: All comments found - agent assesses comment-test conformity
    """
    test_file: str
    test_name: Optional[str]
    language: str
    start_line: int
    end_line: int
    line_count: int
    code: str
    lines: List[Dict]
    numbers_found: List[Dict]
    function_calls: List[Dict]
    keywords_found: List[Dict]
    comments: Dict  # Contains description_comment, inline_comments, block_comments


class TestExtractor:
    """
    Extracts test code and patterns using deterministic methods.
    
    DESIGN PHILOSOPHY:
        This class performs EXTRACTION only, not ANALYSIS.
        - Pattern matching is deterministic (regex)
        - No heuristics or judgment calls
        - No classification of "good" vs "bad"
        
    The agent using this output is responsible for:
        - Determining which numbers are "magic numbers"
        - Identifying which function calls indicate external dependencies
        - Recognizing flakiness risks (sleep, random, time)
        - Evaluating test structure (setup/action/assertion phases)
        - Any qualitative analysis
    
    WHY THIS SEPARATION:
        - Scripts can be wrong about judgment calls
        - Agent can apply context-specific reasoning
        - Raw data allows agent to find patterns we didn't anticipate
    """
    
    # ==========================================================================
    # PATTERNS FOR EXTRACTION
    # ==========================================================================
    # These patterns extract FACTS, not judgments.
    # The agent interprets the extracted data.
    # ==========================================================================
    
    # Pattern to find numeric literals
    # Matches: 42, 100, 3.14, 0xFF, etc.
    # Agent decides: Is this a "magic number" or an acceptable constant?
    NUMBER_PATTERN = r'(?<![a-zA-Z_])(\d+)(?![a-zA-Z_\d])'
    
    # Pattern to find function/method calls
    # Matches: foo(), bar(x), obj.method()
    # Agent decides: Is this an external dependency? A flakiness risk?
    FUNCTION_CALL_PATTERN = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
    
    # Language keywords to extract
    # These are FACTUAL presences, not quality judgments
    # Agent decides: Is this global variable problematic? Is static state an issue?
    KEYWORD_PATTERNS = {
        'c': [
            (r'\bglobal\b', 'global'),
            (r'\bstatic\b', 'static'),
            (r'\bextern\b', 'extern'),
            (r'\bvolatile\b', 'volatile'),
        ],
        'cpp': [
            (r'\bglobal\b', 'global'),
            (r'\bstatic\b', 'static'),
            (r'\bextern\b', 'extern'),
            (r'\bvolatile\b', 'volatile'),
            (r'\bmutable\b', 'mutable'),
        ],
        'python': [
            (r'\bglobal\b', 'global'),
            (r'\bnonlocal\b', 'nonlocal'),
        ],
        'javascript': [
            (r'\bvar\b', 'var'),
            (r'\blet\b', 'let'),
            (r'\bconst\b', 'const'),
        ],
        'java': [
            (r'\bstatic\b', 'static'),
            (r'\bvolatile\b', 'volatile'),
            (r'\bsynchronized\b', 'synchronized'),
        ],
    }
    
    def __init__(self, test_file: str):
        """
        Initialize the extractor with a test file path.
        
        Args:
            test_file: Path to the test file to analyze
        """
        self.test_file = Path(test_file)
        self.lines: List[str] = []
        self.language = self._detect_language()
        
    def _detect_language(self) -> str:
        """
        Detect programming language from file extension.
        
        This is DETERMINISTIC - simple extension mapping.
        Returns 'unknown' for unrecognized extensions.
        """
        ext = self.test_file.suffix.lower()
        lang_map = {
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp',
            '.py': 'python',
            '.js': 'javascript', '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
        }
        return lang_map.get(ext, 'unknown')
    
    def load_file(self):
        """Load the test file contents into memory."""
        with open(self.test_file, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
    
    def extract(self, test_name: Optional[str] = None) -> TestInfo:
        """
        Extract test code and patterns.
        
        This method extracts FACTS only:
        - Raw code lines
        - All numbers found (not judged as magic/acceptable)
        - All function calls (not judged as safe/risky)
        - All keywords (not judged as problematic/fine)
        - All comments (not judged for conformity with test behavior)
        
        Args:
            test_name: Optional name of specific test function.
                      If None, extracts from entire file.
        
        Returns:
            TestInfo containing extracted data for agent analysis.
        
        Note: The agent MUST analyze this data to make judgments about:
            - Test structure (setup/action/assert phases)
            - Magic numbers vs acceptable constants
            - Risky function calls (sleep, rand, fopen, etc.)
            - Problematic patterns (global state, etc.)
            - Comment-test conformity (does test match what comments describe?)
        """
        self.load_file()
        
        # Find test boundaries - deterministic based on language patterns
        if test_name:
            start_line, end_line = self._find_test_boundaries(test_name)
        else:
            start_line, end_line = 0, len(self.lines)
        
        test_lines = self.lines[start_line:end_line]
        
        # Build line-by-line data for agent's analysis
        # Agent can look for any patterns we didn't extract
        lines_data = []
        for i, line in enumerate(test_lines):
            lines_data.append({
                "number": start_line + i + 1,
                "content": line.rstrip('\n\r')
            })
        
        # Extract deterministic patterns
        # Agent interprets these - we just report what we found
        numbers = self._extract_numbers(test_lines, start_line)
        function_calls = self._extract_function_calls(test_lines, start_line)
        keywords = self._extract_keywords(test_lines, start_line)
        
        # Extract comments - agent assesses if test matches what comments describe
        comments = self._extract_comments(test_lines, start_line, test_name)
        
        return TestInfo(
            test_file=str(self.test_file),
            test_name=test_name,
            language=self.language,
            start_line=start_line + 1,
            end_line=end_line,
            line_count=len(test_lines),
            code=''.join(test_lines),
            lines=lines_data,
            numbers_found=numbers,
            function_calls=function_calls,
            keywords_found=keywords,
            comments=comments
        )
    
    def _find_test_boundaries(self, test_name: str) -> tuple:
        """
        Find the start and end lines of a specific test function.
        
        Uses language-specific patterns to find function definitions.
        Falls back to entire file if test not found.
        
        Args:
            test_name: Name of the test function to find
            
        Returns:
            Tuple of (start_line, end_line) - 0-based indices
        """
        test_patterns = {
            'c': [
                r'^(?:void\s+)?(' + re.escape(test_name) + r')\s*\(',
                r'^START_TEST\s*\(\s*' + re.escape(test_name) + r'\s*\)',
            ],
            'cpp': [
                r'TEST\s*\(\s*\w+\s*,\s*' + re.escape(test_name) + r'\s*\)',
                r'TEST_F\s*\(\s*\w+\s*,\s*' + re.escape(test_name) + r'\s*\)',
                r'TEST_CASE\s*\(\s*["\']' + re.escape(test_name) + r'["\']',
            ],
            'python': [
                r'^def\s+' + re.escape(test_name) + r'\s*\(',
                r'^\s+def\s+' + re.escape(test_name) + r'\s*\(',
            ],
            'javascript': [
                r'(?:test|it)\s*\(\s*[\'"]' + re.escape(test_name) + r'[\'"]',
            ],
            'typescript': [
                r'(?:test|it)\s*\(\s*[\'"]' + re.escape(test_name) + r'[\'"]',
            ],
            'java': [
                r'(?:public\s+)?void\s+' + re.escape(test_name) + r'\s*\(',
                r'@Test.*\n.*void\s+' + re.escape(test_name) + r'\s*\(',
            ],
            'go': [
                r'func\s+' + re.escape(test_name) + r'\s*\(',
            ],
            'rust': [
                r'fn\s+' + re.escape(test_name) + r'\s*\(',
            ],
        }
        
        patterns = test_patterns.get(self.language, [])
        
        for i, line in enumerate(self.lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    end = self._find_function_end(i)
                    return (i, end)
        
        # Test not found - return entire file
        return (0, len(self.lines))
    
    def _find_function_end(self, start: int) -> int:
        """
        Find the end of a function starting at the given line.
        
        Uses language-appropriate detection:
        - Python: Indentation-based
        - Others: Brace matching
        
        Args:
            start: Starting line index (0-based)
            
        Returns:
            End line index (exclusive)
        """
        if self.language == 'python':
            # Python uses indentation
            if start + 1 >= len(self.lines):
                return len(self.lines)
            first_line = self.lines[start]
            base_indent = len(first_line) - len(first_line.lstrip())
            for i in range(start + 1, len(self.lines)):
                line = self.lines[i]
                if line.strip() and not line.strip().startswith('#'):
                    indent = len(line) - len(line.lstrip())
                    if indent <= base_indent:
                        return i
            return len(self.lines)
        else:
            # Brace-based languages
            brace_depth = 0
            found_open = False
            for i in range(start, len(self.lines)):
                for char in self.lines[i]:
                    if char == '{':
                        brace_depth += 1
                        found_open = True
                    elif char == '}':
                        brace_depth -= 1
                        if found_open and brace_depth == 0:
                            return i + 1
            return len(self.lines)
    
    def _extract_numbers(self, lines: List[str], offset: int) -> List[Dict]:
        """
        Extract all numeric literals found in the code.
        
        This extracts ALL numbers. The agent decides:
        - Which are "magic numbers"
        - Which are acceptable (0, 1, common sizes, etc.)
        - Which need named constants
        
        Args:
            lines: Lines of code to search
            offset: Line number offset for reporting
            
        Returns:
            List of {line, value, context} for each number found
        """
        result = []
        for i, line in enumerate(lines):
            # Skip pure comment lines (but agent can re-examine raw_lines)
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
                continue
            
            matches = re.finditer(self.NUMBER_PATTERN, line)
            for match in matches:
                result.append({
                    "line": i + offset + 1,
                    "value": match.group(1),
                    "context": line.strip()
                })
        return result
    
    def _extract_function_calls(self, lines: List[str], offset: int) -> List[Dict]:
        """
        Extract all function/method calls found in the code.
        
        This extracts ALL calls. The agent decides:
        - Which are external dependencies (fopen, socket, etc.)
        - Which are flakiness risks (sleep, rand, time, etc.)
        - Which are normal/expected
        
        Args:
            lines: Lines of code to search
            offset: Line number offset for reporting
            
        Returns:
            List of {line, name, context} for each function call found
        """
        result = []
        for i, line in enumerate(lines):
            # Skip pure comment lines
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
                continue
            
            matches = re.finditer(self.FUNCTION_CALL_PATTERN, line)
            for match in matches:
                func_name = match.group(1)
                # Skip obvious control flow keywords (not function calls)
                if func_name not in ['if', 'while', 'for', 'switch', 'catch', 'sizeof', 'typeof']:
                    result.append({
                        "line": i + offset + 1,
                        "name": func_name,
                        "context": line.strip()
                    })
        return result
    
    def _extract_keywords(self, lines: List[str], offset: int) -> List[Dict]:
        """
        Extract language-specific keywords found in the code.
        
        This extracts keyword PRESENCES. The agent decides:
        - Is this global variable problematic?
        - Is this static state causing test interdependence?
        - Are these keywords used appropriately?
        
        Args:
            lines: Lines of code to search
            offset: Line number offset for reporting
            
        Returns:
            List of {line, keyword, context} for each keyword found
        """
        result = []
        patterns = self.KEYWORD_PATTERNS.get(self.language, [])
        
        for i, line in enumerate(lines):
            for pattern, keyword in patterns:
                if re.search(pattern, line):
                    result.append({
                        "line": i + offset + 1,
                        "keyword": keyword,
                        "context": line.strip()
                    })
        return result
    
    def _extract_comments(self, lines: List[str], offset: int, test_name: Optional[str] = None) -> Dict:
        """
        Extract all comments from the test code.
        
        This extracts comments DETERMINISTICALLY. The agent decides:
        - Does the test actually do what the description comment says?
        - Are inline comments accurate descriptions of what the code does?
        - Is there a mismatch between comments and actual test behavior?
        
        COMMENT TYPES EXTRACTED:
        1. description_comment: The comment block immediately before the test function
           (docstring, block comment, or consecutive line comments)
        2. inline_comments: Single-line comments within the test (// or #)
        3. block_comments: Multi-line /* */ comments within the test
        
        The agent should assess COMMENT-TEST CONFORMITY:
        - If comment says "test divide by zero", does test actually test that?
        - If comment says "should throw exception", does test verify exception?
        - If comment describes setup, does code actually do that setup?
        
        Args:
            lines: Lines of test code
            offset: Line number offset for reporting
            test_name: Name of test (used to find description comment)
            
        Returns:
            Dict with:
            - description_comment: {lines: [...], text: "full text"}
            - inline_comments: [{line, content}]
            - block_comments: [{start_line, end_line, content}]
        """
        result = {
            "description_comment": None,
            "inline_comments": [],
            "block_comments": []
        }
        
        # Extract description comment (comment block before test function)
        if test_name and offset > 0:
            result["description_comment"] = self._extract_description_comment(offset)
        
        # Extract inline and block comments within the test
        in_block_comment = False
        block_start = None
        block_content = []
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + offset + 1
            
            # Handle block comments (/* ... */)
            if '/*' in stripped and '*/' in stripped:
                # Single-line block comment
                match = re.search(r'/\*(.+?)\*/', stripped)
                if match:
                    result["block_comments"].append({
                        "start_line": line_num,
                        "end_line": line_num,
                        "content": match.group(1).strip()
                    })
            elif '/*' in stripped:
                # Start of multi-line block comment
                in_block_comment = True
                block_start = line_num
                # Get content after /*
                idx = stripped.index('/*')
                block_content = [stripped[idx + 2:].strip()]
            elif in_block_comment:
                if '*/' in stripped:
                    # End of block comment
                    idx = stripped.index('*/')
                    block_content.append(stripped[:idx].lstrip('* ').strip())
                    result["block_comments"].append({
                        "start_line": block_start,
                        "end_line": line_num,
                        "content": ' '.join(c for c in block_content if c)
                    })
                    in_block_comment = False
                    block_content = []
                else:
                    # Middle of block comment
                    block_content.append(stripped.lstrip('* ').strip())
            
            # Handle inline comments
            elif not in_block_comment:
                # C-style // comments
                if '//' in stripped:
                    idx = stripped.index('//')
                    comment_text = stripped[idx + 2:].strip()
                    if comment_text:  # Only non-empty comments
                        result["inline_comments"].append({
                            "line": line_num,
                            "content": comment_text
                        })
                
                # Python/shell # comments (but not in strings)
                elif self.language in ['python', 'shell', 'ruby'] and '#' in stripped:
                    # Simple heuristic: if line starts with # or has # not in quotes
                    if stripped.startswith('#'):
                        comment_text = stripped[1:].strip()
                        if comment_text:
                            result["inline_comments"].append({
                                "line": line_num,
                                "content": comment_text
                            })
                    else:
                        # Try to find # not in a string (simple heuristic)
                        # This won't be perfect but extracts most comments
                        match = re.search(r'#\s*(.+)$', stripped)
                        if match and not re.search(r'["\'][^"\']*#[^"\']*["\']', stripped):
                            result["inline_comments"].append({
                                "line": line_num,
                                "content": match.group(1).strip()
                            })
        
        return result
    
    def _extract_description_comment(self, test_start_line: int) -> Optional[Dict]:
        """
        Extract the description comment immediately before a test function.
        
        Looks for:
        - Python docstrings (triple quotes)
        - Block comments (/* ... */)
        - Consecutive line comments (// or #)
        
        Args:
            test_start_line: 0-based index of test function start
            
        Returns:
            Dict with lines (list of line numbers) and text (full comment text),
            or None if no description comment found
        """
        if test_start_line <= 0:
            return None
        
        comment_lines = []
        comment_text_parts = []
        
        # Look backwards from test start
        i = test_start_line - 1
        
        # Skip blank lines
        while i >= 0 and not self.lines[i].strip():
            i -= 1
        
        if i < 0:
            return None
        
        line = self.lines[i].strip()
        
        # Check for different comment styles
        if self.language == 'python':
            # Check for docstring (""" or ''') - would be inside function
            # Or consecutive # comments before function
            while i >= 0 and self.lines[i].strip().startswith('#'):
                comment_lines.insert(0, i + 1)
                comment_text_parts.insert(0, self.lines[i].strip()[1:].strip())
                i -= 1
        
        elif self.language in ['c', 'cpp', 'java', 'javascript', 'typescript']:
            # Check for block comment ending with */
            if line.endswith('*/'):
                # Find the start of this block comment
                end_line = i
                while i >= 0 and '/*' not in self.lines[i]:
                    i -= 1
                if i >= 0:
                    # Extract the block comment
                    for j in range(i, end_line + 1):
                        comment_lines.append(j + 1)
                        text = self.lines[j].strip()
                        # Clean up comment markers
                        text = re.sub(r'^/\*+\s*', '', text)
                        text = re.sub(r'\s*\*+/$', '', text)
                        text = re.sub(r'^\*+\s*', '', text)
                        if text:
                            comment_text_parts.append(text)
            
            # Check for consecutive // comments
            elif line.startswith('//'):
                while i >= 0 and self.lines[i].strip().startswith('//'):
                    comment_lines.insert(0, i + 1)
                    text = self.lines[i].strip()[2:].strip()
                    comment_text_parts.insert(0, text)
                    i -= 1
        
        if comment_lines:
            return {
                "lines": comment_lines,
                "text": ' '.join(comment_text_parts)
            }
        
        return None
    
    def export_json(self, output_file: str, test_name: Optional[str] = None):
        """
        Export extracted data to JSON file.
        
        The JSON includes:
        - Metadata (file, language, line range)
        - Raw lines (for agent's additional analysis)
        - Extracted patterns (numbers, calls, keywords)
        - Comments (description, inline, block) for conformity analysis
        
        Args:
            output_file: Path to write JSON output
            test_name: Optional specific test to extract
        """
        info = self.extract(test_name)
        
        data = {
            "test_file": info.test_file,
            "test_name": info.test_name,
            "language": info.language,
            "start_line": info.start_line,
            "end_line": info.end_line,
            "line_count": info.line_count,
            # Raw lines for agent to extract additional patterns
            "lines": info.lines,
            # Deterministic pattern extractions - agent interprets these
            "patterns": {
                "numbers_found": info.numbers_found,
                "function_calls": info.function_calls,
                "keywords_found": info.keywords_found
            },
            # Comments for agent to assess comment-test conformity
            "comments": info.comments
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)


def main():
    if len(sys.argv) < 2:
        print("""
Test Code Extractor - Extract test code and patterns for analysis

Usage:
  python test_design_analyzer.py extract <test_file> [--test <test_name>] [--json <output.json>]

Commands:
  extract <test_file> [--test <test_name>] [--json <output.json>]
    Extract test code and deterministic patterns

Examples:
  python test_design_analyzer.py extract test_main.c --json test_code.json
  python test_design_analyzer.py extract test_utils.py --test test_parse_config --json test_code.json
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'extract':
        if len(sys.argv) < 3:
            print("Usage: test_design_analyzer.py extract <test_file> [--test <test_name>] [--json output.json]")
            sys.exit(1)
        
        test_file = sys.argv[2]
        test_name = None
        json_output = None
        
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == '--test' and i + 1 < len(sys.argv):
                test_name = sys.argv[i + 1]
                i += 2
            elif sys.argv[i] == '--json' and i + 1 < len(sys.argv):
                json_output = sys.argv[i + 1]
                i += 2
            else:
                i += 1
        
        extractor = TestExtractor(test_file)
        info = extractor.extract(test_name)
        
        print(f"\n=== Test Code: {test_file} ===")
        if test_name:
            print(f"Test: {test_name}")
        print(f"Language: {info.language}")
        print(f"Lines: {info.start_line}-{info.end_line} ({info.line_count} lines)")
        
        print(f"\nPatterns found:")
        print(f"  Numbers: {len(info.numbers_found)}")
        print(f"  Function calls: {len(info.function_calls)}")
        print(f"  Keywords: {len(info.keywords_found)}")
        
        if json_output:
            extractor.export_json(json_output, test_name)
            print(f"\nJSON exported to: {json_output}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
