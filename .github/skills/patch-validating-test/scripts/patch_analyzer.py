#!/usr/bin/env python3
"""
Patch Analyzer
==============

PURPOSE:
    Analyzes patches to identify affected functions, categorize changes,
    assess risk, and generate test scenarios. Uses parsed patch data to
    provide higher-level analysis.

WHAT THIS SCRIPT DOES:
    1. Identifies functions affected by the patch (using source file analysis)
    2. Categorizes changes using pattern matching (error handling, bounds checks, etc.)
    3. Assesses patch risk based on size and change types
    4. Generates test scenario suggestions based on change categories
    5. Exports analysis as JSON or Markdown

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT understand code semantics (only pattern matching)
    - Does NOT determine if test scenarios are complete or sufficient
    - Does NOT verify that tests will actually catch bugs
    - Does NOT score quality (provides data for agent to score)

PATTERN-BASED CATEGORIZATION:
    This script uses REGEX PATTERNS to categorize changes:
    - ERROR_HANDLING: return -1, NULL, throw, assert, etc.
    - BOUNDARY_CHECK: comparisons with limits, sizeof, overflow keywords
    - INITIALIZATION: memset, = 0, = NULL, Init() calls
    - CLEANUP: free, delete, close, Cleanup() calls
    - LOGGING: log, print, debug, trace calls

    These are HEURISTIC matches - the agent should verify the categorizations
    and may override them based on actual code understanding.

LIMITATIONS:
    - Function detection is heuristic (may miss complex C++ templates)
    - Change categorization is regex-based (not semantic)
    - Risk assessment is formulaic (agent should apply judgment)
    - Test scenarios are templates (agent must fill in specifics)

USAGE:
    python patch_analyzer.py analyze <patch_file> [--source-root <path>] [--json out.json] [--md out.md]
    python patch_analyzer.py functions <patch_file>
    python patch_analyzer.py scenarios <patch_file>
    python patch_analyzer.py risk <patch_file>

DESIGN NOTE:
    This script provides STRUCTURED SUGGESTIONS based on patterns.
    The agent should:
    - Verify that identified functions are correct
    - Validate change categorizations
    - Adjust risk assessment based on domain knowledge
    - Customize test scenarios for the specific context
"""

import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Import from patch_parser
from patch_parser import PatchParser, PatchInfo, FilePatch, ChangeType


class ChangeCategory(Enum):
    """
    Categories of code changes for test scenario generation.
    
    These categories are assigned by PATTERN MATCHING, not semantic analysis.
    The agent should verify categorizations are accurate.
    
    Values:
        BUG_FIX: General bug fix (default when others don't match)
        NEW_FEATURE: New functionality added
        REFACTOR: Code restructuring without behavior change
        ERROR_HANDLING: Error detection, reporting, or recovery
        BOUNDARY_CHECK: Input validation, range checks, overflow protection
        INITIALIZATION: Variable/state initialization
        CLEANUP: Resource release, memory freeing
        LOGGING: Debug/trace/log output
        CONFIGURATION: Config settings, constants
        UNKNOWN: Could not categorize
    """
    BUG_FIX = "bug_fix"
    NEW_FEATURE = "new_feature"
    REFACTOR = "refactor"
    ERROR_HANDLING = "error_handling"
    BOUNDARY_CHECK = "boundary_check"
    INITIALIZATION = "initialization"
    CLEANUP = "cleanup"
    LOGGING = "logging"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


@dataclass
class AffectedFunction:
    """
    Information about a function affected by the patch.
    
    This represents the analysis of which functions were changed
    and what types of changes were made.
    
    Attributes:
        name: Function name (may be "unknown" if not parseable)
        file_path: Path to the file containing this function
        start_line: First line of function
        end_line: Last line of function
        added_lines: Line numbers of added lines within this function
        removed_lines: Line numbers of removed lines within this function
        change_categories: Categorizations based on pattern matching
    """
    name: str
    file_path: str
    start_line: int
    end_line: int
    added_lines: List[int] = field(default_factory=list)
    removed_lines: List[int] = field(default_factory=list)
    change_categories: List[ChangeCategory] = field(default_factory=list)


@dataclass
class TestScenario:
    """
    A test scenario suggestion derived from patch analysis.
    
    These are TEMPLATE SUGGESTIONS - the agent must customize
    them with actual test logic and assertions.
    
    Attributes:
        name: Suggested test name
        description: What the test should verify
        priority: "high", "medium", or "low" based on risk
        category: Type of test (validation, regression, boundary, etc.)
        target_lines: Lines the test should cover
        target_file: File containing the code to test
        target_function: Function to test
        assertions: Suggested assertion points
        setup_hints: Hints for test setup
    """
    name: str
    description: str
    priority: str  # "high", "medium", "low"
    category: str
    target_lines: List[int]
    target_file: str
    target_function: Optional[str]
    assertions: List[str]
    setup_hints: List[str]


@dataclass
class PatchAnalysis:
    """
    Complete analysis of a patch.
    
    Attributes:
        patch_info: The parsed patch data
        affected_functions: Functions identified as changed
        test_scenarios: Suggested test scenarios
        change_summary: Summary statistics
        risk_assessment: Risk level and factors
    """
    patch_info: PatchInfo
    affected_functions: List[AffectedFunction]
    test_scenarios: List[TestScenario]
    change_summary: Dict[str, any]
    risk_assessment: Dict[str, any]


class PatchAnalyzer:
    """
    Analyzes patches to generate test requirements.
    
    This class performs PATTERN-BASED ANALYSIS:
    - Identifies functions using code structure patterns
    - Categorizes changes using regex patterns
    - Generates test scenarios using templates
    
    The agent should use this as a STARTING POINT and apply
    deeper understanding to refine the analysis.
    """
    
    # ==========================================================================
    # CHANGE CATEGORIZATION PATTERNS
    # ==========================================================================
    # These patterns are used to categorize changes by type.
    # They are HEURISTICS - the agent should verify accuracy.
    # ==========================================================================
    
    # Error handling patterns - matches code dealing with errors
    ERROR_PATTERNS = [
        r'\breturn\s+(-\d+|NULL|nullptr|false|ERROR|FAIL)',  # Error return values
        r'\bif\s*\(\s*!\w+\s*\)',                            # if (!result)
        r'\bif\s*\(\w+\s*[!=]=\s*NULL',                      # if (ptr == NULL)
        r'\bif\s*\(\w+\s*[<>=!]=',                           # Comparison checks
        r'\b(error|err|errno|status)\s*[!=]=',               # Error variable checks
        r'\bthrow\s+',                                        # C++ throw
        r'\braise\s+',                                        # Python raise
        r'\bassert\s*\(',                                     # Assertions
    ]
    
    # Boundary check patterns - matches bounds/limit checking code
    BOUNDARY_PATTERNS = [
        r'\bif\s*\(\s*\w+\s*[<>]=?\s*\d+',      # if (x < 10)
        r'\bif\s*\(\s*\w+\s*[<>]=?\s*\w+\s*\)', # if (x < max)
        r'\b(MAX|MIN|LIMIT|SIZE|LENGTH|COUNT)\b', # Limit constants
        r'\bsizeof\s*\(',                        # sizeof checks
        r'\b(overflow|underflow|bounds)\b',     # Safety keywords
    ]
    
    # Initialization patterns - matches initialization code
    INIT_PATTERNS = [
        r'\w+\s*=\s*(0|NULL|nullptr|false|\{\}|"")',  # Zero/null init
        r'\bmemset\s*\(',                              # Memory zeroing
        r'\bmemcpy\s*\(',                              # Memory copy
        r'\binit\w*\s*\(',                             # init*() calls
        r'\b(Initialize|Init|Setup|Create)\w*\s*\(',  # Common init names
    ]
    
    # Cleanup patterns - matches resource cleanup code
    CLEANUP_PATTERNS = [
        r'\bfree\s*\(',                                # C free
        r'\bdelete\s+',                                # C++ delete
        r'\bclose\s*\(',                               # File/handle close
        r'\b(Cleanup|Destroy|Release|Dispose)\w*\s*\(', # Common cleanup names
    ]
    
    # Logging patterns - matches log/debug output
    LOGGING_PATTERNS = [
        r'\b(log|LOG|Log|print|printf|fprintf|cout|cerr)\s*[\(\<]',
        r'\b(debug|DEBUG|Debug|trace|TRACE|Trace)\s*[\(\<]',
        r'\b(info|INFO|Info|warn|WARN|Warn|error|ERROR|Error)\s*[\(\<]',
    ]
    
    def __init__(self, source_root: str = "."):
        """
        Initialize the analyzer.
        
        Args:
            source_root: Root directory for finding source files
        """
        self.source_root = Path(source_root)
        self.analysis: Optional[PatchAnalysis] = None
    
    def analyze(self, patch_info: PatchInfo) -> PatchAnalysis:
        """
        Perform full analysis of a patch.
        
        This is the main analysis method that:
        1. Finds affected functions
        2. Categorizes changes
        3. Assesses risk
        4. Generates test scenarios
        
        Args:
            patch_info: Parsed patch data from PatchParser
            
        Returns:
            Complete PatchAnalysis
        """
        affected_functions = self._find_affected_functions(patch_info)
        change_summary = self._summarize_changes(patch_info, affected_functions)
        risk_assessment = self._assess_risk(patch_info, affected_functions)
        test_scenarios = self._generate_test_scenarios(patch_info, affected_functions)
        
        self.analysis = PatchAnalysis(
            patch_info=patch_info,
            affected_functions=affected_functions,
            test_scenarios=test_scenarios,
            change_summary=change_summary,
            risk_assessment=risk_assessment
        )
        
        return self.analysis
    
    def _find_affected_functions(self, patch_info: PatchInfo) -> List[AffectedFunction]:
        """
        Identify functions affected by the patch.
        
        ALGORITHM:
        1. For each changed file, try to read the source
        2. Parse function boundaries using pattern matching
        3. Map changed lines to functions
        4. Categorize changes within each function
        
        LIMITATIONS:
        - May miss functions in complex C++ code
        - Falls back to hunk headers if parsing fails
        - Function boundaries are approximate
        
        Returns:
            List of AffectedFunction objects
        """
        affected = []
        
        for file_patch in patch_info.files:
            if file_patch.is_deleted_file:
                continue
            
            # Try to read the source file to find function boundaries
            source_path = self.source_root / file_patch.new_path
            functions = {}
            
            if source_path.exists():
                functions = self._extract_functions_from_file(source_path)
            
            # Map changed lines to functions
            added_lines = [ln for ln, _ in file_patch.get_all_added_lines()]
            removed_lines = [ln for ln, _ in file_patch.get_all_removed_lines()]
            
            for func_name, (start, end) in functions.items():
                func_added = [ln for ln in added_lines if start <= ln <= end]
                func_removed = [ln for ln in removed_lines if start <= ln <= end]
                
                if func_added or func_removed:
                    # Categorize the changes
                    categories = self._categorize_changes(file_patch, func_added)
                    
                    affected.append(AffectedFunction(
                        name=func_name,
                        file_path=file_patch.new_path,
                        start_line=start,
                        end_line=end,
                        added_lines=func_added,
                        removed_lines=func_removed,
                        change_categories=categories
                    ))
            
            # Handle cases where we couldn't parse functions
            if not functions and (added_lines or removed_lines):
                # Use hunk headers as hints for function names
                for hunk in file_patch.hunks:
                    func_match = re.search(r'\b(\w+)\s*\(', hunk.header)
                    func_name = func_match.group(1) if func_match else "unknown"
                    
                    hunk_added = [ln for ln, _ in hunk.get_added_lines()]
                    hunk_removed = [ln for ln, _ in hunk.get_removed_lines()]
                    
                    if hunk_added or hunk_removed:
                        categories = self._categorize_changes(file_patch, hunk_added)
                        
                        affected.append(AffectedFunction(
                            name=func_name,
                            file_path=file_patch.new_path,
                            start_line=hunk.new_start,
                            end_line=hunk.new_start + hunk.new_count - 1,
                            added_lines=hunk_added,
                            removed_lines=hunk_removed,
                            change_categories=categories
                        ))
        
        return affected
    
    def _extract_functions_from_file(self, file_path: Path) -> Dict[str, Tuple[int, int]]:
        """
        Extract function boundaries from a source file.
        
        Uses PATTERN MATCHING to find function definitions.
        This is HEURISTIC - may not work for all code styles.
        
        Args:
            file_path: Path to source file
            
        Returns:
            Dict mapping function name -> (start_line, end_line)
        """
        functions = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return functions
        
        # Simple function detection for C/C++/Java/JavaScript/Python
        ext = file_path.suffix.lower()
        
        if ext in ['.c', '.cpp', '.cc', '.h', '.hpp', '.java', '.js', '.ts']:
            functions = self._extract_c_style_functions(lines)
        elif ext == '.py':
            functions = self._extract_python_functions(lines)
        
        return functions
    
    def _extract_c_style_functions(self, lines: List[str]) -> Dict[str, Tuple[int, int]]:
        """
        Extract functions from C-style languages (C, C++, Java, JavaScript).
        
        ALGORITHM:
        - Look for lines with '(' and ')' that might be signatures
        - Find opening brace within next few lines
        - Track brace depth to find closing brace
        
        LIMITATIONS:
        - May be confused by macros, templates, lambdas
        - Simple brace counting may fail with complex expressions
        
        Args:
            lines: Source file lines
            
        Returns:
            Dict mapping function name -> (start_line, end_line)
        """
        functions = {}
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Look for function signature pattern
            if '(' in line and ')' in line and not line.strip().startswith('//'):
                # Check for opening brace
                brace_line = None
                for j in range(i, min(i + 5, len(lines))):
                    if '{' in lines[j]:
                        brace_line = j
                        break
                
                if brace_line is not None:
                    func_match = re.search(r'\b(\w+)\s*\([^)]*\)\s*(?:const)?\s*(?:override)?\s*(?:noexcept)?\s*{?', line)
                    if func_match:
                        func_name = func_match.group(1)
                        if func_name not in ['if', 'while', 'for', 'switch', 'catch']:
                            # Find closing brace
                            brace_depth = 0
                            end_line = brace_line
                            
                            for j in range(brace_line, len(lines)):
                                brace_depth += lines[j].count('{') - lines[j].count('}')
                                if brace_depth == 0:
                                    end_line = j
                                    break
                            
                            functions[func_name] = (i + 1, end_line + 1)
                            i = end_line + 1
                            continue
            i += 1
        
        return functions
    
    def _extract_python_functions(self, lines: List[str]) -> Dict[str, Tuple[int, int]]:
        """
        Extract functions from Python code.
        
        ALGORITHM:
        - Find 'def function_name(' patterns
        - Track indentation to find function end
        
        LIMITATIONS:
        - Does not handle nested functions specially
        - Indentation-based end detection may fail with unusual formatting
        
        Args:
            lines: Source file lines
            
        Returns:
            Dict mapping function name -> (start_line, end_line)
        """
        functions = {}
        
        for i, line in enumerate(lines):
            match = re.match(r'^(\s*)def\s+(\w+)\s*\(', line)
            if match:
                indent = len(match.group(1))
                func_name = match.group(2)
                start_line = i + 1
                end_line = start_line
                
                # Find end of function (next line with same or less indentation)
                for j in range(i + 1, len(lines)):
                    if lines[j].strip() and not lines[j].strip().startswith('#'):
                        line_indent = len(lines[j]) - len(lines[j].lstrip())
                        if line_indent <= indent:
                            end_line = j
                            break
                        end_line = j + 1
                
                functions[func_name] = (start_line, end_line)
        
        return functions
    
    def _categorize_changes(self, file_patch: FilePatch, added_lines: List[int]) -> List[ChangeCategory]:
        """
        Categorize the type of changes made using pattern matching.
        
        This method applies REGEX PATTERNS to categorize changes.
        Results are HEURISTIC - the agent should verify accuracy.
        
        Multiple categories may apply to the same change.
        
        Args:
            file_patch: The file patch containing changes
            added_lines: Line numbers of added lines to categorize
            
        Returns:
            List of ChangeCategory values that matched
        """
        categories = set()
        
        for line_num, content in file_patch.get_all_added_lines():
            if line_num not in added_lines:
                continue
            
            # Check against patterns
            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, content):
                    categories.add(ChangeCategory.ERROR_HANDLING)
                    break
            
            for pattern in self.BOUNDARY_PATTERNS:
                if re.search(pattern, content):
                    categories.add(ChangeCategory.BOUNDARY_CHECK)
                    break
            
            for pattern in self.INIT_PATTERNS:
                if re.search(pattern, content):
                    categories.add(ChangeCategory.INITIALIZATION)
                    break
            
            for pattern in self.CLEANUP_PATTERNS:
                if re.search(pattern, content):
                    categories.add(ChangeCategory.CLEANUP)
                    break
            
            for pattern in self.LOGGING_PATTERNS:
                if re.search(pattern, content):
                    categories.add(ChangeCategory.LOGGING)
                    break
        
        if not categories:
            categories.add(ChangeCategory.UNKNOWN)
        
        return list(categories)
    
    def _summarize_changes(self, patch_info: PatchInfo, 
                          affected_functions: List[AffectedFunction]) -> Dict:
        """
        Create a summary of the changes.
        
        Aggregates statistics about the patch for quick overview.
        
        Args:
            patch_info: The parsed patch data
            affected_functions: Functions identified as changed
            
        Returns:
            Dict with total_files, total_added, total_removed, 
            affected_functions count, and change_categories breakdown
        """
        stats = patch_info.get_statistics()
        
        # Count change categories
        category_counts = {}
        for func in affected_functions:
            for cat in func.change_categories:
                category_counts[cat.value] = category_counts.get(cat.value, 0) + 1
        
        return {
            'total_files': stats['files_changed'],
            'total_added': stats['lines_added'],
            'total_removed': stats['lines_removed'],
            'affected_functions': len(affected_functions),
            'change_categories': category_counts
        }
    
    def _assess_risk(self, patch_info: PatchInfo,
                    affected_functions: List[AffectedFunction]) -> Dict:
        """
        Assess the risk level of the patch.
        
        This is a FORMULAIC ASSESSMENT based on:
        - Number of changed lines (more = higher risk)
        - Number of affected functions (more = higher risk)
        - Types of changes (error handling, boundary checks = higher risk)
        
        The agent should apply domain knowledge to adjust this assessment.
        
        Args:
            patch_info: The parsed patch data
            affected_functions: Functions identified as changed
            
        Returns:
            Dict with level ("high"/"medium"/"low"), score, and factors list
        """
        risk_factors = []
        risk_score = 0
        
        stats = patch_info.get_statistics()
        
        # Large changes are higher risk
        if stats['lines_added'] + stats['lines_removed'] > 100:
            risk_factors.append("Large number of changed lines")
            risk_score += 2
        elif stats['lines_added'] + stats['lines_removed'] > 50:
            risk_score += 1
        
        # Many affected functions
        if len(affected_functions) > 5:
            risk_factors.append("Many functions affected")
            risk_score += 2
        elif len(affected_functions) > 2:
            risk_score += 1
        
        # Error handling changes
        for func in affected_functions:
            if ChangeCategory.ERROR_HANDLING in func.change_categories:
                risk_factors.append(f"Error handling modified in {func.name}")
                risk_score += 1
            if ChangeCategory.BOUNDARY_CHECK in func.change_categories:
                risk_factors.append(f"Boundary checks modified in {func.name}")
                risk_score += 1
        
        # Determine risk level
        if risk_score >= 4:
            risk_level = "high"
        elif risk_score >= 2:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            'level': risk_level,
            'score': risk_score,
            'factors': risk_factors
        }
    
    def _generate_test_scenarios(self, patch_info: PatchInfo,
                                 affected_functions: List[AffectedFunction]) -> List[TestScenario]:
        """
        Generate test scenarios based on the patch analysis.
        
        Creates TEMPLATE SCENARIOS that the agent must customize:
        - Basic validation test for each function
        - Regression test for each function
        - Category-specific tests (error handling, boundary, etc.)
        
        These are SUGGESTIONS - the agent determines which are appropriate
        and fills in actual test logic.
        
        Args:
            patch_info: The parsed patch data
            affected_functions: Functions identified as changed
            
        Returns:
            List of TestScenario templates
        """
        scenarios = []
        
        for func in affected_functions:
            # Basic validation test
            scenarios.append(TestScenario(
                name=f"test_{func.name}_patch_validation",
                description=f"Validate that the changes to {func.name} work correctly",
                priority="high",
                category="validation",
                target_lines=func.added_lines,
                target_file=func.file_path,
                target_function=func.name,
                assertions=[
                    f"Function {func.name} executes without error",
                    "Return value is as expected",
                    "Side effects are correct"
                ],
                setup_hints=[
                    f"Set up valid inputs for {func.name}",
                    "Initialize required dependencies"
                ]
            ))
            
            # Regression test
            scenarios.append(TestScenario(
                name=f"test_{func.name}_regression",
                description=f"Ensure existing functionality of {func.name} still works",
                priority="high",
                category="regression",
                target_lines=func.removed_lines if func.removed_lines else func.added_lines,
                target_file=func.file_path,
                target_function=func.name,
                assertions=[
                    "Existing behavior is preserved",
                    "No unintended side effects"
                ],
                setup_hints=[
                    "Use inputs that worked before the patch",
                    "Verify output matches expected behavior"
                ]
            ))
            
            # Category-specific tests
            for category in func.change_categories:
                if category == ChangeCategory.ERROR_HANDLING:
                    scenarios.append(TestScenario(
                        name=f"test_{func.name}_error_handling",
                        description=f"Test error handling in {func.name}",
                        priority="high",
                        category="error_handling",
                        target_lines=func.added_lines,
                        target_file=func.file_path,
                        target_function=func.name,
                        assertions=[
                            "Errors are properly detected",
                            "Error conditions return expected values",
                            "No resource leaks on error paths"
                        ],
                        setup_hints=[
                            "Provide invalid inputs",
                            "Simulate failure conditions",
                            "Test boundary conditions"
                        ]
                    ))
                
                elif category == ChangeCategory.BOUNDARY_CHECK:
                    scenarios.append(TestScenario(
                        name=f"test_{func.name}_boundaries",
                        description=f"Test boundary conditions in {func.name}",
                        priority="high",
                        category="boundary",
                        target_lines=func.added_lines,
                        target_file=func.file_path,
                        target_function=func.name,
                        assertions=[
                            "Boundary values are handled correctly",
                            "Off-by-one errors are prevented",
                            "Overflow/underflow is handled"
                        ],
                        setup_hints=[
                            "Test with minimum values",
                            "Test with maximum values",
                            "Test with boundary-1 and boundary+1"
                        ]
                    ))
                
                elif category == ChangeCategory.INITIALIZATION:
                    scenarios.append(TestScenario(
                        name=f"test_{func.name}_initialization",
                        description=f"Test initialization in {func.name}",
                        priority="medium",
                        category="initialization",
                        target_lines=func.added_lines,
                        target_file=func.file_path,
                        target_function=func.name,
                        assertions=[
                            "Values are properly initialized",
                            "Default states are correct",
                            "No uninitialized memory access"
                        ],
                        setup_hints=[
                            "Call function without prior initialization",
                            "Verify initial state values"
                        ]
                    ))
                
                elif category == ChangeCategory.CLEANUP:
                    scenarios.append(TestScenario(
                        name=f"test_{func.name}_cleanup",
                        description=f"Test resource cleanup in {func.name}",
                        priority="medium",
                        category="cleanup",
                        target_lines=func.added_lines,
                        target_file=func.file_path,
                        target_function=func.name,
                        assertions=[
                            "Resources are properly released",
                            "No memory leaks",
                            "Handles can be reused after cleanup"
                        ],
                        setup_hints=[
                            "Allocate resources before calling",
                            "Verify resources are freed after call",
                            "Use memory leak detection tools"
                        ]
                    ))
        
        return scenarios
    
    def export_json(self, output_file: str):
        """
        Export analysis to JSON format.
        
        Args:
            output_file: Path to write JSON
            
        Raises:
            ValueError: If no analysis has been performed
        """
        if not self.analysis:
            raise ValueError("No analysis to export. Run analyze() first.")
        
        data = {
            'change_summary': self.analysis.change_summary,
            'risk_assessment': self.analysis.risk_assessment,
            'affected_functions': [
                {
                    'name': f.name,
                    'file': f.file_path,
                    'lines': {'start': f.start_line, 'end': f.end_line},
                    'added_lines': f.added_lines,
                    'removed_lines': f.removed_lines,
                    'categories': [c.value for c in f.change_categories]
                }
                for f in self.analysis.affected_functions
            ],
            'test_scenarios': [
                {
                    'name': s.name,
                    'description': s.description,
                    'priority': s.priority,
                    'category': s.category,
                    'target_file': s.target_file,
                    'target_function': s.target_function,
                    'target_lines': s.target_lines,
                    'assertions': s.assertions,
                    'setup_hints': s.setup_hints
                }
                for s in self.analysis.test_scenarios
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def export_markdown(self, output_file: str):
        """
        Export analysis to Markdown format for human review.
        
        Creates a structured report with:
        - Change summary
        - Risk assessment
        - Affected functions list
        - Recommended test scenarios
        
        Args:
            output_file: Path to write Markdown
            
        Raises:
            ValueError: If no analysis has been performed
        """
        if not self.analysis:
            raise ValueError("No analysis to export. Run analyze() first.")
        
        lines = []
        lines.append("# Patch Analysis Report\n")
        
        # Summary
        lines.append("## Change Summary\n")
        summary = self.analysis.change_summary
        lines.append(f"- **Files Changed:** {summary['total_files']}")
        lines.append(f"- **Lines Added:** {summary['total_added']}")
        lines.append(f"- **Lines Removed:** {summary['total_removed']}")
        lines.append(f"- **Functions Affected:** {summary['affected_functions']}")
        lines.append("")
        
        # Risk Assessment
        risk = self.analysis.risk_assessment
        lines.append("## Risk Assessment\n")
        lines.append(f"**Risk Level:** {risk['level'].upper()} (score: {risk['score']})\n")
        if risk['factors']:
            lines.append("**Risk Factors:**")
            for factor in risk['factors']:
                lines.append(f"- {factor}")
        lines.append("")
        
        # Affected Functions
        lines.append("## Affected Functions\n")
        for func in self.analysis.affected_functions:
            lines.append(f"### {func.name}")
            lines.append(f"- **File:** `{func.file_path}`")
            lines.append(f"- **Lines:** {func.start_line}-{func.end_line}")
            lines.append(f"- **Added Lines:** {func.added_lines}")
            lines.append(f"- **Categories:** {', '.join(c.value for c in func.change_categories)}")
            lines.append("")
        
        # Test Scenarios
        lines.append("## Recommended Test Scenarios\n")
        for scenario in self.analysis.test_scenarios:
            priority_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(scenario.priority, "⚪")
            lines.append(f"### {priority_emoji} {scenario.name}")
            lines.append(f"**Priority:** {scenario.priority} | **Category:** {scenario.category}\n")
            lines.append(f"{scenario.description}\n")
            lines.append(f"**Target:** `{scenario.target_file}` → `{scenario.target_function}`\n")
            lines.append("**Assertions:**")
            for assertion in scenario.assertions:
                lines.append(f"- [ ] {assertion}")
            lines.append("\n**Setup Hints:**")
            for hint in scenario.setup_hints:
                lines.append(f"- {hint}")
            lines.append("")
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))


def main():
    if len(sys.argv) < 2:
        print("""
Patch Analyzer - Analyze patches for test requirements

Usage:
  python patch_analyzer.py <command> [options]

Commands:
  analyze <patch_file> [--source-root <path>] [--json <out.json>] [--md <out.md>]
    Analyze a patch and generate test scenarios
    
  functions <patch_file> [--source-root <path>]
    List affected functions
    
  scenarios <patch_file> [--source-root <path>]
    Show recommended test scenarios
    
  risk <patch_file> [--source-root <path>]
    Show risk assessment

Examples:
  python patch_analyzer.py analyze fix.patch --json analysis.json --md report.md
  python patch_analyzer.py functions feature.patch --source-root /path/to/repo
  python patch_analyzer.py scenarios bugfix.patch
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    # Parse common arguments
    patch_file = sys.argv[2] if len(sys.argv) > 2 else None
    source_root = "."
    json_output = None
    md_output = None
    
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == '--source-root' and i + 1 < len(sys.argv):
            source_root = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--json' and i + 1 < len(sys.argv):
            json_output = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--md' and i + 1 < len(sys.argv):
            md_output = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    
    if not patch_file:
        print("Error: patch file required")
        sys.exit(1)
    
    # Parse the patch
    parser = PatchParser()
    patch_info = parser.parse_file(patch_file)
    
    # Create analyzer
    analyzer = PatchAnalyzer(source_root)
    analysis = analyzer.analyze(patch_info)
    
    if command == 'analyze':
        # Print summary
        print(f"\n=== Patch Analysis: {patch_file} ===\n")
        
        summary = analysis.change_summary
        print(f"Files: {summary['total_files']} | +{summary['total_added']} -{summary['total_removed']} lines")
        print(f"Affected functions: {summary['affected_functions']}")
        print(f"Change categories: {summary['change_categories']}")
        
        risk = analysis.risk_assessment
        print(f"\nRisk: {risk['level'].upper()} (score: {risk['score']})")
        for factor in risk['factors']:
            print(f"  - {factor}")
        
        print(f"\nTest scenarios generated: {len(analysis.test_scenarios)}")
        
        if json_output:
            analyzer.export_json(json_output)
            print(f"\nJSON exported to: {json_output}")
        
        if md_output:
            analyzer.export_markdown(md_output)
            print(f"Markdown exported to: {md_output}")
    
    elif command == 'functions':
        print(f"\nAffected Functions in {patch_file}:\n")
        for func in analysis.affected_functions:
            print(f"  {func.name} ({func.file_path}:{func.start_line}-{func.end_line})")
            print(f"    Added: {func.added_lines}")
            print(f"    Categories: {[c.value for c in func.change_categories]}")
    
    elif command == 'scenarios':
        print(f"\nTest Scenarios for {patch_file}:\n")
        for scenario in analysis.test_scenarios:
            priority_marker = {"high": "[H]", "medium": "[M]", "low": "[L]"}.get(scenario.priority, "[?]")
            print(f"{priority_marker} {scenario.name}")
            print(f"    {scenario.description}")
            print(f"    Target: {scenario.target_file} → {scenario.target_function}")
            print()
    
    elif command == 'risk':
        risk = analysis.risk_assessment
        print(f"\nRisk Assessment for {patch_file}:\n")
        print(f"Level: {risk['level'].upper()}")
        print(f"Score: {risk['score']}")
        print("\nRisk Factors:")
        for factor in risk['factors']:
            print(f"  - {factor}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
