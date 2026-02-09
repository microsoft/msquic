#!/usr/bin/env python3
"""
Execution Trace XML Generator
=============================

PURPOSE:
    Generates execution_info.xml files from traced execution steps.
    Creates standardized XML output compatible with coverage analysis tools.

WHAT THIS SCRIPT DOES:
    1. Loads execution trace data from JSON format
    2. Converts trace steps into structured XML format
    3. Records context information (repo, source, test, language)
    4. Records execution steps with:
       - Location (file, line, column)
       - Variable state before/after execution
       - Branch decisions and reasons
       - Loop iterations
       - Coverage hits
    5. Outputs Cobertura-compatible execution_info.xml

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT actually execute code or trace runtime
    - Does NOT analyze or interpret the trace data
    - Does NOT determine if coverage is sufficient
    - Does NOT make quality judgments about tests
    - The actual tracing is done by the agent through analysis

OUTPUT FORMAT:
    XML structure:
    <execution>
      <context>
        <repoPath>, <sourceFile>, <testFile>, <testCase>, <language>
        <assumptions> - key/value pairs for symbolic values
      </context>
      <trace>
        <step index="N">
          <location file="" line="" columnStart="" columnEnd="">
            <code>...</code>
          </location>
          <before><variables scope="test">...</variables></before>
          <evaluation>
            <result value="" type=""/>
            <branch condition="" evaluated="" taken="then|else">
              <reason>...</reason>
            </branch>
            <loop iteration="" totalIterations=""/>
          </evaluation>
          <after><variables scope="test">...</variables></after>
          <coverage line="" hitsIncrement=""/>
          <notes>...</notes>
        </step>
      </trace>
    </execution>

USAGE:
    python trace_generator.py generate <repo> <source> <test> <testcase> <trace.json> <output.xml>

DESIGN NOTE:
    This script is a DATA TRANSFORMER only. It converts trace data from one format
    (JSON) to another (XML). The actual trace analysis and coverage simulation
    is performed by the agent, which provides the trace JSON as input.
"""

import json
import sys
from pathlib import Path
from typing import List, Dict
import xml.etree.ElementTree as ET
from xml.dom import minidom


class TraceXMLGenerator:
    """
    Generates execution_info.xml from trace data.
    
    This class is a pure DATA TRANSFORMER:
    - Takes structured trace data (from JSON)
    - Outputs standardized XML format
    - No analysis or interpretation
    
    The trace data itself is produced by the agent's manual analysis
    of test execution paths through the source code.
    """
    
    def __init__(self, repo_path: str, source_file: str, test_file: str, test_case: str, language: str = "C++"):
        """
        Initialize the generator with context information.
        
        Args:
            repo_path: Root path of the repository
            source_file: Path to the source file being traced
            test_file: Path to the test file
            test_case: Name of the specific test case
            language: Programming language (default: C++)
        """
        self.repo_path = Path(repo_path)
        self.source_file = source_file
        self.test_file = test_file
        self.test_case = test_case
        self.language = language
        self.steps: List[Dict] = []
        self.assumptions: Dict[str, str] = {}
    
    def load_trace_json(self, trace_file: str):
        """
        Load trace data from a JSON file.
        
        Expected JSON format:
        {
            "steps": [
                {
                    "step_index": 1,
                    "file": "source.c",
                    "line": 42,
                    "code": "if (x > 0)",
                    "variables_before": "x=5",
                    "branch_taken": "then",
                    "branch_condition": "x > 0",
                    "branch_reason": "x=5 is greater than 0",
                    ...
                },
                ...
            ],
            "assumptions": {
                "input_size": "10",
                "buffer_state": "initialized"
            }
        }
        
        Args:
            trace_file: Path to the JSON trace file
        """
        with open(trace_file, 'r') as f:
            data = json.load(f)
        
        self.steps = data.get('steps', [])
        self.assumptions = data.get('assumptions', {})
    
    def set_assumption(self, key: str, value: str):
        """
        Add an assumption about symbolic or unknown values.
        
        Assumptions are used when the agent cannot determine exact values
        but needs to make reasonable assumptions to trace execution.
        
        Example assumptions:
        - "input_size": "10" (assuming input has 10 elements)
        - "connection_state": "established" (assuming connection is open)
        
        Args:
            key: Name of the assumption
            value: Assumed value
        """
        self.assumptions[key] = value
    
    def add_step(self, step_data: Dict):
        """
        Add an execution step to the trace.
        
        Step data should contain:
        - step_index: Sequential step number
        - file: Source file path
        - line: Line number (1-based)
        - code: The code being executed
        - columnStart/columnEnd: Optional column positions
        - variables_before: Variable state before execution
        - variables_after: Variable state after execution
        - result_value/result_type: For expression results
        - branch_taken: "then" or "else" for conditionals
        - branch_condition: The condition expression
        - branch_reason: Why this branch was taken
        - loop_iteration: Current loop iteration
        - loop_total: Total iterations (if known)
        - hits_increment: Coverage hit count (usually 1)
        - notes: Additional notes about this step
        
        Args:
            step_data: Dictionary containing step information
        """
        self.steps.append(step_data)
    
    def generate_xml(self, output_file: str):
        """
        Generate the execution_info.xml file.
        
        This method transforms the loaded trace data into a structured XML
        document suitable for coverage analysis tools.
        
        Args:
            output_file: Path to write the XML output
        """
        root = ET.Element('execution')
        
        # Context
        context = ET.SubElement(root, 'context')
        
        repo_elem = ET.SubElement(context, 'repoPath')
        repo_elem.text = str(self.repo_path.resolve())
        
        source_elem = ET.SubElement(context, 'sourceFile')
        source_elem.text = self.source_file
        
        test_elem = ET.SubElement(context, 'testFile')
        test_elem.text = self.test_file
        
        testcase_elem = ET.SubElement(context, 'testCase')
        testcase_elem.text = self.test_case
        
        lang_elem = ET.SubElement(context, 'language')
        lang_elem.text = self.language
        
        assumptions_elem = ET.SubElement(context, 'assumptions')
        for key, value in self.assumptions.items():
            item = ET.SubElement(assumptions_elem, 'item')
            item.set('key', key)
            item.text = str(value)
        
        # Trace
        trace = ET.SubElement(root, 'trace')
        
        for step_data in self.steps:
            step = ET.SubElement(trace, 'step')
            step.set('index', str(step_data.get('step_index', 0)))
            
            # Location
            location = ET.SubElement(step, 'location')
            location.set('file', step_data.get('file', ''))
            location.set('line', str(step_data.get('line', 0)))
            location.set('columnStart', str(step_data.get('columnStart', 0)))
            location.set('columnEnd', str(step_data.get('columnEnd', 0)))
            
            code_cdata = ET.SubElement(location, 'code')
            code_cdata.text = step_data.get('code', '')
            
            # Before state
            before = ET.SubElement(step, 'before')
            vars_test = ET.SubElement(before, 'variables')
            vars_test.set('scope', 'test')
            vars_test.text = step_data.get('variables_before', '')
            
            # Evaluation
            evaluation = ET.SubElement(step, 'evaluation')
            
            if 'result_value' in step_data:
                result = ET.SubElement(evaluation, 'result')
                result.set('value', str(step_data['result_value']))
                result.set('type', step_data.get('result_type', 'unknown'))
            
            if 'branch_taken' in step_data:
                branch = ET.SubElement(evaluation, 'branch')
                branch.set('condition', step_data.get('branch_condition', ''))
                branch.set('evaluated', str(step_data.get('branch_evaluated', '')))
                branch.set('taken', step_data['branch_taken'])
                
                reason = ET.SubElement(branch, 'reason')
                reason.text = step_data.get('branch_reason', '')
            
            if 'loop_iteration' in step_data:
                loop = ET.SubElement(evaluation, 'loop')
                loop.set('iteration', str(step_data['loop_iteration']))
                loop.set('totalIterations', str(step_data.get('loop_total', 0)))
                
                condition = ET.SubElement(loop, 'condition')
                condition.set('value', str(step_data.get('loop_condition', 'true')))
            
            # After state
            after = ET.SubElement(step, 'after')
            vars_after = ET.SubElement(after, 'variables')
            vars_after.set('scope', 'test')
            vars_after.text = step_data.get('variables_after', '')
            
            # Coverage
            coverage = ET.SubElement(step, 'coverage')
            coverage.set('line', str(step_data.get('line', 0)))
            coverage.set('hitsIncrement', str(step_data.get('hits_increment', 1)))
            
            # Notes
            if 'notes' in step_data:
                notes = ET.SubElement(step, 'notes')
                notes.text = step_data['notes']
        
        # Pretty print
        xml_str = minidom.parseString(ET.tostring(root, encoding='unicode')).toprettyxml(indent="  ")
        xml_lines = [line for line in xml_str.split('\n') if line.strip()]
        xml_str = '\n'.join(xml_lines) + '\n'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_str)


def main():
    if len(sys.argv) < 2:
        print("""
Execution Trace XML Generator

Usage:
  python trace_generator.py generate <repo_path> <source_file> <test_file> <test_case> <trace_json> <output_xml>
    Generate execution_info.xml from trace JSON
    
  python trace_generator.py from-template <template_file> <output_xml>
    Generate from filled template

Examples:
  python trace_generator.py generate . bbr.c BbrTest.cpp MyTest trace.json execution_info.xml
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'generate':
        if len(sys.argv) < 8:
            print("Usage: trace_generator.py generate <repo> <source> <test> <testcase> <trace> <output>")
            sys.exit(1)
        
        repo_path = sys.argv[2]
        source_file = sys.argv[3]
        test_file = sys.argv[4]
        test_case = sys.argv[5]
        trace_json = sys.argv[6]
        output_xml = sys.argv[7]
        
        generator = TraceXMLGenerator(repo_path, source_file, test_file, test_case)
        generator.load_trace_json(trace_json)
        generator.generate_xml(output_xml)
        
        print(f"Execution trace XML generated: {output_xml}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
