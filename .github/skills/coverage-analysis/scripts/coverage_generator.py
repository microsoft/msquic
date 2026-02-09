#!/usr/bin/env python3
"""
Coverage Generator
==================

PURPOSE:
    Generates Cobertura-format coverage.xml from traced execution data.
    Converts coverage information into a standardized format for reporting tools.

WHAT THIS SCRIPT DOES:
    1. Loads source analysis (executable lines, branches) from JSON
    2. Loads coverage data (which lines were covered) from trace or simple file
    3. Calculates coverage statistics (line rate, branch rate)
    4. Generates Cobertura-compatible XML for coverage tools

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT actually run tests or measure coverage at runtime
    - Does NOT analyze source code (uses pre-analyzed JSON)
    - Does NOT determine if coverage is sufficient (just reports it)
    - Does NOT make quality judgments

OUTPUT FORMAT:
    Cobertura XML compatible with coverage tools (SonarQube, Codecov, etc.)
    
    <coverage lines-valid="100" lines-covered="75" line-rate="0.750" ...>
      <packages>
        <package name="...">
          <classes>
            <class name="..." filename="...">
              <lines>
                <line number="1" hits="1" branch="false"/>
                <line number="5" hits="0" branch="true" condition-coverage="50% (1/2)"/>
              </lines>
            </class>
          </classes>
        </package>
      </packages>
    </coverage>

USAGE:
    python coverage_generator.py generate <repo> <source> <analysis.json> <trace.json> <output.xml>
    python coverage_generator.py generate-simple <repo> <source> <analysis.json> <covered.txt> <output.xml>

DESIGN NOTE:
    This is a DATA TRANSFORMER. It takes coverage data from the agent's
    manual trace analysis and converts it to standardized XML format.
    The actual coverage determination is done by the agent.
"""

import json
import sys
from pathlib import Path
from typing import Set, Dict
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom


class CoverageGenerator:
    """
    Generates Cobertura XML from coverage data.
    
    This class TRANSFORMS data from one format to another:
    - Input: Source analysis JSON + coverage data
    - Output: Cobertura XML
    
    No analysis or judgment - pure data transformation.
    """
    
    def __init__(self, source_file: str, repo_path: str):
        """
        Initialize the generator.
        
        Args:
            source_file: Path to the source file being reported
            repo_path: Root path of the repository
        """
        self.source_file = Path(source_file)
        self.repo_path = Path(repo_path)
        self.covered_lines: Set[int] = set()
        self.covered_branches: Dict[int, Set[str]] = {}
        self.all_executable_lines: Set[int] = set()
        self.all_branches: Dict[int, int] = {}  # line -> branch_count
    
    def load_analysis(self, analysis_json: str):
        """
        Load source analysis JSON (from source_analyzer.py).
        
        This tells us:
        - Which lines CAN be covered (executable_lines)
        - Which lines have branches and how many (branches)
        
        Args:
            analysis_json: Path to the analysis JSON file
        """
        with open(analysis_json, 'r') as f:
            data = json.load(f)
        
        self.all_executable_lines = set(data['executable_lines'])
        
        for line_str, branch_info in data.get('branches', {}).items():
            line = int(line_str)
            self.all_branches[line] = branch_info['branch_count']
    
    def load_trace(self, trace_json: str):
        """
        Load execution trace JSON (from path_tracer.py / agent analysis).
        
        This tells us:
        - Which lines WERE covered (covered_lines)
        - Which branches were taken at each decision point
        
        Args:
            trace_json: Path to the trace JSON file
        """
        with open(trace_json, 'r') as f:
            data = json.load(f)
        
        self.covered_lines = set(data['covered_lines'])
        
        # Load branch coverage
        for line_str, branches in data.get('covered_branches', {}).items():
            line = int(line_str)
            self.covered_branches[line] = set(branches) if isinstance(branches, list) else {branches}
    
    def load_simple_coverage(self, coverage_file: str):
        """
        Load simple coverage file (just line numbers).
        
        Format: One line number per line, comments start with #
        
        Example:
            # Covered lines
            10
            15
            22
            
        Args:
            coverage_file: Path to the coverage file
        """
        with open(coverage_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and line.isdigit():
                    self.covered_lines.add(int(line))
    
    def generate_cobertura_xml(self, output_file: str):
        """
        Generate Cobertura coverage XML.
        
        Creates XML compatible with standard coverage tools like:
        - SonarQube
        - Codecov
        - Coveralls
        - Jenkins Coverage Plugin
        
        Args:
            output_file: Path to write the XML output
        """
        # Calculate statistics
        total_lines = len(self.all_executable_lines)
        covered_lines_count = len(self.covered_lines & self.all_executable_lines)
        line_rate = covered_lines_count / total_lines if total_lines > 0 else 0.0
        
        total_branches = sum(self.all_branches.values())
        covered_branches_count = sum(len(branches) for branches in self.covered_branches.values())
        branch_rate = covered_branches_count / total_branches if total_branches > 0 else 0.0
        
        # Create XML structure
        root = ET.Element('coverage')
        root.set('lines-valid', str(total_lines))
        root.set('lines-covered', str(covered_lines_count))
        root.set('line-rate', f"{line_rate:.3f}")
        root.set('branches-valid', str(total_branches))
        root.set('branches-covered', str(covered_branches_count))
        root.set('branch-rate', f"{branch_rate:.3f}")
        root.set('version', 'neural-executor/1.0')
        root.set('timestamp', str(int(datetime.now().timestamp() * 1000)))
        
        # Sources
        sources = ET.SubElement(root, 'sources')
        source = ET.SubElement(sources, 'source')
        source.text = str(self.repo_path.resolve())
        
        # Packages
        packages = ET.SubElement(root, 'packages')
        
        # Determine package name from path
        rel_path = self.source_file.relative_to(self.repo_path) if self.source_file.is_absolute() else self.source_file
        package_name = '.'.join(rel_path.parts[:-1])
        
        package = ET.SubElement(packages, 'package')
        package.set('name', package_name if package_name else 'default')
        
        classes = ET.SubElement(package, 'classes')
        
        # Class (one per source file)
        cls = ET.SubElement(classes, 'class')
        cls.set('name', self.source_file.stem)
        cls.set('filename', str(rel_path).replace('\\', '/'))
        cls.set('line-rate', f"{line_rate:.3f}")
        cls.set('branch-rate', f"{branch_rate:.3f}")
        
        # Methods (empty for now)
        ET.SubElement(cls, 'methods')
        
        # Lines
        lines_elem = ET.SubElement(cls, 'lines')
        
        for line_num in sorted(self.all_executable_lines):
            line = ET.SubElement(lines_elem, 'line')
            line.set('number', str(line_num))
            line.set('hits', '1' if line_num in self.covered_lines else '0')
            
            # Check if this line has branches
            if line_num in self.all_branches:
                line.set('branch', 'true')
                total_branches = self.all_branches[line_num]
                covered = len(self.covered_branches.get(line_num, set()))
                percentage = int(100 * covered / total_branches) if total_branches > 0 else 0
                line.set('condition-coverage', f"{percentage}% ({covered}/{total_branches})")
            else:
                line.set('branch', 'false')
        
        # Pretty print XML
        xml_str = minidom.parseString(ET.tostring(root, encoding='unicode')).toprettyxml(indent="  ")
        
        # Remove extra blank lines
        xml_lines = [line for line in xml_str.split('\n') if line.strip()]
        xml_str = '\n'.join(xml_lines) + '\n'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_str)
    
    def print_summary(self):
        """
        Print a human-readable coverage summary.
        
        Shows:
        - Line coverage: X/Y (Z%)
        - Branch coverage: X/Y (Z%)
        """
        total_lines = len(self.all_executable_lines)
        covered = len(self.covered_lines & self.all_executable_lines)
        
        total_branches = sum(self.all_branches.values())
        covered_branches = sum(len(b) for b in self.covered_branches.values())
        
        print(f"\n=== Coverage Summary ===")
        print(f"Lines: {covered}/{total_lines} ({100*covered/total_lines if total_lines > 0 else 0:.1f}%)")
        print(f"Branches: {covered_branches}/{total_branches} ({100*covered_branches/total_branches if total_branches > 0 else 0:.1f}%)")


def main():
    if len(sys.argv) < 2:
        print("""
Coverage Generator

Usage:
  python coverage_generator.py <command> [options]

Commands:
  generate <repo_path> <source_file> <analysis_json> <trace_json> <output_xml>
    Generate Cobertura coverage.xml from analysis and trace
    
  generate-simple <repo_path> <source_file> <analysis_json> <covered_lines_file> <output_xml>
    Generate from analysis and simple covered lines list

Examples:
  python coverage_generator.py generate . bbr.c bbr_analysis.json trace.json coverage.xml
  python coverage_generator.py generate-simple . bbr.c bbr_analysis.json covered.txt coverage.xml
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'generate':
        if len(sys.argv) < 7:
            print("Usage: coverage_generator.py generate <repo> <source> <analysis> <trace> <output>")
            sys.exit(1)
        
        repo_path = sys.argv[2]
        source_file = sys.argv[3]
        analysis_json = sys.argv[4]
        trace_json = sys.argv[5]
        output_xml = sys.argv[6]
        
        generator = CoverageGenerator(source_file, repo_path)
        generator.load_analysis(analysis_json)
        generator.load_trace(trace_json)
        generator.print_summary()
        generator.generate_cobertura_xml(output_xml)
        
        print(f"\nCoverage XML generated: {output_xml}")
    
    elif command == 'generate-simple':
        if len(sys.argv) < 7:
            print("Usage: coverage_generator.py generate-simple <repo> <source> <analysis> <covered> <output>")
            sys.exit(1)
        
        repo_path = sys.argv[2]
        source_file = sys.argv[3]
        analysis_json = sys.argv[4]
        covered_file = sys.argv[5]
        output_xml = sys.argv[6]
        
        generator = CoverageGenerator(source_file, repo_path)
        generator.load_analysis(analysis_json)
        generator.load_simple_coverage(covered_file)
        generator.print_summary()
        generator.generate_cobertura_xml(output_xml)
        
        print(f"\nCoverage XML generated: {output_xml}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
