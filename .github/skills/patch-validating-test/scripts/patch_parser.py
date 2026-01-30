#!/usr/bin/env python3
"""
Patch Parser
============

PURPOSE:
    Parses unified diff format (git diff, patch files) to extract structured
    information about file changes, hunks, and individual line modifications.

WHAT THIS SCRIPT DOES:
    1. Parses unified diff format (the standard format from 'git diff')
    2. Extracts file-level information (old/new paths, new/deleted/renamed status)
    3. Extracts hunk information (line ranges, context header)
    4. Extracts line-level changes (added, removed, context lines)
    5. Provides statistics (files changed, lines added/removed)
    6. Exports parsed data to JSON for further analysis

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT interpret the meaning of changes
    - Does NOT analyze code semantics
    - Does NOT determine if changes are good/bad
    - Does NOT identify functions or code structures (see patch_analyzer.py)
    - Does NOT make any quality judgments

SUPPORTED FORMATS:
    - Git diff format (diff --git a/file b/file)
    - Traditional unified diff (--- a/file, +++ b/file)
    - New/deleted/renamed file detection

OUTPUT:
    JSON containing:
    - statistics: {files_changed, lines_added, lines_removed, ...}
    - files: [{old_path, new_path, is_new_file, is_deleted, hunks, ...}]
    - Each hunk: {old_start, old_count, new_start, new_count, added_lines, removed_lines}

USAGE:
    python patch_parser.py parse <patch_file> [--json output.json]
    python patch_parser.py summary <patch_file>
    python patch_parser.py files <patch_file>
    python patch_parser.py lines <patch_file> [file_path]

DESIGN NOTE:
    This script performs SYNTACTIC PARSING only. It extracts the structure
    of a diff without understanding what the code does. The agent or
    patch_analyzer.py uses this parsed data for semantic analysis.
"""

import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum


class ChangeType(Enum):
    """
    Type of change for a single line in a diff.
    
    Values:
        ADDED: Line was added (starts with '+' in diff)
        REMOVED: Line was removed (starts with '-' in diff)
        CONTEXT: Line is unchanged context (starts with ' ' in diff)
    """
    ADDED = "added"
    REMOVED = "removed"
    CONTEXT = "context"


@dataclass
class LineChange:
    """
    Represents a single line change in a patch.
    
    This is a FACTUAL record of what the diff says, not an interpretation.
    
    Attributes:
        change_type: ADDED, REMOVED, or CONTEXT
        content: The actual line content (without the +/- prefix)
        old_line_num: Line number in the old file (None for added lines)
        new_line_num: Line number in the new file (None for removed lines)
    """
    change_type: ChangeType
    content: str
    old_line_num: Optional[int] = None
    new_line_num: Optional[int] = None


@dataclass
class Hunk:
    """
    Represents a hunk (chunk) of changes in a diff.
    
    A hunk is a contiguous section of changes, marked by @@ in the diff.
    Example: @@ -10,5 +12,7 @@ function_name
    
    Attributes:
        old_start: Starting line in old file
        old_count: Number of lines from old file
        new_start: Starting line in new file
        new_count: Number of lines in new file
        header: Context after @@ (often function name)
        lines: List of LineChange objects
    """
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: List[LineChange] = field(default_factory=list)
    
    def get_added_lines(self) -> List[Tuple[int, str]]:
        """
        Get all added lines with their new line numbers.
        
        Returns:
            List of (line_number, content) tuples
        """
        return [(l.new_line_num, l.content) for l in self.lines 
                if l.change_type == ChangeType.ADDED and l.new_line_num]
    
    def get_removed_lines(self) -> List[Tuple[int, str]]:
        """
        Get all removed lines with their old line numbers.
        
        Returns:
            List of (line_number, content) tuples
        """
        return [(l.old_line_num, l.content) for l in self.lines 
                if l.change_type == ChangeType.REMOVED and l.old_line_num]
    
    def get_modified_line_range(self) -> Tuple[int, int]:
        """
        Get the range of modified lines in the new file.
        
        Returns:
            (start_line, end_line) tuple
        """
        new_lines = [l.new_line_num for l in self.lines if l.new_line_num]
        if new_lines:
            return (min(new_lines), max(new_lines))
        return (self.new_start, self.new_start + self.new_count - 1)


@dataclass
class FilePatch:
    """
    Represents all changes to a single file.
    
    Attributes:
        old_path: Path in the old version (a/...)
        new_path: Path in the new version (b/...)
        hunks: List of Hunk objects containing the changes
        is_new_file: True if this file was created
        is_deleted_file: True if this file was deleted
        is_renamed: True if this file was renamed
    """
    old_path: str
    new_path: str
    hunks: List[Hunk] = field(default_factory=list)
    is_new_file: bool = False
    is_deleted_file: bool = False
    is_renamed: bool = False
    
    def get_all_added_lines(self) -> List[Tuple[int, str]]:
        """Get all added lines across all hunks."""
        result = []
        for hunk in self.hunks:
            result.extend(hunk.get_added_lines())
        return result
    
    def get_all_removed_lines(self) -> List[Tuple[int, str]]:
        """Get all removed lines across all hunks."""
        result = []
        for hunk in self.hunks:
            result.extend(hunk.get_removed_lines())
        return result
    
    def get_changed_line_numbers(self) -> Dict[str, List[int]]:
        """
        Get lists of added and removed line numbers.
        
        Returns:
            {'added': [line_nums...], 'removed': [line_nums...]}
        """
        return {
            'added': [line_num for line_num, _ in self.get_all_added_lines()],
            'removed': [line_num for line_num, _ in self.get_all_removed_lines()]
        }


@dataclass 
class PatchInfo:
    """
    Complete patch information.
    
    This is the top-level container for all parsed patch data.
    
    Attributes:
        files: List of FilePatch objects, one per changed file
    """
    files: List[FilePatch] = field(default_factory=list)
    
    def get_changed_files(self) -> List[str]:
        """Get list of all changed file paths (new paths)."""
        return [f.new_path for f in self.files]
    
    def get_statistics(self) -> Dict:
        """
        Get patch statistics.
        
        Returns dict with:
        - files_changed: Total files modified
        - lines_added: Total lines added
        - lines_removed: Total lines removed
        - new_files: Count of new files
        - deleted_files: Count of deleted files
        - renamed_files: Count of renamed files
        """
        total_added = 0
        total_removed = 0
        
        for file_patch in self.files:
            for hunk in file_patch.hunks:
                for line in hunk.lines:
                    if line.change_type == ChangeType.ADDED:
                        total_added += 1
                    elif line.change_type == ChangeType.REMOVED:
                        total_removed += 1
        
        return {
            'files_changed': len(self.files),
            'lines_added': total_added,
            'lines_removed': total_removed,
            'new_files': sum(1 for f in self.files if f.is_new_file),
            'deleted_files': sum(1 for f in self.files if f.is_deleted_file),
            'renamed_files': sum(1 for f in self.files if f.is_renamed)
        }


class PatchParser:
    """
    Parses unified diff format patches.
    
    This class performs SYNTACTIC PARSING:
    - Recognizes diff format structure
    - Extracts file headers, hunks, and lines
    - Tracks line numbers correctly
    
    It does NOT interpret what the changes mean - that's for the agent
    or higher-level analyzers.
    """
    
    # ==========================================================================
    # REGEX PATTERNS FOR DIFF PARSING
    # ==========================================================================
    # These patterns match the standard unified diff format
    # ==========================================================================
    
    # File headers
    FILE_HEADER_OLD = re.compile(r'^--- (.+?)(?:\t.*)?$')      # --- a/file.c
    FILE_HEADER_NEW = re.compile(r'^\+\+\+ (.+?)(?:\t.*)?$')   # +++ b/file.c
    
    # Hunk header: @@ -old_start,old_count +new_start,new_count @@ context
    HUNK_HEADER = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$')
    
    # Git-specific headers
    GIT_DIFF_HEADER = re.compile(r'^diff --git a/(.+) b/(.+)$')
    NEW_FILE_MODE = re.compile(r'^new file mode')
    DELETED_FILE_MODE = re.compile(r'^deleted file mode')
    RENAME_FROM = re.compile(r'^rename from (.+)$')
    RENAME_TO = re.compile(r'^rename to (.+)$')
    
    def __init__(self):
        """Initialize the parser."""
        self.patch_info = PatchInfo()
    
    def parse(self, patch_content: str) -> PatchInfo:
        """
        Parse a patch string and return PatchInfo.
        
        This is the main parsing method. It processes the diff line by line,
        building up the structured representation.
        
        Args:
            patch_content: The full patch/diff content as a string
            
        Returns:
            PatchInfo containing all parsed data
        """
        self.patch_info = PatchInfo()
        lines = patch_content.splitlines()
        
        i = 0
        current_file: Optional[FilePatch] = None
        
        while i < len(lines):
            line = lines[i]
            
            # Check for git diff header (diff --git a/... b/...)
            git_match = self.GIT_DIFF_HEADER.match(line)
            if git_match:
                # Save previous file if any
                if current_file:
                    self.patch_info.files.append(current_file)
                # Start new file
                current_file = FilePatch(
                    old_path=git_match.group(1),
                    new_path=git_match.group(2)
                )
                i += 1
                continue
            
            # Check for new/deleted/renamed file markers
            if current_file:
                if self.NEW_FILE_MODE.match(line):
                    current_file.is_new_file = True
                    i += 1
                    continue
                if self.DELETED_FILE_MODE.match(line):
                    current_file.is_deleted_file = True
                    i += 1
                    continue
                rename_from = self.RENAME_FROM.match(line)
                if rename_from:
                    current_file.is_renamed = True
                    current_file.old_path = rename_from.group(1)
                    i += 1
                    continue
                rename_to = self.RENAME_TO.match(line)
                if rename_to:
                    current_file.new_path = rename_to.group(1)
                    i += 1
                    continue
            
            # Check for traditional --- header
            old_match = self.FILE_HEADER_OLD.match(line)
            if old_match:
                if not current_file:
                    # Non-git diff format
                    current_file = FilePatch(
                        old_path=old_match.group(1).replace('a/', '', 1),
                        new_path=""
                    )
                else:
                    current_file.old_path = old_match.group(1).replace('a/', '', 1)
                i += 1
                continue
            
            # Check for +++ header
            new_match = self.FILE_HEADER_NEW.match(line)
            if new_match:
                if current_file:
                    current_file.new_path = new_match.group(1).replace('b/', '', 1)
                i += 1
                continue
            
            # Check for hunk header (@@ -x,y +a,b @@)
            hunk_match = self.HUNK_HEADER.match(line)
            if hunk_match and current_file:
                hunk = Hunk(
                    old_start=int(hunk_match.group(1)),
                    old_count=int(hunk_match.group(2) or 1),
                    new_start=int(hunk_match.group(3)),
                    new_count=int(hunk_match.group(4) or 1),
                    header=hunk_match.group(5).strip()
                )
                
                # Parse hunk content (the actual +/- lines)
                i += 1
                old_line = hunk.old_start
                new_line = hunk.new_start
                
                while i < len(lines):
                    hunk_line = lines[i]
                    
                    # Check if we've hit the next hunk or file
                    if (hunk_line.startswith('@@') or 
                        hunk_line.startswith('diff ') or
                        hunk_line.startswith('--- ') or
                        hunk_line.startswith('+++ ')):
                        break
                    
                    # Parse the line based on its prefix
                    if hunk_line.startswith('+'):
                        # Added line
                        hunk.lines.append(LineChange(
                            change_type=ChangeType.ADDED,
                            content=hunk_line[1:],
                            new_line_num=new_line
                        ))
                        new_line += 1
                    elif hunk_line.startswith('-'):
                        # Removed line
                        hunk.lines.append(LineChange(
                            change_type=ChangeType.REMOVED,
                            content=hunk_line[1:],
                            old_line_num=old_line
                        ))
                        old_line += 1
                    elif hunk_line.startswith(' ') or hunk_line == '':
                        # Context line (unchanged)
                        content = hunk_line[1:] if hunk_line.startswith(' ') else hunk_line
                        hunk.lines.append(LineChange(
                            change_type=ChangeType.CONTEXT,
                            content=content,
                            old_line_num=old_line,
                            new_line_num=new_line
                        ))
                        old_line += 1
                        new_line += 1
                    elif hunk_line.startswith('\\'):
                        # "\ No newline at end of file" - skip
                        pass
                    else:
                        # Unknown line format, treat as context
                        hunk.lines.append(LineChange(
                            change_type=ChangeType.CONTEXT,
                            content=hunk_line,
                            old_line_num=old_line,
                            new_line_num=new_line
                        ))
                        old_line += 1
                        new_line += 1
                    
                    i += 1
                
                current_file.hunks.append(hunk)
                continue
            
            i += 1
        
        # Don't forget the last file
        if current_file:
            self.patch_info.files.append(current_file)
        
        return self.patch_info
    
    def parse_file(self, patch_file: str) -> PatchInfo:
        """
        Parse a patch from a file.
        
        Args:
            patch_file: Path to the patch file
            
        Returns:
            PatchInfo containing all parsed data
        """
        with open(patch_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        return self.parse(content)


def serialize_patch_info(patch_info: PatchInfo) -> Dict:
    """
    Convert PatchInfo to JSON-serializable dict.
    
    Args:
        patch_info: The parsed patch information
        
    Returns:
        Dictionary suitable for JSON serialization
    """
    result = {
        'statistics': patch_info.get_statistics(),
        'files': []
    }
    
    for file_patch in patch_info.files:
        file_dict = {
            'old_path': file_patch.old_path,
            'new_path': file_patch.new_path,
            'is_new_file': file_patch.is_new_file,
            'is_deleted_file': file_patch.is_deleted_file,
            'is_renamed': file_patch.is_renamed,
            'changed_lines': file_patch.get_changed_line_numbers(),
            'hunks': []
        }
        
        for hunk in file_patch.hunks:
            hunk_dict = {
                'old_start': hunk.old_start,
                'old_count': hunk.old_count,
                'new_start': hunk.new_start,
                'new_count': hunk.new_count,
                'header': hunk.header,
                'added_lines': hunk.get_added_lines(),
                'removed_lines': hunk.get_removed_lines(),
                'modified_range': hunk.get_modified_line_range()
            }
            file_dict['hunks'].append(hunk_dict)
        
        result['files'].append(file_dict)
    
    return result


def main():
    if len(sys.argv) < 2:
        print("""
Patch Parser - Parse unified diff format patches

Usage:
  python patch_parser.py <command> [options]

Commands:
  parse <patch_file> [--json <output.json>]
    Parse a patch file and display/export results
    
  summary <patch_file>
    Show a brief summary of the patch
    
  files <patch_file>
    List all changed files
    
  lines <patch_file> [file_path]
    Show changed line numbers (optionally filtered by file)

Examples:
  python patch_parser.py parse fix.patch --json analysis.json
  python patch_parser.py summary feature.patch
  python patch_parser.py files bugfix.patch
  python patch_parser.py lines update.patch src/main.c
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'parse':
        if len(sys.argv) < 3:
            print("Usage: patch_parser.py parse <patch_file> [--json output.json]")
            sys.exit(1)
        
        patch_file = sys.argv[2]
        json_output = None
        
        # Parse optional arguments
        if '--json' in sys.argv:
            idx = sys.argv.index('--json')
            if idx + 1 < len(sys.argv):
                json_output = sys.argv[idx + 1]
        
        parser = PatchParser()
        patch_info = parser.parse_file(patch_file)
        
        # Display results
        stats = patch_info.get_statistics()
        print(f"\n=== Patch Analysis: {patch_file} ===")
        print(f"Files changed: {stats['files_changed']}")
        print(f"Lines added: {stats['lines_added']}")
        print(f"Lines removed: {stats['lines_removed']}")
        
        if stats['new_files'] > 0:
            print(f"New files: {stats['new_files']}")
        if stats['deleted_files'] > 0:
            print(f"Deleted files: {stats['deleted_files']}")
        if stats['renamed_files'] > 0:
            print(f"Renamed files: {stats['renamed_files']}")
        
        print("\n=== Changed Files ===")
        for file_patch in patch_info.files:
            status = ""
            if file_patch.is_new_file:
                status = " [NEW]"
            elif file_patch.is_deleted_file:
                status = " [DELETED]"
            elif file_patch.is_renamed:
                status = f" [RENAMED from {file_patch.old_path}]"
            
            print(f"  {file_patch.new_path}{status}")
            
            added = len(file_patch.get_all_added_lines())
            removed = len(file_patch.get_all_removed_lines())
            print(f"    +{added} -{removed} lines")
        
        if json_output:
            with open(json_output, 'w') as f:
                json.dump(serialize_patch_info(patch_info), f, indent=2)
            print(f"\nJSON exported to: {json_output}")
    
    elif command == 'summary':
        if len(sys.argv) < 3:
            print("Usage: patch_parser.py summary <patch_file>")
            sys.exit(1)
        
        patch_file = sys.argv[2]
        parser = PatchParser()
        patch_info = parser.parse_file(patch_file)
        stats = patch_info.get_statistics()
        
        print(f"Patch: {patch_file}")
        print(f"  {stats['files_changed']} file(s) changed")
        print(f"  {stats['lines_added']} insertion(s), {stats['lines_removed']} deletion(s)")
    
    elif command == 'files':
        if len(sys.argv) < 3:
            print("Usage: patch_parser.py files <patch_file>")
            sys.exit(1)
        
        patch_file = sys.argv[2]
        parser = PatchParser()
        patch_info = parser.parse_file(patch_file)
        
        for f in patch_info.get_changed_files():
            print(f)
    
    elif command == 'lines':
        if len(sys.argv) < 3:
            print("Usage: patch_parser.py lines <patch_file> [file_path]")
            sys.exit(1)
        
        patch_file = sys.argv[2]
        filter_path = sys.argv[3] if len(sys.argv) > 3 else None
        
        parser = PatchParser()
        patch_info = parser.parse_file(patch_file)
        
        for file_patch in patch_info.files:
            if filter_path and filter_path not in file_patch.new_path:
                continue
            
            print(f"\n{file_patch.new_path}:")
            changes = file_patch.get_changed_line_numbers()
            
            if changes['added']:
                print(f"  Added lines: {changes['added']}")
            if changes['removed']:
                print(f"  Removed lines: {changes['removed']}")
    
    else:
        print(f"Unknown command: {command}")
        print("Run without arguments for help")
        sys.exit(1)


if __name__ == "__main__":
    main()
