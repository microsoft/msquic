import os
import json
import sys
import pickle
import hashlib
from collections import deque
from typing import Dict, List, Optional, Tuple
import tree_sitter
from tree_sitter import Language

# Tree-sitter language modules (required for parsing).
LANGUAGE_MODULES: Dict[str, str] = {
    "python": "tree_sitter_python",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
}

EXT_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
}

PARSERS: Dict[str, tree_sitter.Parser] = {}

project_path = os.getcwd()
programming_language = "python"
prefer_path = ""
parser: Optional[tree_sitter.Parser] = None

project_data = {
    "functions": {},
    "function_calls": {},
    "function_callees": {},
    "types": {},
    "defines": {},
    "classes": {}
}

# Cache configuration
CACHE_DIR = os.path.join(os.path.dirname(__file__), ".cache")
CACHE_VERSION = "v1"  # Bump this if cache format changes


def _detect_language(file_path: str) -> Optional[str]:
    _, ext = os.path.splitext(file_path)
    return EXT_TO_LANGUAGE.get(ext.lower())


def _get_parser(lang: Optional[str]) -> Optional[tree_sitter.Parser]:
    if not lang:
        return None
    if lang in PARSERS:
        return PARSERS[lang]

    module_name = LANGUAGE_MODULES.get(lang)
    if not module_name:
        return None

    module = __import__(module_name, fromlist=["language"])
    ts_lang = Language(module.language())
    ts_parser = tree_sitter.Parser()
    ts_parser.language = ts_lang
    PARSERS[lang] = ts_parser
    return ts_parser


def _get_cache_path(proj_path: str) -> str:
    """Get cache file path for a project."""
    path_hash = hashlib.md5(proj_path.encode()).hexdigest()[:12]
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"project_cache_{path_hash}_{CACHE_VERSION}.pkl")


def _get_project_fingerprint(proj_path: str) -> str:
    """
    Compute a fingerprint of the project based on file paths and modification times.
    This is fast - just stats, no file reads.
    """
    files_info = []
    for root, dirs, files in os.walk(proj_path):
        for file in files:
            if not file.endswith((".c", ".h", ".w", ".cpp", ".hpp", ".py")):
                continue
            file_path = os.path.join(root, file)
            try:
                stat = os.stat(file_path)
                files_info.append((file_path, stat.st_mtime, stat.st_size))
            except OSError:
                continue
    
    files_info.sort()
    fingerprint = hashlib.md5(str(files_info).encode()).hexdigest()
    return fingerprint


def _load_cache(cache_path: str, expected_fingerprint: str) -> Optional[Dict]:
    """Load cached project data if valid."""
    if not os.path.exists(cache_path):
        return None
    
    try:
        with open(cache_path, "rb") as f:
            cached = pickle.load(f)
        
        if cached.get("fingerprint") != expected_fingerprint:
            print("Cache fingerprint mismatch, re-indexing...", file=sys.stderr)
            return None
        
        return cached.get("data")
    except Exception as e:
        print(f"Cache load failed: {e}", file=sys.stderr)
        return None


def _save_cache(cache_path: str, fingerprint: str, data: Dict):
    """Save project data to cache."""
    try:
        # We can't pickle tree-sitter nodes directly, so store serializable info
        serializable_data = {
            "functions": {},
            "function_calls": data["function_calls"],
            "function_callees": data["function_callees"],
            "types": data["types"],
            "defines": data["defines"],
            "classes": data["classes"],
        }
        
        # Serialize function nodes as (start_byte, end_byte, start_line, end_line)
        for file_path, funcs in data["functions"].items():
            serializable_data["functions"][file_path] = {}
            for name, node in funcs.items():
                serializable_data["functions"][file_path][name] = {
                    "start_byte": node.start_byte,
                    "end_byte": node.end_byte,
                    "start_line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1,
                }
        
        with open(cache_path, "wb") as f:
            pickle.dump({"fingerprint": fingerprint, "data": serializable_data}, f)
        
        print(f"Cache saved to {cache_path}", file=sys.stderr)
    except Exception as e:
        print(f"Cache save failed: {e}", file=sys.stderr)


def init(proj_path, force_reindex: bool = False):
    global parser, project_path, programming_language, project_data
    project_path = proj_path
    
    # Check cache first
    cache_path = _get_cache_path(proj_path)
    fingerprint = _get_project_fingerprint(proj_path)
    
    if not force_reindex:
        cached_data = _load_cache(cache_path, fingerprint)
        if cached_data:
            project_data = cached_data
            print(f"✅ Loaded from cache. Functions in {len(project_data['functions'])} files.", file=sys.stderr)
            return project_data
    
    # No valid cache, do full indexing
    print("Indexing project with tree-sitter...", file=sys.stderr)
    files_processed = 0
    ts_files = 0

    for root, dirs, files in os.walk(project_path):
        for file in files:
            if not (file.endswith((".c", ".h", ".w", ".cpp", ".hpp", ".py"))):
                continue

            file_path = os.path.join(root, file)
            lang = _detect_language(file_path)
            files_processed += 1

            try:
                with open(file_path, "rb") as c_file:
                    file_content = c_file.read()
            except Exception as e:
                print(f"Warning: Could not read file {file_path}: {e}", file=sys.stderr)
                continue

            ts_parser = _get_parser(lang)
            if not ts_parser:
                raise RuntimeError(f"Tree-sitter parser not available for language '{lang}' (file {file_path}).")

            try:
                tree = ts_parser.parse(file_content)
                parser = parser or ts_parser
                programming_language = lang
                project_data["functions"][file_path], project_data["function_calls"][file_path], project_data["function_callees"][file_path] = parse_all_function_info(file_content, tree)
                project_data["types"][file_path] = parse_all_type_info(file_content, tree)
                project_data["defines"][file_path] = parse_all_define_info(file_content, tree)
                project_data["classes"][file_path] = parse_all_class_info(file_content, tree)
                ts_files += 1
            except Exception as exc:
                raise RuntimeError(f"Tree-sitter parse failed for {file_path}: {exc}") from exc

    print(f"✅ Initialization complete. Files: {files_processed}, tree-sitter: {ts_files}.", file=sys.stderr)
    
    # Save to cache
    _save_cache(cache_path, fingerprint, project_data)
    
    return project_data


def find_nodes_by_type(root_node: tree_sitter.Node, node_type: str) -> List[tree_sitter.Node]:
    nodes = []
    if root_node.type == node_type:
        nodes.append(root_node)
    for child_node in root_node.children:
        nodes.extend(find_nodes_by_type(child_node, node_type))
    return nodes


def find_first_node_by_type(root_node: tree_sitter.Node, node_type: str) -> tree_sitter.Node:
    queue = deque([root_node])
    while queue:
        current_node = queue.popleft()
        if current_node.type == node_type:
            return current_node
        for child_node in current_node.children:
            queue.append(child_node)
    return None


def parse_all_function_info(source_code, tree: tree_sitter.Tree):
    fun_info = {}
    fun_call_info = {}
    fun_callee_info = {}
    
    if programming_language in ("c", "cpp"):
        all_function_nodes = find_nodes_by_type(tree.root_node, "function_definition")
        for node in all_function_nodes:
            dec_node = find_first_node_by_type(node, "function_declarator")
            if not dec_node:
                continue
            function_name = None
            
            call_expr = find_first_node_by_type(dec_node, "call_expression")
            if call_expr:
                call_ident = find_first_node_by_type(call_expr, "identifier")
                if call_ident:
                    potential_name = source_code[call_ident.start_byte:call_ident.end_byte].decode("utf8", errors="replace")
                    if not (potential_name.startswith("_") and any(keyword in potential_name for keyword in ["_Ret_", "_Post_", "_Pre_", "_In_", "_Out_", "_Check_", "_Frees_"])):
                        function_name = potential_name
                        fun_info[function_name] = node
            
            if not function_name:
                for sub_node in dec_node.children:
                    if sub_node.type == "identifier":
                        potential_name = source_code[sub_node.start_byte:sub_node.end_byte].decode("utf8", errors="replace")
                        if not (potential_name.startswith("_") and any(keyword in potential_name for keyword in ["_Ret_", "_Post_", "_Pre_", "_In_", "_Out_", "_Check_", "_Frees_"])):
                            if potential_name not in ["PVOID", "VOID", "BOOL", "INT", "UINT", "DWORD", "LONG", "ULONG"]:
                                function_name = potential_name
                                fun_info[function_name] = node
                                break
            if function_name:
                call_nodes = find_nodes_by_type(node, "call_expression")
                for call_node in call_nodes:
                    call_ident = find_first_node_by_type(call_node, "identifier")
                    if call_ident:
                        called_name = source_code[call_ident.start_byte:call_ident.end_byte].decode("utf8", errors="replace")
                        if called_name not in fun_call_info:
                            fun_call_info[called_name] = set()
                        fun_call_info[called_name].add(function_name)
                        if function_name not in fun_callee_info:
                            fun_callee_info[function_name] = set()
                        fun_callee_info[function_name].add(called_name)
        
        all_def_funciton_nodes = find_nodes_by_type(tree.root_node, "preproc_function_def")
        for node in all_def_funciton_nodes:
            for sub_node in node.children:
                if sub_node.type == "identifier":
                    function_name = source_code[sub_node.start_byte:sub_node.end_byte].decode("utf8", errors="replace")
                    fun_info[function_name] = node

    elif programming_language == "python":
        all_function_nodes = find_nodes_by_type(tree.root_node, "function_definition")
        for node in all_function_nodes:
            function_name = None
            name_node = None
            if hasattr(node, 'child_by_field_name'):
                try:
                    name_node = node.child_by_field_name('name')
                except Exception:
                    name_node = None

            if name_node and name_node.type == 'identifier':
                function_name = source_code[name_node.start_byte:name_node.end_byte].decode('utf8', errors="replace")
                fun_info[function_name] = node
            else:
                for child in node.children:
                    if child.type == 'identifier':
                        function_name = source_code[child.start_byte:child.end_byte].decode('utf8', errors="replace")
                        fun_info[function_name] = node
                        break

                if not function_name:
                    ident = find_first_node_by_type(node, 'identifier')
                    if ident:
                        function_name = source_code[ident.start_byte:ident.end_byte].decode('utf8', errors="replace")
                        fun_info[function_name] = node

            if function_name:
                call_nodes = find_nodes_by_type(node, "call")
                for call_node in call_nodes:
                    call_ident = find_first_node_by_type(call_node, "identifier")
                    if call_ident:
                        called_name = source_code[call_ident.start_byte:call_ident.end_byte].decode("utf8", errors="replace")
                        if called_name not in fun_call_info:
                            fun_call_info[called_name] = set()
                        fun_call_info[called_name].add(function_name)
                        if function_name not in fun_callee_info:
                            fun_callee_info[function_name] = set()
                        fun_callee_info[function_name].add(called_name)

    return fun_info, fun_call_info, fun_callee_info


def parse_all_type_info(source_code, tree: tree_sitter.Tree):
    return {}


def parse_all_define_info(source_code, tree: tree_sitter.Tree):
    return {}


def parse_all_class_info(source_code, tree: tree_sitter.Tree):
    return {}


def _get_node_bytes(node_or_dict) -> Tuple[int, int]:
    """Get start_byte and end_byte from either a tree-sitter node or cached dict."""
    if hasattr(node_or_dict, 'start_byte'):
        # It's a tree-sitter node
        return node_or_dict.start_byte, node_or_dict.end_byte
    else:
        # It's a cached dict
        return node_or_dict["start_byte"], node_or_dict["end_byte"]


def query_function(function_name: str, file_path: str = None) -> str:
    file_to_fundef = project_data["functions"]

    if file_path:
        if file_path in file_to_fundef and function_name in file_to_fundef[file_path]:
            node = file_to_fundef[file_path][function_name]
            start_byte, end_byte = _get_node_bytes(node)
            with open(file_path, "rb") as f:
                source_code = f.read()
            return source_code[start_byte:end_byte].decode("utf8", errors="replace")
        return ""

    for path, fun_info in file_to_fundef.items():
        if function_name in fun_info:
            node = fun_info[function_name]
            start_byte, end_byte = _get_node_bytes(node)
            with open(path, "rb") as f:
                source_code = f.read()
            return source_code[start_byte:end_byte].decode("utf8", errors="replace")
    return ""


def build_call_graph(function_name, visited=None, file_path=None):
    if not project_data:
        raise ValueError("Project data is not initialized. Please run init() first.")

    if visited is None:
        visited = set()

    if function_name in visited:
        return {"function": function_name, "calls": "Already visited (cycle)"}

    visited.add(function_name)

    target_path = None
    if file_path:
        funcs = project_data["functions"].get(file_path, {})
        if function_name in funcs:
            target_path = file_path

    if not target_path:
        for path, functions in project_data["functions"].items():
            if function_name in functions:
                target_path = path
                break

    if not target_path:
        print(f"⚠️ Function {function_name} not found in project.")
        return {
            "file": "unknown",
            "function": function_name,
            "calls": []
        }

    print(f"Analyzing function: {function_name} in {target_path}")

    callees = project_data["function_callees"].get(target_path, {}).get(function_name, set())

    calls = []
    for callee in callees:
        callee_subgraph = build_call_graph(callee, visited, None)
        calls.append(callee_subgraph)

    # Get line numbers from the function node
    start_line = 0
    end_line = 0
    func_node = project_data["functions"].get(target_path, {}).get(function_name)
    if func_node:
        if hasattr(func_node, 'start_point'):
            # tree-sitter node
            start_line = func_node.start_point[0] + 1  # tree-sitter uses 0-based indexing
            end_line = func_node.end_point[0] + 1
        else:
            # cached dict
            start_line = func_node.get("start_line", 0)
            end_line = func_node.get("end_line", 0)

    return {
        "file": target_path,
        "function": function_name,
        "start_line": start_line,
        "end_line": end_line,
        "calls": calls
    }
