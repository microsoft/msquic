#!/usr/bin/env python3
#
#  Copyright 2023 Ji WenCong <admin@xiaojsoft.org>. All rights reserved.
#
#  Licensed to MsQuic project under Contributor License Agreement (CLA)
#  with Microsoft Corporation.
#

import os
import sys
import json

import re

#  Directory/file paths.
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SRC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "..", "src"))

CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")

#  Unified path separator.
UNIFIED_SEP = "/"

ASCII_UPPER_A = 65
ASCII_UPPER_Z = 90

RE_PRAGMA_ONCE = re.compile(r"^\#[\s]*pragma[\s]+once[\s]*$")
RE_IFNDEF = re.compile(r"^\#[\s]*ifndef[\s]+([^\s]+)[\s]*$")
RE_DEFINE = re.compile(r"^\#[\s]*define[\s]+([^\s]+)[\s]*(.*)$")
RE_ENDIF = re.compile(r"^\#[\s]*endif[\s]*([^\s].*)?$")


def is_header_file(file_name):
    for ext in [".h", ".hpp"]:
        if file_name.lower().endswith(ext):
            return True
    return False


def is_skipped_file(file_rel, skip_list):
    for skip_re in skip_list:
        if skip_re.search(file_rel) is not None:
            return True
    return False


def find_header_files(dir_path, rel="", file_list=[], skip_list=[]):
    for sub_name in os.listdir(dir_path):
        sub_path = os.path.join(dir_path, sub_name)
        sub_rel = (sub_name if len(rel) == 0 else (rel + UNIFIED_SEP + sub_name))
        if os.path.isdir(sub_path):
            find_header_files(
                sub_path, 
                rel=sub_rel, 
                file_list=file_list,
                skip_list=skip_list
            )
        else:
            if not is_header_file(sub_name):
                continue
            if is_skipped_file(sub_rel, skip_list):
                continue
            file_list.append({
                "name": sub_name,
                "path": sub_path,
                "rel": sub_rel
            })
    
    return file_list


def append_warning(warnings, file_info, msg):
    warnings.append({
        "file": file_info,
        "message": msg
    })


ST_FRONT_WAIT_HASHTAG = 0
ST_FRONT_HANDLE_HASHTAG = 1
ST_FRONT_DETECT_DEFINE = 2
ST_FRONT_ERR = -2
ST_FRONT_OK = -1

ST_TAIL_WAIT_HASHTAG = 0
ST_TAIL_HANDLE_HASHTAG = 1
ST_TAIL_ERR = -2
ST_TAIL_OK = -1


def check_header_file(file_info, file_encoding="utf-8", use_google_style=False, use_pragma_once=False, warnings=[], auto_fix=False):
    file_name = file_info["name"]
    file_path = file_info["path"]
    file_rel = file_info["rel"]

    #  Read the header file.
    fp = open(file_path, "r", encoding=file_encoding)
    file_content = fp.read()
    file_lines = file_content.splitlines(False)
    fp.close()

    #
    #  Get the name of the include guard macro.
    #
    #  If Google's coding-style is used, the macro indicates the path of the file relative to 
    #  the project root.
    #  If Google's coding-style is not used, the macro indicates the file name only.
    #
    if use_google_style:
        incguard_macro = "_MSQUIC_SRC_"
        for ch in file_rel:                       #  Replace non-letter characters with underscore.
            ch = ch.upper()
            chcode = ord(ch)
            if chcode >= ASCII_UPPER_A and chcode <= ASCII_UPPER_Z:
                incguard_macro += ch
            else:
                incguard_macro += "_"
        if not incguard_macro.endswith("_"):
            incguard_macro += "_"
    else:
        incguard_macro = "_"
        for ch in file_name:                      #  Replace non-letter characters with underscore.
            ch = ch.upper()
            chcode = ord(ch)
            if chcode >= ASCII_UPPER_A and chcode <= ASCII_UPPER_Z:
                incguard_macro += ch
            else:
                incguard_macro += "_"
        if not incguard_macro.endswith("_"):
            incguard_macro += "_"
    
    #
    #  Now check the front part of the header file.
    #
    #  If "#pragma once" is used, it shall be the first line starts with '#' character.
    #  Then, a "#ifndef ...\n#define ...\n" sequence must be found.
    #
    
    actual_incguard_macro = None
    found_pragma_once = False
    
    state = ST_FRONT_WAIT_HASHTAG
    cursor = 0
    current_line = None
    
    lineno_pragma_once = -1
    lineno_ifndef = -1
    lineno_define = -1
    
    while True:
        if state == ST_FRONT_WAIT_HASHTAG:
            if cursor >= len(file_lines):
                append_warning(warnings, file_info, "No line starts with hashtag (#) can be found.")
                state = ST_FRONT_ERR
                continue
            current_line = file_lines[cursor].lstrip()
            cursor += 1
            if current_line.startswith("#"):
                state = ST_FRONT_HANDLE_HASHTAG
        elif state == ST_FRONT_HANDLE_HASHTAG:
            if RE_PRAGMA_ONCE.match(current_line) is not None:
                lineno_pragma_once = cursor - 1
                found_pragma_once = True
                state = ST_FRONT_WAIT_HASHTAG
                continue
            else:
                tmp = RE_IFNDEF.match(current_line)
                if tmp is not None:
                    lineno_ifndef = cursor - 1
                    actual_incguard_macro = tmp[1]
                    state = ST_FRONT_DETECT_DEFINE
                else:
                    append_warning(warnings, file_info, "Expect a #ifndef line.")
                    state = ST_FRONT_ERR
                    continue
        elif state == ST_FRONT_DETECT_DEFINE:
            if cursor >= len(file_lines):
                append_warning(warnings, file_info, "No #define line after the #ifndef line.")
                state = ST_FRONT_ERR
                continue
            current_line = file_lines[cursor].lstrip()
            cursor += 1
            if current_line.startswith("#"):
                tmp = RE_DEFINE.match(current_line)
                if tmp is None:
                    append_warning(warnings, file_info, "Expect a #define line right after the #ifndef line.")
                    state = ST_FRONT_ERR
                    continue
                
                lineno_define = cursor - 1
                
                if tmp[1] != actual_incguard_macro:
                    msg = "The include guard macro in #ifndef (%s) is different from the #define (%s)." % (
                        actual_incguard_macro,
                        tmp[1]
                    )
                    append_warning(warnings, file_info, msg)
                    state = ST_FRONT_ERR
                    continue
                
                #  Now we finished the front part check.
                state = ST_FRONT_OK
                continue
        elif state == ST_FRONT_ERR or state == ST_FRONT_OK:
            break
        else:
            raise Exception("Illegal state.")
    
    #  Check the existence of "#pragma once".
    if use_pragma_once:
        if not found_pragma_once:
            append_warning(warnings, file_info, "No \"#pragma once\" can be found.")
    
    #  Check the include guard macro.
    if actual_incguard_macro is not None and actual_incguard_macro != incguard_macro:
        msg = "Expected include guard macro is \"%s\" (not \"%s\")." % (
            incguard_macro,
            actual_incguard_macro
        )
        append_warning(warnings, file_info, msg)
    
    #  Stop if we failed to process the front part.
    if state != ST_FRONT_OK:
        return
    
    #
    #  Now check the tail part of the header file, the file must end with "#endif" line.
    #
    
    state = ST_FRONT_WAIT_HASHTAG
    cursor = len(file_lines) - 1
    current_line = None
    
    lineno_endif = -1
    
    while True:
        if state == ST_TAIL_WAIT_HASHTAG:
            if cursor < 0:
                append_warning(warnings, file_info, "No \"#endif\" can be found.")
                state = ST_TAIL_ERR
                continue
            current_line = file_lines[cursor].lstrip()
            cursor -= 1
            if len(current_line) != 0:
                if current_line.startswith("#"):
                    state = ST_TAIL_HANDLE_HASHTAG
                else:
                    append_warning(warnings, file_info, "The file must end with a \"#endif\" line.")
                    state = ST_TAIL_ERR
                continue
        elif state == ST_TAIL_HANDLE_HASHTAG:
            tmp = RE_ENDIF.match(current_line)
            if tmp is None:
                append_warning(warnings, file_info, "The file must end with a \"#endif\" line.")
                state = ST_TAIL_ERR
                continue
            
            lineno_endif = cursor + 1
            
            #  OK.
            state = ST_TAIL_OK
        elif state == ST_TAIL_ERR or state == ST_TAIL_OK:
            break
        else:
            raise Exception("Illegal state.")

    if auto_fix:
        if lineno_pragma_once >= 0:
            file_lines[lineno_pragma_once] = "#pragma once"
        if lineno_ifndef >= 0:
            file_lines[lineno_ifndef] = "#ifndef " + incguard_macro
        if lineno_define >= 0:
            file_lines[lineno_define] = "#define " + incguard_macro
        if lineno_endif >= 0:
            file_lines[lineno_endif] = "#endif  //  " + incguard_macro
        
        #  Next procedure must be the last one of the fixing procedures.
        if use_pragma_once and lineno_pragma_once < 0:
            if lineno_ifndef >= 0:
                #  Insert the "#pragma once" before the "#ifndef".
                file_lines.insert(lineno_ifndef, "")
                file_lines.insert(lineno_ifndef, "#pragma once")
        
        file_newcontent = "\n".join(file_lines)
        if file_newcontent != file_content:
            fp = open(file_path, "w", encoding=file_encoding)
            fp.write(file_newcontent)
            fp.close()
            print("fix " + file_rel)


def main():
    #  Read the configuration file.
    fp = open(CONFIG_PATH, "r", encoding="utf-8")
    config = json.loads(fp.read())
    fp.close()
    
    #  Get options from the configuration file.
    opts = config["options"]
    
    use_pragma_once = opts["use_pragma_once"] if ("use_pragma_once" in opts) else False
    use_google_style = opts["use_google_style"] if ("use_google_style" in opts) else False
    auto_fix = opts["auto_fix"] if ("auto_fix" in opts) else False
    
    
    #  Get the skipped file list.
    skip_list = []
    for skip_regexp in config["skip"]:
        skip_list.append(re.compile(skip_regexp))
    
    #  Enumerate all header files.
    hdr_list = find_header_files(SRC_DIR, skip_list=skip_list)
    
    #  Scan all header files.
    warnings = []
    for file_info in hdr_list:
        check_header_file(
            file_info, 
            use_google_style=use_google_style, 
            use_pragma_once=use_pragma_once, 
            warnings=warnings, 
            auto_fix=auto_fix
        )
    
    #  Print all warnings.
    for i in range(0, len(warnings)):
        warning = warnings[i]
        print("[%d] %s: %s" % (
            i + 1,
            warning["file"]["rel"],
            warning["message"]
        ))
    
    if len(warnings) == 0:
        print("Everything OK!")
    else:
        print("Total %d warnings." % len(warnings))


if __name__ == "__main__":
    main()

