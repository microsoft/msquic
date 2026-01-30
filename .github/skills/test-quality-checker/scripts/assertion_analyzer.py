#!/usr/bin/env python3
"""
Assertion Extractor
===================

PURPOSE:
    Extracts assertions from test files using deterministic pattern matching.
    Provides raw data for an agent to analyze and make quality judgments.

WHAT THIS SCRIPT DOES:
    1. Detects programming language from file extension
    2. Locates test function boundaries (if test name provided)
    3. Extracts all assertions using regex patterns for known frameworks
    4. Categorizes assertions by type (equality, null_check, exception, etc.)
    5. Extracts operands from assertions where possible
    6. Provides raw test code lines for additional analysis

WHAT THIS SCRIPT DOES NOT DO:
    - Does NOT score or rate assertion quality
    - Does NOT determine if assertions are "good" or "bad"
    - Does NOT judge assertion specificity or completeness
    - Does NOT decide if assertions are sufficient for the code being tested
    - Does NOT analyze assertion relevance to the target function
    - Does NOT identify missing assertions
    - Does NOT make any qualitative judgments

OUTPUT:
    JSON containing:
    - List of assertions with line numbers, code, type, and operands
    - Boolean flags for assertion type presence (for convenience, not judgment)
    - Raw code lines so the agent can extract additional patterns

SUPPORTED FRAMEWORKS:
    C: assert, Check (ck_assert_*), CUnit (CU_ASSERT_*), Unity (TEST_ASSERT_*), cmocka
    C++: Google Test (EXPECT_*/ASSERT_*), Catch2 (REQUIRE/CHECK), Boost.Test
    Python: assert, unittest (self.assert*), pytest
    JavaScript: Jest (expect), Chai (expect/assert)
    Java: JUnit (assert*), AssertJ, Hamcrest

USAGE:
    python assertion_analyzer.py extract <test_file> [--test <test_name>] [--json <output.json>]
"""

import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Assertion:
    """
    Represents a single assertion extracted from test code.
    
    Attributes:
        line_number: 1-based line number in the file
        code: The full line of code containing the assertion
        assertion_type: Category of assertion (equality, null_check, boolean, exception, etc.)
                       This is a factual categorization, not a quality judgment.
        operands: List of operands/arguments extracted from the assertion pattern
    """
    line_number: int
    code: str
    assertion_type: str
    operands: List[str] = field(default_factory=list)


@dataclass
class AssertionInfo:
    """
    Complete extraction results from a test file.
    
    Attributes:
        test_file: Path to the analyzed file
        test_name: Name of specific test function (if provided)
        language: Detected programming language
        start_line: First line of the test (1-based)
        end_line: Last line of the test
        total_assertions: Count of assertions found
        assertions: List of Assertion objects
        has_exception_handling: True if any exception-type assertions found
        has_null_checks: True if any null-check assertions found
        has_equality_checks: True if any equality assertions found
        has_boundary_checks: True if any comparison assertions found
        raw_code: The complete test code as a string
        raw_lines: List of {number, content} for each line - for agent's additional analysis
    
    Note: The has_* flags are convenience summaries, NOT quality indicators.
          The agent must determine if these are sufficient or appropriate.
    """
    test_file: str
    test_name: Optional[str]
    language: str
    start_line: int
    end_line: int
    total_assertions: int
    assertions: List[Assertion]
    has_exception_handling: bool
    has_null_checks: bool
    has_equality_checks: bool
    has_boundary_checks: bool
    raw_code: str
    raw_lines: List[Dict]


class AssertionExtractor:
    """
    Extracts assertions from test code using pattern matching.
    
    This class performs DETERMINISTIC extraction only:
    - Pattern matching against known assertion frameworks
    - No heuristics or judgment calls
    - No quality assessment
    
    The agent using this output is responsible for:
    - Judging assertion quality (specificity, completeness, relevance)
    - Identifying missing assertions
    - Evaluating if assertions are appropriate for the code under test
    - Any qualitative analysis
    """
    
    # ==========================================================================
    # ASSERTION PATTERNS
    # ==========================================================================
    # Each pattern tuple contains: (regex_pattern, framework_name, assertion_type)
    # 
    # assertion_type categories:
    #   - 'generic': General boolean assertion
    #   - 'equality': Checks two values are equal
    #   - 'inequality': Checks two values are not equal
    #   - 'null_check': Checks for null/None/nil
    #   - 'boolean': Checks true/false
    #   - 'comparison': Checks <, >, <=, >= relationships
    #   - 'exception': Checks for thrown exceptions
    #   - 'contains': Checks if collection/string contains element
    #   - 'type_check': Checks type/instanceof
    #
    # These categories are FACTUAL classifications, not quality judgments.
    # ==========================================================================
    
    ASSERTION_PATTERNS = {
        'c': [
            # Standard C assert
            (r'\bassert\s*\(\s*(.+)\s*\)', 'assert', 'generic'),
            # Check framework
            (r'\bck_assert\s*\(\s*(.+)\s*\)', 'check', 'generic'),
            (r'\bck_assert_int_eq\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_eq', 'equality'),
            (r'\bck_assert_int_ne\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_ne', 'inequality'),
            (r'\bck_assert_int_lt\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_lt', 'comparison'),
            (r'\bck_assert_int_le\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_le', 'comparison'),
            (r'\bck_assert_int_gt\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_gt', 'comparison'),
            (r'\bck_assert_int_ge\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_ge', 'comparison'),
            (r'\bck_assert_uint_eq\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_eq', 'equality'),
            (r'\bck_assert_uint_ne\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_ne', 'inequality'),
            (r'\bck_assert_ptr_null\s*\(\s*(.+)\s*\)', 'check_null', 'null_check'),
            (r'\bck_assert_ptr_nonnull\s*\(\s*(.+)\s*\)', 'check_nonnull', 'null_check'),
            (r'\bck_assert_ptr_eq\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_ptr_eq', 'equality'),
            (r'\bck_assert_ptr_ne\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_ptr_ne', 'inequality'),
            (r'\bck_assert_str_eq\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_str_eq', 'equality'),
            (r'\bck_assert_str_ne\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'check_str_ne', 'inequality'),
            (r'\bck_assert_mem_eq\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'check_mem_eq', 'equality'),
            (r'\bck_assert_float_eq\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'check_float_eq', 'equality'),
            (r'\bck_assert_double_eq\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'check_double_eq', 'equality'),
            # CUnit
            (r'\bCU_ASSERT\s*\(\s*(.+)\s*\)', 'cunit', 'generic'),
            (r'\bCU_ASSERT_TRUE\s*\(\s*(.+)\s*\)', 'cunit_true', 'boolean'),
            (r'\bCU_ASSERT_FALSE\s*\(\s*(.+)\s*\)', 'cunit_false', 'boolean'),
            (r'\bCU_ASSERT_EQUAL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cunit_eq', 'equality'),
            (r'\bCU_ASSERT_NOT_EQUAL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cunit_ne', 'inequality'),
            (r'\bCU_ASSERT_PTR_NULL\s*\(\s*(.+)\s*\)', 'cunit_null', 'null_check'),
            (r'\bCU_ASSERT_PTR_NOT_NULL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cunit_notnull', 'null_check'),
            (r'\bCU_ASSERT_STRING_EQUAL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cunit_str_eq', 'equality'),
            # Unity
            (r'\bTEST_ASSERT\s*\(\s*(.+)\s*\)', 'unity', 'generic'),
            (r'\bTEST_ASSERT_TRUE\s*\(\s*(.+)\s*\)', 'unity_true', 'boolean'),
            (r'\bTEST_ASSERT_FALSE\s*\(\s*(.+)\s*\)', 'unity_false', 'boolean'),
            (r'\bTEST_ASSERT_NULL\s*\(\s*(.+)\s*\)', 'unity_null', 'null_check'),
            (r'\bTEST_ASSERT_NOT_NULL\s*\(\s*(.+)\s*\)', 'unity_notnull', 'null_check'),
            (r'\bTEST_ASSERT_EQUAL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unity_eq', 'equality'),
            (r'\bTEST_ASSERT_EQUAL_INT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unity_eq_int', 'equality'),
            (r'\bTEST_ASSERT_EQUAL_STRING\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unity_eq_str', 'equality'),
            (r'\bTEST_ASSERT_EQUAL_MEMORY\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'unity_eq_mem', 'equality'),
            (r'\bTEST_ASSERT_GREATER_THAN\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unity_gt', 'comparison'),
            (r'\bTEST_ASSERT_LESS_THAN\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unity_lt', 'comparison'),
            # cmocka
            (r'\bassert_true\s*\(\s*(.+)\s*\)', 'cmocka_true', 'boolean'),
            (r'\bassert_false\s*\(\s*(.+)\s*\)', 'cmocka_false', 'boolean'),
            (r'\bassert_null\s*\(\s*(.+)\s*\)', 'cmocka_null', 'null_check'),
            (r'\bassert_non_null\s*\(\s*(.+)\s*\)', 'cmocka_notnull', 'null_check'),
            (r'\bassert_int_equal\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_eq', 'equality'),
            (r'\bassert_int_not_equal\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_ne', 'inequality'),
            (r'\bassert_string_equal\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_str_eq', 'equality'),
            (r'\bassert_memory_equal\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_mem_eq', 'equality'),
            (r'\bassert_ptr_equal\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_ptr_eq', 'equality'),
            (r'\bassert_ptr_not_equal\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_ptr_ne', 'inequality'),
            (r'\bassert_in_range\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_range', 'comparison'),
            (r'\bassert_not_in_range\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'cmocka_not_range', 'comparison'),
        ],
        'cpp': [
            # Google Test - EXPECT variants
            (r'\bEXPECT_EQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_eq', 'equality'),
            (r'\bEXPECT_NE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_ne', 'inequality'),
            (r'\bEXPECT_LT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_lt', 'comparison'),
            (r'\bEXPECT_LE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_le', 'comparison'),
            (r'\bEXPECT_GT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_gt', 'comparison'),
            (r'\bEXPECT_GE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_ge', 'comparison'),
            (r'\bEXPECT_TRUE\s*\(\s*(.+)\s*\)', 'gtest_true', 'boolean'),
            (r'\bEXPECT_FALSE\s*\(\s*(.+)\s*\)', 'gtest_false', 'boolean'),
            (r'\bEXPECT_NULL\s*\(\s*(.+)\s*\)', 'gtest_null', 'null_check'),
            (r'\bEXPECT_STREQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_streq', 'equality'),
            (r'\bEXPECT_STRNE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_strne', 'inequality'),
            (r'\bEXPECT_STRCASEEQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_strcaseeq', 'equality'),
            (r'\bEXPECT_STRCASENE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_strcasene', 'inequality'),
            (r'\bEXPECT_FLOAT_EQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_float_eq', 'equality'),
            (r'\bEXPECT_DOUBLE_EQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_double_eq', 'equality'),
            (r'\bEXPECT_NEAR\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_near', 'equality'),
            (r'\bEXPECT_THROW\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_throw', 'exception'),
            (r'\bEXPECT_NO_THROW\s*\(\s*(.+)\s*\)', 'gtest_no_throw', 'exception'),
            (r'\bEXPECT_ANY_THROW\s*\(\s*(.+)\s*\)', 'gtest_any_throw', 'exception'),
            (r'\bEXPECT_THAT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_that', 'generic'),
            # Google Test - ASSERT variants
            (r'\bASSERT_EQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_eq', 'equality'),
            (r'\bASSERT_NE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_ne', 'inequality'),
            (r'\bASSERT_LT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_lt', 'comparison'),
            (r'\bASSERT_LE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_le', 'comparison'),
            (r'\bASSERT_GT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_gt', 'comparison'),
            (r'\bASSERT_GE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_ge', 'comparison'),
            (r'\bASSERT_TRUE\s*\(\s*(.+)\s*\)', 'gtest_true', 'boolean'),
            (r'\bASSERT_FALSE\s*\(\s*(.+)\s*\)', 'gtest_false', 'boolean'),
            (r'\bASSERT_NULL\s*\(\s*(.+)\s*\)', 'gtest_null', 'null_check'),
            (r'\bASSERT_STREQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_streq', 'equality'),
            (r'\bASSERT_STRNE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_strne', 'inequality'),
            (r'\bASSERT_FLOAT_EQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_float_eq', 'equality'),
            (r'\bASSERT_DOUBLE_EQ\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_double_eq', 'equality'),
            (r'\bASSERT_NEAR\s*\(\s*(.+)\s*,\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_near', 'equality'),
            (r'\bASSERT_THROW\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_throw', 'exception'),
            (r'\bASSERT_NO_THROW\s*\(\s*(.+)\s*\)', 'gtest_no_throw', 'exception'),
            (r'\bASSERT_THAT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'gtest_that', 'generic'),
            # Catch2
            (r'\bREQUIRE\s*\(\s*(.+)\s*\)', 'catch2', 'generic'),
            (r'\bREQUIRE_FALSE\s*\(\s*(.+)\s*\)', 'catch2_false', 'boolean'),
            (r'\bREQUIRE_THROWS\s*\(\s*(.+)\s*\)', 'catch2_throws', 'exception'),
            (r'\bREQUIRE_THROWS_AS\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'catch2_throws_as', 'exception'),
            (r'\bREQUIRE_THROWS_WITH\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'catch2_throws_with', 'exception'),
            (r'\bREQUIRE_NOTHROW\s*\(\s*(.+)\s*\)', 'catch2_nothrow', 'exception'),
            (r'\bCHECK\s*\(\s*(.+)\s*\)', 'catch2', 'generic'),
            (r'\bCHECK_FALSE\s*\(\s*(.+)\s*\)', 'catch2_false', 'boolean'),
            (r'\bCHECK_THROWS\s*\(\s*(.+)\s*\)', 'catch2_throws', 'exception'),
            (r'\bCHECK_THROWS_AS\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'catch2_throws_as', 'exception'),
            (r'\bCHECK_NOTHROW\s*\(\s*(.+)\s*\)', 'catch2_nothrow', 'exception'),
            (r'\bCHECK_THAT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'catch2_that', 'generic'),
            # Boost.Test
            (r'\bBOOST_CHECK\s*\(\s*(.+)\s*\)', 'boost_check', 'generic'),
            (r'\bBOOST_CHECK_EQUAL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_eq', 'equality'),
            (r'\bBOOST_CHECK_NE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_ne', 'inequality'),
            (r'\bBOOST_CHECK_LT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_lt', 'comparison'),
            (r'\bBOOST_CHECK_LE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_le', 'comparison'),
            (r'\bBOOST_CHECK_GT\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_gt', 'comparison'),
            (r'\bBOOST_CHECK_GE\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_ge', 'comparison'),
            (r'\bBOOST_CHECK_THROW\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_throw', 'exception'),
            (r'\bBOOST_CHECK_NO_THROW\s*\(\s*(.+)\s*\)', 'boost_no_throw', 'exception'),
            (r'\bBOOST_REQUIRE\s*\(\s*(.+)\s*\)', 'boost_require', 'generic'),
            (r'\bBOOST_REQUIRE_EQUAL\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'boost_req_eq', 'equality'),
        ],
        'python': [
            # Basic assert
            (r'\bassert\s+(.+?)(?:\s*,\s*["\'].+["\'])?\s*$', 'assert', 'generic'),
            # unittest
            (r'\bself\.assertEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_eq', 'equality'),
            (r'\bself\.assertNotEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_ne', 'inequality'),
            (r'\bself\.assertTrue\s*\(\s*(.+)\s*\)', 'unittest_true', 'boolean'),
            (r'\bself\.assertFalse\s*\(\s*(.+)\s*\)', 'unittest_false', 'boolean'),
            (r'\bself\.assertIsNone\s*\(\s*(.+)\s*\)', 'unittest_none', 'null_check'),
            (r'\bself\.assertIsNotNone\s*\(\s*(.+)\s*\)', 'unittest_notnone', 'null_check'),
            (r'\bself\.assertIs\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_is', 'equality'),
            (r'\bself\.assertIsNot\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_isnot', 'inequality'),
            (r'\bself\.assertIn\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_in', 'contains'),
            (r'\bself\.assertNotIn\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_notin', 'contains'),
            (r'\bself\.assertIsInstance\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_isinstance', 'type_check'),
            (r'\bself\.assertNotIsInstance\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_notisinstance', 'type_check'),
            (r'\bself\.assertGreater\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_gt', 'comparison'),
            (r'\bself\.assertGreaterEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_ge', 'comparison'),
            (r'\bself\.assertLess\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_lt', 'comparison'),
            (r'\bself\.assertLessEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_le', 'comparison'),
            (r'\bself\.assertAlmostEqual\s*\(\s*(.+)\s*,\s*(.+)', 'unittest_almost_eq', 'equality'),
            (r'\bself\.assertNotAlmostEqual\s*\(\s*(.+)\s*,\s*(.+)', 'unittest_not_almost_eq', 'inequality'),
            (r'\bself\.assertRegex\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_regex', 'contains'),
            (r'\bself\.assertNotRegex\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_notregex', 'contains'),
            (r'\bself\.assertCountEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_counteq', 'equality'),
            (r'\bself\.assertRaises\s*\(\s*(.+)\s*\)', 'unittest_raises', 'exception'),
            (r'\bself\.assertRaisesRegex\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'unittest_raises_regex', 'exception'),
            (r'\bself\.assertWarns\s*\(\s*(.+)\s*\)', 'unittest_warns', 'exception'),
            (r'\bself\.assertLogs\s*\(\s*(.+)\s*\)', 'unittest_logs', 'generic'),
            # pytest
            (r'\bpytest\.raises\s*\(\s*(.+)\s*\)', 'pytest_raises', 'exception'),
            (r'\bpytest\.warns\s*\(\s*(.+)\s*\)', 'pytest_warns', 'exception'),
            (r'\bpytest\.approx\s*\(\s*(.+)\s*\)', 'pytest_approx', 'equality'),
        ],
        'javascript': [
            # Jest
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBe\s*\(\s*(.+)\s*\)', 'jest_be', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toEqual\s*\(\s*(.+)\s*\)', 'jest_equal', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toStrictEqual\s*\(\s*(.+)\s*\)', 'jest_strict_equal', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.not\.toBe\s*\(\s*(.+)\s*\)', 'jest_not_be', 'inequality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.not\.toEqual\s*\(\s*(.+)\s*\)', 'jest_not_equal', 'inequality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeTruthy\s*\(\s*\)', 'jest_truthy', 'boolean'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeFalsy\s*\(\s*\)', 'jest_falsy', 'boolean'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeNull\s*\(\s*\)', 'jest_null', 'null_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeUndefined\s*\(\s*\)', 'jest_undefined', 'null_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeDefined\s*\(\s*\)', 'jest_defined', 'null_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeNaN\s*\(\s*\)', 'jest_nan', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeGreaterThan\s*\(\s*(.+)\s*\)', 'jest_gt', 'comparison'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeGreaterThanOrEqual\s*\(\s*(.+)\s*\)', 'jest_ge', 'comparison'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeLessThan\s*\(\s*(.+)\s*\)', 'jest_lt', 'comparison'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeLessThanOrEqual\s*\(\s*(.+)\s*\)', 'jest_le', 'comparison'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeCloseTo\s*\(\s*(.+)', 'jest_close', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toMatch\s*\(\s*(.+)\s*\)', 'jest_match', 'contains'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toContain\s*\(\s*(.+)\s*\)', 'jest_contain', 'contains'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toContainEqual\s*\(\s*(.+)\s*\)', 'jest_contain_eq', 'contains'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toHaveLength\s*\(\s*(.+)\s*\)', 'jest_length', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toHaveProperty\s*\(\s*(.+)', 'jest_property', 'contains'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toBeInstanceOf\s*\(\s*(.+)\s*\)', 'jest_instanceof', 'type_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toThrow\s*\(', 'jest_throw', 'exception'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.toThrowError\s*\(', 'jest_throw_error', 'exception'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.rejects\.toThrow\s*\(', 'jest_rejects', 'exception'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.resolves\.toBe\s*\(\s*(.+)\s*\)', 'jest_resolves', 'equality'),
            # Chai - expect style
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.equal\s*\(\s*(.+)\s*\)', 'chai_equal', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.deep\.equal\s*\(\s*(.+)\s*\)', 'chai_deep_equal', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.not\.equal\s*\(\s*(.+)\s*\)', 'chai_not_equal', 'inequality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.be\.true', 'chai_true', 'boolean'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.be\.false', 'chai_false', 'boolean'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.be\.null', 'chai_null', 'null_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.be\.undefined', 'chai_undefined', 'null_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.be\.a\s*\(\s*(.+)\s*\)', 'chai_type', 'type_check'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.include\s*\(\s*(.+)\s*\)', 'chai_include', 'contains'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.have\.lengthOf\s*\(\s*(.+)\s*\)', 'chai_length', 'equality'),
            (r'\bexpect\s*\(\s*(.+)\s*\)\.to\.throw\s*\(', 'chai_throw', 'exception'),
            # Chai - assert style
            (r'\bassert\.equal\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'chai_assert_eq', 'equality'),
            (r'\bassert\.strictEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'chai_assert_strict', 'equality'),
            (r'\bassert\.deepEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'chai_assert_deep', 'equality'),
            (r'\bassert\.notEqual\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'chai_assert_ne', 'inequality'),
            (r'\bassert\.isTrue\s*\(\s*(.+)\s*\)', 'chai_assert_true', 'boolean'),
            (r'\bassert\.isFalse\s*\(\s*(.+)\s*\)', 'chai_assert_false', 'boolean'),
            (r'\bassert\.isNull\s*\(\s*(.+)\s*\)', 'chai_assert_null', 'null_check'),
            (r'\bassert\.isNotNull\s*\(\s*(.+)\s*\)', 'chai_assert_notnull', 'null_check'),
            (r'\bassert\.throws\s*\(\s*(.+)\s*\)', 'chai_assert_throws', 'exception'),
        ],
        'java': [
            # JUnit 5
            (r'\bassertEquals\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_eq', 'equality'),
            (r'\bassertNotEquals\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_ne', 'inequality'),
            (r'\bassertTrue\s*\(\s*(.+)\s*\)', 'junit_true', 'boolean'),
            (r'\bassertFalse\s*\(\s*(.+)\s*\)', 'junit_false', 'boolean'),
            (r'\bassertNull\s*\(\s*(.+)\s*\)', 'junit_null', 'null_check'),
            (r'\bassertNotNull\s*\(\s*(.+)\s*\)', 'junit_notnull', 'null_check'),
            (r'\bassertSame\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_same', 'equality'),
            (r'\bassertNotSame\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_notsame', 'inequality'),
            (r'\bassertArrayEquals\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_array_eq', 'equality'),
            (r'\bassertIterableEquals\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_iter_eq', 'equality'),
            (r'\bassertLinesMatch\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_lines', 'equality'),
            (r'\bassertThrows\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_throws', 'exception'),
            (r'\bassertThrowsExactly\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_throws_exact', 'exception'),
            (r'\bassertDoesNotThrow\s*\(\s*(.+)\s*\)', 'junit_no_throw', 'exception'),
            (r'\bassertTimeout\s*\(\s*(.+)\s*,\s*(.+)\s*\)', 'junit_timeout', 'generic'),
            (r'\bassertAll\s*\(\s*(.+)\s*\)', 'junit_all', 'generic'),
            # AssertJ
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isEqualTo\s*\(\s*(.+)\s*\)', 'assertj_eq', 'equality'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isNotEqualTo\s*\(\s*(.+)\s*\)', 'assertj_ne', 'inequality'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isTrue\s*\(\s*\)', 'assertj_true', 'boolean'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isFalse\s*\(\s*\)', 'assertj_false', 'boolean'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isNull\s*\(\s*\)', 'assertj_null', 'null_check'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isNotNull\s*\(\s*\)', 'assertj_notnull', 'null_check'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isGreaterThan\s*\(\s*(.+)\s*\)', 'assertj_gt', 'comparison'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isLessThan\s*\(\s*(.+)\s*\)', 'assertj_lt', 'comparison'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.contains\s*\(\s*(.+)\s*\)', 'assertj_contains', 'contains'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.hasSize\s*\(\s*(.+)\s*\)', 'assertj_size', 'equality'),
            (r'\bassertThat\s*\(\s*(.+)\s*\)\.isInstanceOf\s*\(\s*(.+)\s*\)', 'assertj_instanceof', 'type_check'),
            (r'\bassertThatThrownBy\s*\(\s*(.+)\s*\)', 'assertj_thrown', 'exception'),
            (r'\bassertThatCode\s*\(\s*(.+)\s*\)\.doesNotThrowAnyException', 'assertj_no_throw', 'exception'),
            # Hamcrest
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*is\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_is', 'equality'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*equalTo\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_eq', 'equality'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*not\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_not', 'inequality'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*nullValue\s*\(\s*\)\s*\)', 'hamcrest_null', 'null_check'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*notNullValue\s*\(\s*\)\s*\)', 'hamcrest_notnull', 'null_check'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*greaterThan\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_gt', 'comparison'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*lessThan\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_lt', 'comparison'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*containsString\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_contains', 'contains'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*hasItem\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_hasitem', 'contains'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*hasSize\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_size', 'equality'),
            (r'\bassertThat\s*\(\s*(.+)\s*,\s*instanceOf\s*\(\s*(.+)\s*\)\s*\)', 'hamcrest_instanceof', 'type_check'),
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
        self.assertions: List[Assertion] = []
        
    def _detect_language(self) -> str:
        """
        Detect programming language from file extension.
        
        This is a simple deterministic mapping - no heuristics.
        Returns 'c' as default for unknown extensions.
        """
        ext = self.test_file.suffix.lower()
        lang_map = {
            '.c': 'c', '.h': 'c',
            '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp',
            '.py': 'python',
            '.js': 'javascript', '.ts': 'javascript',
            '.java': 'java',
        }
        return lang_map.get(ext, 'c')
    
    def load_file(self):
        """Load the test file contents into memory."""
        with open(self.test_file, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
    
    def extract(self, test_name: Optional[str] = None) -> AssertionInfo:
        """
        Extract all assertions from the test file.
        
        This method:
        1. Loads the file
        2. Optionally finds specific test function boundaries
        3. Runs pattern matching to find assertions
        4. Collects raw code for agent's additional analysis
        
        Args:
            test_name: Optional name of specific test function to analyze.
                      If None, analyzes the entire file.
        
        Returns:
            AssertionInfo containing all extracted data plus raw code.
        
        Note: This method extracts DATA only. It does NOT:
            - Judge if assertions are good/bad
            - Determine if there are enough assertions
            - Evaluate assertion quality or relevance
        """
        self.load_file()
        
        # Find test boundaries - deterministic based on language patterns
        start_line, end_line = 0, len(self.lines)
        if test_name:
            start_line, end_line = self._find_test_boundaries(test_name)
        
        # Extract raw code and lines for agent's additional analysis
        # The agent may want to look for patterns we don't extract
        test_lines = self.lines[start_line:end_line]
        raw_code = ''.join(test_lines)
        raw_lines = [
            {"number": start_line + i + 1, "content": line.rstrip('\n\r')}
            for i, line in enumerate(test_lines)
        ]
        
        # Find assertions using pattern matching
        self._find_assertions(start_line, end_line)
        
        # Summarize assertion types present - these are FACTUAL flags, not quality judgments
        # The agent decides if these are sufficient or appropriate
        has_exception = any(a.assertion_type == 'exception' for a in self.assertions)
        has_null = any(a.assertion_type == 'null_check' for a in self.assertions)
        has_equality = any(a.assertion_type == 'equality' for a in self.assertions)
        has_boundary = any(a.assertion_type == 'comparison' for a in self.assertions)
        
        return AssertionInfo(
            test_file=str(self.test_file),
            test_name=test_name,
            language=self.language,
            start_line=start_line + 1,
            end_line=end_line,
            total_assertions=len(self.assertions),
            assertions=self.assertions,
            has_exception_handling=has_exception,
            has_null_checks=has_null,
            has_equality_checks=has_equality,
            has_boundary_checks=has_boundary,
            raw_code=raw_code,
            raw_lines=raw_lines
        )
    
    def _find_assertions(self, start_line: int, end_line: int):
        """
        Find all assertions in the specified line range using regex patterns.
        
        This is DETERMINISTIC pattern matching:
        - Only finds assertions that match known patterns
        - May miss custom assertion functions or macros
        - The agent should review raw_lines for additional assertions
        
        Args:
            start_line: First line to search (0-based)
            end_line: Last line to search (exclusive)
        """
        patterns = self.ASSERTION_PATTERNS.get(self.language, self.ASSERTION_PATTERNS['c'])
        
        for i in range(start_line, end_line):
            line = self.lines[i]
            stripped = line.strip()
            
            # Try each pattern until one matches
            for pattern, name, atype in patterns:
                match = re.search(pattern, stripped)
                if match:
                    operands = list(match.groups())
                    self.assertions.append(Assertion(
                        line_number=i + 1,
                        code=stripped,
                        assertion_type=atype,
                        operands=operands
                    ))
                    break  # Only match first pattern per line
    
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
            'c': [r'^(?:void\s+)?(' + re.escape(test_name) + r')\s*\('],
            'cpp': [r'TEST.*\(\s*\w+\s*,\s*' + re.escape(test_name) + r'\s*\)'],
            'python': [r'^def\s+' + re.escape(test_name) + r'\s*\('],
            'javascript': [r'(?:test|it)\s*\(\s*[\'"]' + re.escape(test_name) + r'[\'"]'],
            'java': [r'void\s+' + re.escape(test_name) + r'\s*\('],
        }
        
        patterns = test_patterns.get(self.language, test_patterns['c'])
        
        for i, line in enumerate(self.lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    end = self._find_function_end(i)
                    return (i, end)
        
        # Test not found - return entire file
        return (0, len(self.lines))
    
    def _find_function_end(self, start: int) -> int:
        """Find the end of a function"""
        if self.language == 'python':
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
    
    def export_json(self, output_file: str, test_name: Optional[str] = None):
        """Export extracted assertions to JSON"""
        info = self.extract(test_name)
        
        data = {
            "test_file": info.test_file,
            "test_name": info.test_name,
            "language": info.language,
            "start_line": info.start_line,
            "end_line": info.end_line,
            "total_assertions": info.total_assertions,
            "assertion_types_present": {
                "exception_handling": info.has_exception_handling,
                "null_checks": info.has_null_checks,
                "equality_checks": info.has_equality_checks,
                "boundary_checks": info.has_boundary_checks
            },
            "assertions": [
                {
                    "line": a.line_number,
                    "code": a.code,
                    "type": a.assertion_type,
                    "operands": a.operands
                }
                for a in info.assertions
            ],
            # Raw code for agent to extract additional information
            "raw_lines": info.raw_lines
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)


def main():
    if len(sys.argv) < 2:
        print("""
Assertion Extractor - Extract assertions from test files

Usage:
  python assertion_analyzer.py extract <test_file> [--test <test_name>] [--json <output.json>]

Commands:
  extract <test_file> [--test <test_name>] [--json <output.json>]
    Extract assertions from a test file

Examples:
  python assertion_analyzer.py extract test_main.c --json assertions.json
  python assertion_analyzer.py extract test_utils.py --test test_parse_config --json assertions.json
""")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'extract':
        if len(sys.argv) < 3:
            print("Usage: assertion_analyzer.py extract <test_file> [--test <test_name>] [--json output.json]")
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
        
        extractor = AssertionExtractor(test_file)
        info = extractor.extract(test_name)
        
        print(f"\n=== Assertions Extracted: {test_file} ===")
        if test_name:
            print(f"Test: {test_name}")
        print(f"Total assertions: {info.total_assertions}")
        print(f"\nAssertion types present:")
        print(f"  Exception handling: {info.has_exception_handling}")
        print(f"  Null checks: {info.has_null_checks}")
        print(f"  Equality checks: {info.has_equality_checks}")
        print(f"  Boundary checks: {info.has_boundary_checks}")
        
        print(f"\nAssertions:")
        for a in info.assertions:
            print(f"  Line {a.line_number}: [{a.assertion_type}] {a.code[:60]}...")
        
        if json_output:
            extractor.export_json(json_output, test_name)
            print(f"\nJSON exported to: {json_output}")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
