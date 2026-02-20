/*
 * Minimal implementations of Prims and FStar operations
 * needed by the extracted CircularBuffer code.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

typedef int32_t krml_checked_int_t;

/* Prims integer operations (krml_checked_int_t = int32_t) */
krml_checked_int_t Prims_op_Addition(krml_checked_int_t x, krml_checked_int_t y) { return x + y; }
krml_checked_int_t Prims_op_Subtraction(krml_checked_int_t x, krml_checked_int_t y) { return x - y; }
krml_checked_int_t Prims_op_Multiply(krml_checked_int_t x, krml_checked_int_t y) { return x * y; }
krml_checked_int_t Prims_op_Division(krml_checked_int_t x, krml_checked_int_t y) { return x / y; }
krml_checked_int_t Prims_op_Modulus(krml_checked_int_t x, krml_checked_int_t y) { return x % y; }
krml_checked_int_t Prims_op_Minus(krml_checked_int_t x) { return -x; }

bool Prims_op_LessThan(krml_checked_int_t x, krml_checked_int_t y) { return x < y; }
bool Prims_op_LessThanOrEqual(krml_checked_int_t x, krml_checked_int_t y) { return x <= y; }
bool Prims_op_GreaterThan(krml_checked_int_t x, krml_checked_int_t y) { return x > y; }
bool Prims_op_GreaterThanOrEqual(krml_checked_int_t x, krml_checked_int_t y) { return x >= y; }

/* FStar.Math.Lib.abs */
krml_checked_int_t FStar_Math_Lib_abs(krml_checked_int_t x) { return x < 0 ? -x : x; }

/* cb_max_length = pow2_63 (assume val in CircularBuffer.Spec) */
krml_checked_int_t Pulse_Lib_CircularBuffer_Spec_cb_max_length = (krml_checked_int_t)0x8000000000000000LL;
