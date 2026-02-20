/*
 * verified_support.h
 *
 * Declarations for FStar runtime functions and Pulse.Lib.Vector stubs
 * needed by the extracted CircularBuffer code.
 */
#ifndef VERIFIED_SUPPORT_H
#define VERIFIED_SUPPORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "verified_recv_buffer.h"

/* FStar.SizeT.v is the identity on size_t (machine-word integers) */
static inline size_t FStar_SizeT_v(size_t x) { return x; }
static inline size_t FStar_SizeT_uint_to_t(size_t x) { return x; }

/* ---- Vector stubs (heap-allocated, replacing KaRaMeL VLAs) ---- */
/* Ghost parameters (#s, #cap) are passed as void* null pointers.   */

typedef Pulse_Lib_RangeVec_range range_t;
typedef Pulse_Lib_Vector_vector_internal__Pulse_Lib_RangeVec_range vec_t;

vec_t *Pulse_Lib_Vector_create(range_t def, size_t n);
void   Pulse_Lib_Vector_free(vec_t *v, void *_s, void *_cap);
range_t Pulse_Lib_Vector_at(vec_t *v, size_t i, void *_s, void *_cap);
void   Pulse_Lib_Vector_set(vec_t *v, size_t i, range_t x, void *_s, void *_cap);
size_t Pulse_Lib_Vector_size(vec_t *v, void *_s, void *_cap);
void   Pulse_Lib_Vector_push_back(vec_t *v, range_t x, void *_s, void *_cap);
range_t Pulse_Lib_Vector_pop_back(vec_t *v, void *_s, void *_cap);

#endif /* VERIFIED_SUPPORT_H */
