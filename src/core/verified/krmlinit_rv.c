#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "verified_support.h"

/* ---- Vector operations for Pulse_Lib_RangeVec_range ---- */
/* Ghost parameters (erased #s, #cap) are passed as void* null pointers */

vec_t *Pulse_Lib_Vector_create(range_t def, size_t n) {
    vec_t *v = (vec_t *)malloc(sizeof(vec_t));
    v->arr = (range_t *)malloc(n * sizeof(range_t));
    for (size_t i = 0; i < n; i++) v->arr[i] = def;
    v->sz = n;
    v->cap = n;
    v->default_val = def;
    return v;
}

void Pulse_Lib_Vector_free(vec_t *v, void *_s, void *_cap) {
    free(v->arr);
    free(v);
}

range_t Pulse_Lib_Vector_at(vec_t *v, size_t i, void *_s, void *_cap) {
    return v->arr[i];
}

void Pulse_Lib_Vector_set(vec_t *v, size_t i, range_t x, void *_s, void *_cap) {
    v->arr[i] = x;
}

size_t Pulse_Lib_Vector_size(vec_t *v, void *_s, void *_cap) {
    return v->sz;
}

void Pulse_Lib_Vector_push_back(vec_t *v, range_t x, void *_s, void *_cap) {
    if (v->sz >= v->cap) {
        size_t new_cap = v->cap == 0 ? 1 : v->cap * 2;
        range_t *new_arr = (range_t *)malloc(new_cap * sizeof(range_t));
        if (v->sz > 0) memcpy(new_arr, v->arr, v->sz * sizeof(range_t));
        free(v->arr);
        v->arr = new_arr;
        v->cap = new_cap;
    }
    v->arr[v->sz++] = x;
}

range_t Pulse_Lib_Vector_pop_back(vec_t *v, void *_s, void *_cap) {
    return v->arr[--v->sz];
}
