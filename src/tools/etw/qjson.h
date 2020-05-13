/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This is a helper file for writing qlog json data.

--*/

typedef struct QJSON {
    HANDLE File;
    BOOLEAN NeedsComma;
} QJSON;

inline BOOLEAN QjOpen(_Inout_ QJSON* Qj, _In_z_ const char* FileName)
{
    if ((Qj->File = fopen(FileName, "w")) == NULL) {
        return FALSE;
    }
    fprintf(Qj->File, "{");
    Qj->NeedsComma = FALSE;
    return TRUE;
}

inline void QjClose(_Inout_ QJSON* Qj)
{
    fprintf(Qj->File, "}");
    fclose(Qj->File);
    Qj->File = NULL;
}

inline void QjObjectStart(_In_ QJSON* Qj, _In_z_ const char* Name)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "\"%s\":{", Name);
    Qj->NeedsComma = FALSE;
}

inline void QjObjectEnd(_In_ QJSON* Qj)
{
    fprintf(Qj->File, "}");
    Qj->NeedsComma = TRUE;
}

inline void QjWriteString(_In_ QJSON* Qj, _In_z_ const char* Name, _In_z_ const char* Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    if (Value == NULL) {
        fprintf(Qj->File, "\"%s\":null", Name);
    } else {
        fprintf(Qj->File, "\"%s\":\"%s\"", Name, Value);
    }
    Qj->NeedsComma = TRUE;
}

inline void QjWriteStringInt(_In_ QJSON* Qj, _In_z_ const char* Name, _In_ UINT64 Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "\"%s\":\"%llu\"", Name, Value);
    Qj->NeedsComma = TRUE;
}

inline void QjWriteInt(_In_ QJSON* Qj, _In_z_ const char* Name, _In_ UINT64 Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "\"%s\":%llu", Name, Value);
    Qj->NeedsComma = TRUE;
}

inline void QjWriteBool(_In_ QJSON* Qj, _In_z_ const char* Name, _In_ BOOLEAN Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "\"%s\":%s", Name, Value ? "true" : "false");
    Qj->NeedsComma = TRUE;
}

inline void QjArrayStart(_In_ QJSON* Qj, _In_z_ const char* Name)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "\"%s\":[", Name);
    Qj->NeedsComma = FALSE;
}

inline void QjArrayEnd(_In_ QJSON* Qj)
{
    fprintf(Qj->File, "]");
    Qj->NeedsComma = TRUE;
}

inline void QjArrayArrayStart(_In_ QJSON* Qj)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "[");
    Qj->NeedsComma = FALSE;
}

inline void QjArrayObjectStart(_In_ QJSON* Qj)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "{");
    Qj->NeedsComma = FALSE;
}

inline void QjArrayWriteString(_In_ QJSON* Qj, _In_z_ const char* Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    if (Value == NULL) {
        fprintf(Qj->File, "null");
    } else {
        fprintf(Qj->File, "\"%s\"", Value);
    }
    Qj->NeedsComma = TRUE;
}

inline void QjArrayWriteInt(_In_ QJSON* Qj, _In_ UINT64 Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "%llu", Value);
    Qj->NeedsComma = TRUE;
}

inline void QjArrayWriteBool(_In_ QJSON* Qj, _In_ BOOLEAN Value)
{
    if (Qj->NeedsComma) {
        fprintf(Qj->File, ",");
    }
    fprintf(Qj->File, "%s", Value ? "true" : "false");
    Qj->NeedsComma = TRUE;
}
