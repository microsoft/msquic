/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Latency math helpers.

--*/

#pragma once

//
// Forward declaration because of include issues with math.h
//
extern "C" {
    double sqrt(double value);
}

struct Statistics {
    double Mean {0};
    double Variance {0};
    double StandardDeviation {0};
    double StandardError {0};
    uint32_t Min {0};
    uint32_t Max {0};
};

struct Percentiles {
    double P50 {0};
    double P90 {0};
    double P99 {0};
    double P99p9 {0};
    double P99p99 {0};
    double P99p999 {0};
    double P99p9999 {0};
};

#ifdef _KERNEL_MODE
__declspec(noinline)
#endif
static
double
ComputeVariance(
    _In_reads_(Length) uint32_t* Measurements,
    _In_ size_t Length,
    _In_ double Mean
    )
{
    if (Length <= 1) {
        return 0;
    }
    double Variance = 0;
    for (size_t i = 0; i < Length; i++) {
        uint32_t Value = Measurements[i];
        Variance += (Value - Mean) * (Value - Mean) / (Length - 1);
    }
    return Variance;
}

#ifdef _KERNEL_MODE
__declspec(noinline)
#endif
static
void
GetStatistics(
    _In_reads_(DataLength) uint32_t* Data,
    _In_ size_t DataLength,
    _Out_ Statistics* AllStatistics,
    _Out_ Percentiles* PercentileStats
    )
{
    if (DataLength == 0) {
        return;
    }

    uint64_t Sum = 0;
    uint32_t Min = 0xFFFFFFFF;
    uint32_t Max = 0;
    for (size_t i = 0; i < DataLength; i++) {
        uint32_t Value = Data[i];
        Sum += Value;
        if (Value > Max) {
            Max = Value;
        }
        if (Value < Min) {
            Min = Value;
        }
    }
    double Mean = Sum / (double)DataLength;
    double Variance =
        ComputeVariance(
            Data,
            DataLength,
            Mean);
    double StandardDeviation = sqrt(Variance);
    double StandardError = StandardDeviation / sqrt((double)DataLength);
    *AllStatistics = Statistics {
        Mean,
        Variance,
        StandardDeviation,
        StandardError,
        Min,
        Max
    };

#ifdef _WIN32
    qsort_s(
        Data,
        DataLength,
        sizeof(uint32_t),
        [](void*, const void* Left, const void* Right) -> int {
            return *(const uint32_t*)Left - *(const uint32_t*)Right;
        },
        nullptr);
#else
    qsort(
        Data,
        DataLength,
        sizeof(uint32_t),
        [](const void* Left, const void* Right) -> int {
            return *(const uint32_t*)Left - *(const uint32_t*)Right;
        });
#endif

    uint32_t PercentileIndex = (uint32_t)(DataLength * 0.5);
    PercentileStats->P50 = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.9);
    PercentileStats->P90 = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.99);
    PercentileStats->P99 = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.999);
    PercentileStats->P99p9 = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.9999);
    PercentileStats->P99p99 = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.99999);
    PercentileStats->P99p999 = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.999999);
    PercentileStats->P99p9999 = Data[PercentileIndex];
}
