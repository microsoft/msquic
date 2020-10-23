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

#include <stdlib.h>

struct Statistics {
    double Mean {0};
    double Variance {0};
    double StandardDeviation {0};
    double StandardError {0};
    uint32_t Min {0};
    uint32_t Max {0};
};

struct Percentiles {
    double FiftiethPercentile {0};
    double NinetiethPercentile {0};
    double NintyNinthPercentile {0};
    double NintyNinePointNinthPercentile {0};
    double NintyNinePointNineNinethPercentile {0};
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

    qsort_s(
        Data,
        DataLength,
        sizeof(uint32_t),
        [](void*, const void* Left, const void* Right) -> int {
            return *(const uint32_t*)Left - *(const uint32_t*)Right;
        },
        nullptr);

    uint32_t PercentileIndex = (uint32_t)(DataLength * 0.5);
    PercentileStats->FiftiethPercentile = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.9);
    PercentileStats->NinetiethPercentile = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.99);
    PercentileStats->NintyNinthPercentile = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.999);
    PercentileStats->NintyNinePointNinthPercentile = Data[PercentileIndex];

    PercentileIndex = (uint32_t)(DataLength * 0.9999);
    PercentileStats->NintyNinePointNineNinethPercentile = Data[PercentileIndex];
}
