/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Latency match helpers.

--*/

#pragma once

#include <math.h>

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
double
ComputeVarianceWithoutOutliers(
    _In_reads_(Length) uint32_t* Measurements,
    _In_ size_t Length,
    _In_ size_t Count,
    _In_ double Mean,
    _In_ double LowerFence,
    _In_ double UpperFence
)
{
    if (Length <= 1) {
        return 0;
    }
    double Variance = 0;
    for (size_t i = 0; i < Length; i++) {
        uint32_t Value = Measurements[i];
        if (Value > LowerFence && Value < UpperFence) {
            Variance += (Value - Mean) * (Value - Mean) / (Count - 1);
        }
    }
    return Variance;
}

#ifdef _KERNEL_MODE
__declspec(noinline)
#endif
static
double
ComputeQuartile(
    _In_reads_(Length) uint32_t* Measurements,
    _In_ size_t Count
    )
{
    if (Count % 2 == 0) {
        return ((double)Measurements[Count / 2 - 1] + (double)Measurements[Count / 2]) / 2.0;
    }
    return (double)Measurements[Count / 2];
}

#ifdef _KERNEL_MODE
__declspec(noinline)
#endif
static
uint64_t
SumWithoutOutliers(
    _In_reads_(Length) uint32_t* Measurements,
    _In_ size_t Length,
    _In_ double LowerFence,
    _In_ double UpperFence,
    _Out_ size_t* NewLength
    )
{
    uint64_t Sum = 0;
    *NewLength = 0;

    for (size_t i = 0; i < Length; i++) {
        uint32_t Value = Measurements[i];
        if (Value > LowerFence && Value < UpperFence) {
            Sum += Value;
            (*NewLength)++;
        }
    }
    return Sum;
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
    _Out_ Statistics* WithoutOutlierStatistics,
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

    double Quartile1, Quartile3;

    if (DataLength == 1) {
        Quartile1 = Quartile3 = Data[0];
    } else {
        Quartile1 = ComputeQuartile(Data, DataLength / 2);
        Quartile3 = ComputeQuartile(Data, DataLength * 3 / 2);
    }

    double IQR = Quartile3 - Quartile1;
    double LowerFence = Quartile1 - 1.5 * IQR;
    double UpperFence = Quartile3 + 1.5 * IQR;

    printf("Q1 %f IQR %f Q3 %f LF %f UF %f\n", Quartile1, IQR, Quartile3, LowerFence, UpperFence);

    size_t NewLength = 0;
    Sum = SumWithoutOutliers(Data, DataLength, LowerFence, UpperFence, &NewLength);

    printf("NewSum %llu NewLen %llu OldLen %llu\n", (unsigned long long) Sum, (unsigned long long)NewLength, (unsigned long long)DataLength);

    Mean = Sum / (double)NewLength;
    Variance = ComputeVarianceWithoutOutliers(Data, DataLength, NewLength, Mean, LowerFence, UpperFence);
    StandardDeviation = sqrt(Variance);
    StandardError = StandardDeviation / sqrt((double)DataLength);
    *WithoutOutlierStatistics = Statistics{
        Mean,
        Variance,
        StandardDeviation,
        StandardError,
        Min,
        Max
    };

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
