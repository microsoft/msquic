// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.EntityFrameworkCore;

namespace QuicDataServer.Models.Db
{
    [Owned]
    public class ThroughputTestResult
    {
        public double Result { get; set; }
    }
}
