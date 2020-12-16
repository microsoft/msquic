<#

.SYNOPSIS
This file contains shared functionality and classes to be used between merging and generating.

#>

class ThroughputConfiguration {
    [boolean]$Loopback;
    [boolean]$Encryption;
    [boolean]$SendBuffering;
    [int]$NumberOfStreams;
    [boolean]$ServerToClient;
}

class HpsConfiguration {
}

class RpsConfiguration {
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;
}

class TestModel {
    [string]$PlatformName;
    [string]$TestName;
    [string]$MachineName;
    [ThroughputConfiguration]$TputConfig;
    [RpsConfiguration]$RpsConfig;
    [HpsConfiguration]$HpsConfig;
    [double[]]$Results;
}

class TestCommitModel {
    [string]$CommitHash;
    [datetime]$Date;
    [Collections.Generic.List[TestModel]]$Tests;
}

class CommitsFileModel {
    [string]$CommitHash;
    [datetime]$Date;
}