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

    [int] GetHashCode() {
        return [HashCode]::Combine($this.Loopback, $this.Encryption, $this.SendBuffering, $this.NumberOfStreams, $this.ServerToClient)
    }

    [boolean] Equals([Object]$other) {
        return $this.Encryption -eq $other.Encryption -and
        $this.Loopback -eq $other.Loopback -and
        $this.NumberOfStreams -eq $other.NumberOfStreams -and
        $this.SendBuffering -eq $other.SendBuffering -and
        $this.ServerToClient -eq $other.ServerToClient
    }
}

class HpsConfiguration {
    [int] GetHashCode() {
        return 7;
    }

    [boolean] Equals([Object]$other) {
        return $true
    }
}

class RpsConfiguration {
    [int]$ConnectionCount;
    [int]$RequestSize;
    [int]$ResponseSize;
    [int]$ParallelRequests;

    [int] GetHashCode() {
        return [HashCode]::Combine($this.ConnectionCount, $this.RequestSize, $this.ResponseSize, $this.ParallelRequests)
    }

    [boolean] Equals([Object]$other) {
        return $this.ConnectionCount -eq $other.ConnectionCount -and
        $this.RequestSize -eq $other.RequestSize -and
        $this.ResponseSize -eq $other.ResponseSize -and
        $this.ParallelRequests -eq $other.ParallelRequests
    }
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