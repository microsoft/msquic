$ErrorActionPreference = "Stop"

$Separator = "--------------------------------------------------------------------------------------------------------------------------------"
$DefaultDownloadFolder = "C:\Downloads"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 


#####################################################################################################
# Start-Setup
#####################################################################################################

<#
    .SYNOPSIS
        Sets up the context for the build script to work.
    .DESCRIPTION
        Prints out disk size information and sets up the downloaded content folder.
#>
function Start-Setup 
{
    Write-Host $Separator

    Trace-Message "Starting installation"
    
    Trace-Message "Checking disk space"
    gwmi win32_logicaldisk | Format-Table DeviceId, MediaType, {$_.Size /1GB}, {$_.FreeSpace /1GB}

    Trace-Message "Creating download location C:\Downloads"
    New-Item -Path $DefaultDownloadFolder -ItemType Container -ErrorAction SilentlyContinue
}

#####################################################################################################
# Stop-Setup
#####################################################################################################

<#
    .SYNOPSIS
        Shuts down the build script.
    .DESCRIPTION
        Deletes the downloaded content folder. Cleans the contents of the TEMP folder. Prints
        out a list of the installed software on the image by querying WMIC.
    .PARAMETER PreserveDownloads
        Preserves the downloaded content folder.
    .PARAMETER PreserveTemp
        Preserves the temp folder contents.
#>
function Stop-Setup 
{
    param
    (
        [Parameter(Mandatory=$false)]
        [switch]$PreserveDownloads,
        
        [Parameter(Mandatory=$false)]
        [switch]$PreserveTemp
    )

    Write-Host $Separator

    if (-not $PreserveDownloads) 
    {
        Trace-Message "Deleting download location C:\Downloads"
        Remove-Item -Path "C:\Downloads" -Recurse -ErrorAction SilentlyContinue
    }

    if (-not $PreserveTemp) 
    {
        Reset-TempFolders
    }

    Trace-Message "Checking disk space"
    gwmi win32_logicaldisk | Format-Table DeviceId, MediaType, {$_.Size /1GB}, {$_.FreeSpace /1GB}

    Trace-Message "Listing installed 32-bit software"
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName,DisplayVersion,Publisher,InstallDate |out-string -width 300

    Trace-Message "Listing installed 64-bit software"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName,DisplayVersion,Publisher,InstallDate | out-string -width 300

    Trace-Message "Finished installation."
    Write-Host $Separator
}

#####################################################################################################
# Get-File
#####################################################################################################

<#
    .SYNOPSIS
        Downloads a file from a URL to the downloaded contents folder.
    .DESCRIPTION
        Fetches the contents of a file from a URL to the downloaded contents folder (C:\Downloads).
        If a specific FilePath is specified, then skips the cache folder and downloads to the 
        specified path.
    .PARAMETER Url
        The URL of the content to fetch.
    .PARAMETER FileName
        The name of the file to write the fetched content to.
    .OUTPUTS
        The full path to the downloaded file.
#>
function Get-File
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Url,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName
    )

    Write-Host $Separator

    $file = [System.IO.Path]::Combine("C:\Downloads", $FileName)

    Trace-Message "Downloading from $Url to file $File"
    Invoke-WebRequest -Uri $Url -OutFile $file

    Trace-Message "Finished download"
    Write-Host $Separator

    return $file
}

#####################################################################################################
# Get-UniversalPackage
#####################################################################################################

<#
    .SYNOPSIS
        Downloads a universal package from Azure DevOps.
    .DESCRIPTION
        Downloads an universal package from an Azure DevOps package feed.
        Universal packages are used to distributed arbitrary blob content
        and is used by CDPX to store tools that need to be installed into
        build containers.
    .PARAMETER Name
        The name of the package to download.
    .PARAMETER Version
        The version of the package to download.
    .PARAMETER Feed
        The name of the package feed to download from.
        The default is the CX_External_Software feed in the OneBranch account.
    .PARAMETER Account
        The Azure DevOps account or organization name that the feed is in.
        The default is the OneBranch account.
    .PARAMETER Path
        The path to download the package into. THis parameter is only used
        if the switch IgnoreDefaultPath is not specified.
    .PARAMETER Token
        A PAT token to use to perform the download operation. Defaults to
        using the environment variable TEMP_CDP_DEFAULT_CLIENT_PACKAGE_PAT
        if no token is specified.
    .OUTPUTS
        The path to the package folder. A new folder named after the 
        package will be created in the standard download location of 
        C:\Downlaods unless the Path parameter is provided. If the Path
        parameter is provided, then that path is returned instead.
#>
function Get-UniversalPackage
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$Version,
        
        [Parameter(Mandatory=$false)]
        [string]$Feed="CX_External_Software@Local",
        
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Account="onebranch",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Path="C:\Downloads",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Token = $Env:TEMP_CDP_DEFAULT_CLIENT_PACKAGE_PAT,

        [switch]$IgnoreDefaultPath,

        [switch]$EnableDiagnosticLogs
    )

    Write-Host $Separator

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    if (-not $IgnoreDefaultPath)
    {
        $p = Join-Path -Path "C:\Downloads" -ChildPath $Name
        Trace-Message "IgnoreDefaultPath switch was NOT set. Using path $p as download path."
        $Path = $p 
    }
    else
    {
        Trace-Message "IgnoreDefaultPath switch was set. Using path $Path to download package to."
    }

    $o = -join("https://dev.azure.com/", $Account, "/")

    Trace-Message "Invoking Azure DevOps CLI to download package $Name version $Version to $Path from $o and feed $Feed ..."

    $Arguments = @("artifacts", "universal", "download", "--name", $Name, "--version", $Version, "--feed", $Feed, "--organization", $o, "--path", "$Path")
   
    if ($EnableDiagnosticLogs) 
    {
         $Arguments += "--debug"
    }

    $Env:AZURE_DEVOPS_EXT_PAT=$Token
    Write-Host $Arguments
    $exCode = Start-ExternalProcess -Path "C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin\az.cmd" -Arguments $Arguments

    if ($exCode -ne 0)
    {
        throw "CDPXERROR: Failed to download package $Name version $Version to $Path from $o and feed $Feed. Azure DevOps CLI exited with code $exCode"
    }

    Trace-Message "Finished downloading universal package"
    Write-Host $Separator

    return $Path
}

#####################################################################################################
# Login-AzureDevOps
#####################################################################################################

<#
    .SYNOPSIS
        Performs a login to Azure DevOps.
    .DESCRIPTION
        Uses the temporary PAT token to login to Azure DevOps so that universal
        packages can be downloaded.  
    .PARAMETER Account
        The Azure DevOps account or organization name to login to. The default is the
        OneBranch account.
    .PARAMETER Token
        A PAT token to use to perform the login operation. Defaults to
        using the environment variable TEMP_CDP_DEFAULT_CLIENT_PACKAGE_PAT
        if no token is specified.
#>
function Login-AzureDevOps
{
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Account="onebranch",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Token = $Env:TEMP_CDP_DEFAULT_CLIENT_PACKAGE_PAT,

        [switch]$EnableDiagnosticLogs
    )

    Write-Host $Separator

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    $o = -join("https://dev.azure.com/", $Account, "/")

    Write-Host "Invoking Azure DevOps CLI to login to account $o"

    $args = @($o, $Token)

    if ($EnableDiagnosticLogs)
    {
        $args += ("--debug")
    }

    &"$PSScriptRoot\ado-login.cmd" $args

    if ($LASTEXITCODE -ne 0)
    {
        throw "CDPXERROR: Failed to login to account $o with provided PAT token. Azure DevOps CLI exited with code $LASTEXITCODE"
    }

    Trace-Message "Finished login to Azure DevOps"
    Write-Host $Separator
}

#####################################################################################################
# Add-EnvironmentVariable
#####################################################################################################

<#
    .SYNOPSIS
        Defines a new or redefines an existing environment variable.
    .DESCRIPTION
        There are many ways to set environment variables. However, the default mechanisms do not
        work when the change has to be persisted. This implementation writes the change into 
        the registry, invokes the .NET SetEnvironmentVariable method with Machine scope and then
        invokes setx /m to force persistence of the change.
    .PARAMETER Name
        The name of the environment variable.
    .PARAMETER Value
        The value of the environment variable.
    .NOTES
        This does NOT work with PATH.
#>
function Add-EnvironmentVariable 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [string]$Value
    )

    Write-Host $Separator

    Trace-Message "Setting environment variable $name := $value"
    
    Set-Item -Path Env:$Name -Value $Value
    New-Item -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Environment" -ItemType String -Force -Name $Name -Value $Value
    
    [System.Environment]::SetEnvironmentVariable($Name, $Value, [EnvironmentVariableTarget]::Machine)
    
    &setx.exe /m $Name $Value
    
    Write-Host $Separator
}

#####################################################################################################
#  Update-Path
#####################################################################################################

<#
    .SYNOPSIS
        Redefines the PATH.
    .DESCRIPTION
        There are many ways to set environment variables. However, the default mechanisms do not
        work when the change has to be persisted. This implementation writes the change into 
        the registry, invokes the .NET SetEnvironmentVariable method with Machine scope and then
        invokes setx /m to force persistence of the change.
    .PARAMETER PathNodes
        An array of changes to the PATH. These values are appended to the existing value of PATH at the end.
    .NOTES
        This does NOT seem to work at all in Windows containers. Yet to be tested on RS5, but 
        definitely did not work in RS1 through RS4.
#>
function Update-Path 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string[]]$PathNodes
    )

    Write-Host $Separator

    $NodeToAppend=$null

    $path = $env:Path
    
    Trace-Message "Current value of PATH := $path"
    Trace-Message "Appending $Update to PATH"
    
    if (!$path.endswith(";"))
    {
      $path = $path + ";"
    }

    foreach ($PathNode in $PathNodes)
    {
       if (!$PathNode.endswith(";"))
       {
       $PathNode = $PathNode + ";"
       }
    $NodesToAppend += $PathNode    
    }
# add the new nodes
    $path = $path + $NodesToAppend 

#prettify it because there is some cruft from base images and or path typos i.e. foo;;
    $path = $path -replace ";+",";"

#pull these in a hack until remove nodes is implemented
    $path = $path.Replace("C:\Program Files\NuGet;","")
    $path = $path.Replace("C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin;","")
    $path = $path.Replace("C:\Program Files (x86)\Microsoft Visual Studio\2019\TestAgent\Common7\IDE\CommonExtensions\Microsoft\TestWindow;","")

#and set it
    Trace-Message "Setting PATH to $path"
    [System.Environment]::SetEnvironmentVariable("PATH", $path, [EnvironmentVariableTarget]::Machine)
    
    Write-Host $Separator
}


#####################################################################################################
# Add-WindowsFeature
#####################################################################################################

<#
    .SYNOPSIS
        Simple wrapper around the Install-WindowsFeature cmdlet.
    .DESCRIPTION
        A simple wrapper around the Install-WindowsFeature cmdlet that writes log lines and 
        data to help trace what happened.
    .PARAMETER Name
        The name of the feature to install.

    .PARAMETER SourceString
        The full -Source parameter with location to pass into install-WindowsFeature
#>
function Add-WindowsFeature 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceLocation=$null


    )

    Write-Host $Separator

    Trace-Message "Installing Windows feature $Name"

    if ($SourceLocation)
    {
      Install-WindowsFeature -Name $Name -Source $SourceLocation -IncludeAllSubFeature -IncludeManagementTools -Restart:$false -Confirm:$false
    }
    else
    {
      Install-WindowsFeature -Name $Name -IncludeAllSubFeature -IncludeManagementTools -Restart:$false -Confirm:$false
    }

    Trace-Message "Finished installing Windows feature $Name"
    
    Write-Host $Separator
}

#####################################################################################################
# Remove-WindowsFeature
#####################################################################################################


<#
    .SYNOPSIS
        Simple wrapper around the Uninstall-WindowsFeature cmdlet.
    .DESCRIPTION
        A simple wrapper around the Uninstall-WindowsFeature cmdlet that writes log lines and 
        data to help trace what happened.
    .PARAMETER Name
        The name of the feature to uninstall.
#>
function Remove-WindowsFeature 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    Write-Host $Separator

    Trace-Message "Removing Windows feature $Name"

    Uninstall-WindowsFeature -Name $Name -IncludeManagementTools -Restart:$false -Confirm:$false
    
    Trace-Message "Finished removing Windows feature $Name"
    
    Write-Host $Separator
}

#####################################################################################################
# Install-FromMSI
#####################################################################################################

<#
    .SYNOPSIS
        Executes a Microsoft Installer package (MSI) in quiet mode.
    .DESCRIPTION
        Uses the msiexec tool with the appropriate arguments to execute the specified installer
        package in quiet non-interactive mode with full verbose logging enabled.
    .PARAMETER Path
        The full path to the installer package file.
    .PARAMETER Arguments
        The optioal arguments to pass to the MSI installer package.
    .PARAMETER IgnoreExitCodes
        An array of exit codes to ignore. By default 3010 is always ignored because that indicates
        a restart is required. Docker layers are an implied restart. In other scenarios such as 
        image builds or local runs, a restart can be easily triggered by the invoking script or
        user.
    .PARAMETER IgnoreFailures
        Flag to force all failures (including actual failing exit codes) to be ignored. Notably
        1603 is a very common one that indicates that an actual error occurred.
#>
function Install-FromMSI 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [string[]]$Arguments,

        [Parameter(Mandatory=$false)]
        [int[]]$IgnoreExitCodes,

        [switch]$IgnoreFailures
    )

    Write-Host $Separator

    if (-not (Test-Path $Path))
    {
        throw "CDPXERROR: Could not find the MSI installer package at $Path"
    }

    $fileNameOnly = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    
    $log = [System.IO.Path]::Combine($env:TEMP, $fileNameOnly + ".log")

    $args = "/quiet /qn /norestart /lv! `"$log`" /i `"$Path`" $Arguments"
    
    Trace-Message "Installing from $Path"
    Trace-Message "Running msiexec.exe $args"
    
    $ex = Start-ExternalProcess -Path "msiexec.exe" -Arguments $args
    
    if ($ex -eq 3010) 
    {
        Trace-Message "Install from $Path exited with code 3010. Ignoring since that is just indicating restart required."
        Write-Host $Separator 
        return
    }
    elseif ($ex -ne 0)
    {
        foreach ($iex in $IgnoreExitCodes)
        {
            if ($ex -eq $iex)
            {
                Trace-Message "Install from $Path succeeded with exit code $ex"
                Write-Host $Separator
                return
            }
        }    

        Trace-Error "Failed to install from $Path. Process exited with code $ex"
                
        if (-not $IgnoreFailures)
        {
            throw "Failed to install from $Path. Process exited with code $ex"
        }
    }
}

#####################################################################################################
# Install-FromEXE
#####################################################################################################

<#
    .SYNOPSIS
        Executes any arbitrary executable installer.
    .DESCRIPTION
        A simple wrapper function to kick off an executable installer and handle failures, logging etc.
    .PARAMETER Path
        The path to the installer package file.
    .PARAMETER Arguments
        The optioal arguments to pass to the installer package.
    .PARAMETER IgnoreExitCodes
        An array of exit codes to ignore. By default 3010 is always ignored because that indicates
        a restart is required. Docker layers are an implied restart. In other scenarios such as 
        image builds or local runs, a restart can be easily triggered by the invoking script or
        user.
    .PARAMETER IgnoreFailures
        Flag to force all failures (including actual failing exit codes) to be ignored. Notably
        1603 is a very common one that indicates that an actual error occurred.
#>
function Install-FromEXE 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [int[]]$IgnoreExitCodes,
    
        [Parameter(Mandatory=$false)]
        [string[]]$Arguments,

        [switch]$IgnoreFailures
    )

    Write-Host $Separator

    Trace-Message "Running $Path"
    
    $ex = Start-ExternalProcess -Path $Path -Arguments $Arguments

    if ($ex -eq 3010) 
    {
        Trace-Message "Install from $Path exited with code 3010. Ignoring since that is just indicating restart required."
        Write-Host $Separator 
        return
    }
    elseif ($ex -ne 0)
    {
        foreach ($iex in $IgnoreExitCodes)
        {
            if ($ex -eq $iex)
            {
                Trace-Message "Install from $Path succeeded with exit code $ex"
                Write-Host $Separator
                return
            }
        }

        Trace-Error "Failed to install from $Path. Process exited with code $ex"

        if (-not $IgnoreFailures)
        {
            throw "Failed to install from $Path. Process exited with code $ex"
        }
    }
}

#####################################################################################################
# Install-FromInnoSetup
#####################################################################################################

<#
    .SYNOPSIS
        A shorthand function for running a Inno Setup installer package with the appropriate options.
    .DESCRIPTION
        Inno Setup installer packages can be run in silent mode with the options 
        /VERYSILENT /NORESTART /CLOSEAPPLICATIONS /TYPE=full. In most cases, these options are the 
        same for every Inno Setup installer. This function is hence a short hand for Inno Setup.
    .PARAMETER Path
        The path to the Inno Setup installer package file.
    .PARAMETER Arguments
        The optioal arguments to pass to the installer package.
    .PARAMETER IgnoreExitCodes
        An array of exit codes to ignore.
    .PARAMETER IgnoreFailures
        Flag to force all failures (including actual failing exit codes) to be ignored.

#>
function Install-FromInnoSetup
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [int[]]$IgnoreExitCodes,
    
        [Parameter(Mandatory=$false)]
        [string[]]$Arguments,

        [switch]$IgnoreFailures
    )

    $fileNameOnly = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $logName = $fileNameOnly + ".log"
    $logFile = Join-Path $Env:TEMP -ChildPath $logName

    $args = "/QUIET /SP- /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /NOICONS /TYPE=full /LOG `"$logFile`" "
    $args += $Arguments

    Install-FromEXE -Path $Path -Arguments $args -IgnoreExitCodes $IgnoreExitCodes -IgnoreFailures:$IgnoreFailures
}

#####################################################################################################
# Install-FromDevToolsInstaller
#####################################################################################################

<#
    .SYNOPSIS
        A shorthand function for running a DevDiv Tools installer package with the appropriate options.
    .DESCRIPTION
        DevDiv Tools installer packages can be run in silent mode with the options 
        /quiet /install /norestart. In most cases, these options are the 
        same for every DevDiv Tools installer. This function is hence a short hand for DevDiv Tools
        installer packages.
    .PARAMETER Path
        The path to the DevDiv Tools installer package file.
    .PARAMETER Arguments
        The optional arguments to pass to the installer package.
    .PARAMETER IgnoreExitCodes
        An array of exit codes to ignore. 3010 is added by default by this function.
    .PARAMETER IgnoreFailures
        Flag to force all failures (including actual failing exit codes) to be ignored.

#>
function Install-FromDevDivToolsInstaller
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [int[]]$IgnoreExitCodes,
    
        [Parameter(Mandatory=$false)]
        [string[]]$Arguments,

        [switch]$IgnoreFailures
    )

    $fileNameOnly = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $logName = $fileNameOnly + ".log"
    $logFile = Join-Path $Env:TEMP -ChildPath $logName

    $args = "/QUIET /INSTALL /NORESTART `"$logFile`" "
    $args += $Arguments

    $iec = (3010)
    $iec += $IgnoreExitCodes

    Install-FromEXE -Path $Path -Arguments $args -IgnoreExitCodes $iec -IgnoreFailures:$IgnoreFailures
}

#####################################################################################################
# Install-FromChocolatey
#####################################################################################################

<#
    .SYNOPSIS
        Installs a Chocolatey package.
    .DESCRIPTION
        Installs a package using Chocolatey in silent mode with no prompts.
    .PARAMETER Name
        The name of the package to install.
    
#>
function Install-FromChocolatey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    Write-Host $Separator

    Write-Host "Installing chocolatey package $Name"
    Start-ExternalProcess -Path "C:\ProgramData\chocolatey\bin\choco.exe" -Arguments @("install","-y",$Name)

    Write-Host $Separator
}


#####################################################################################################
# Install-FromEXEAsyncWithDevenvKill
#####################################################################################################

<#
    .SYNOPSIS
        Starts an installer asynchronously and waits in the background for rogue child processes
        and kills them after letting them finish.
    .DESCRIPTION
        Visual Studio installers start a number of child processes. Notable amongst them is the devenv.exe
        process that attempts to initialize the VS IDE. Containers do not support UIs so this part hangs.
        There might be other related processes such as msiexec as well that hang. Invariable, these
        child processes complete quite fast, but never exit potentially becuase they are attempting
        to display some UI and hang. This helper function will kick off the installer and then monitor
        the task list to find those child processes by name and then it will kill them.
    .PARAMETER Path
    .PARAMETER StuckProcessNames
    .PARAMETER IgnoreExitCodes
    .PARAMETER IgnoreFailures
    .PARAMETER Arguments
    .PARAMETER WaitMinutes
#>
function Install-FromEXEAsyncWithDevenvKill 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [string[]]$StuckProcessNames,

        [Parameter(Mandatory=$false)]
        [int[]]$IgnoreExitCodes,

        [Parameter()]
        [switch]$IgnoreFailures,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$WaitMinutes = 5,

        [string[]]$Arguments
    )

    Write-Host $Separator

    Trace-Message "Running $Path with $Arguments"
           
    $process = Start-Process $Path -PassThru -Verbose -NoNewWindow -ArgumentList $Arguments
    $pid = $process.Id
    $pn = [System.IO.Path]::GetFileNameWithoutExtension($Path)

    Trace-Message "Started EXE asynchronously. Process ID is $pid"

    Wait-ForProcess -Process $process -Minutes $WaitMinutes

    Trace-Message "Walking task list and killing any processes in the stuck process list $StuckProcessNames"

    foreach ($stuckProcessName in $StuckProcessNames) 
    {
        Stop-ProcessByName -Name $stuckProcessName -WaitBefore 3 -WaitAfter 3
    }
        
    Trace-Message "Also killing any rogue msiexec processes"

    Stop-ProcessByName -Name "msiexec" -WaitBefore 3 -WaitAfter 3

    Wait-WithMessage -Message "Waiting for process with ID $pid launched from $Path to finish now that children have been killed off" -Minutes 2

    Stop-ProcessByName -Name $pn -WaitBefore 3 -WaitAfter 3

    $ex = $process.ExitCode;

    if ($ex -eq 0)
    {
        Trace-Message "Install from $Path succeeded with exit code 0"
        Write-Host $Separator
        return
    }

    foreach ($iex in $ignoreExitCodes)
    {
        if ($ex -eq $iex)
        {
            Trace-Message "Install from $Path succeeded with exit code $ex"
            Write-Host $Separator
            return;
        }
    }

    Trace-Error "Failed to install from $Path. Process exited with code $ex"

    if (-not $IgnoreFailures)
    {
        throw "CDPXERROR: Failed to install from $Path. Process exited with exit code $ex"
    }
}

#####################################################################################################
# Confirm-PresenceOfVisualStudioErrorLogFile
#####################################################################################################

<#
    .SYNOPSIS
        Throws an exception if a known Visual Studio installation error log file is found.
    .DESCRIPTION
        Visual Studio installers do not exit with appropriate error codes in case of component
        install failures. Often, any errors are indicated by the presence of a non-zero size
        error log file in the TEMP folder. This function checks for the existence of such files
        and throws an exception if any are found.
    .PARAMETER Path
        The folder in which to check for the presence of the error log files. Defaults to $Env:TEMP
    .PARAMETER Filter
        The filename filter to apply to search for error log files.
    .PARAMETER ThrowIfExists
        If set, then fails if an error log file is found on disk even if the size is zero. Defaults to false.
    .PARAMETER ThrowIfNotEmpty
        If set, then fails if an error log file is found on disk and its size is non-zero. Defaults to true.
#>
function Confirm-PresenceOfVisualStudioErrorLogFile 
{    
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Filter,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Path = $Env:TEMP,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowIfExists = $false,

        [Parameter(Mandatory = $false)]
        [switch]$ThrowIfNotEmpty = $true
    )

    if (Test-Path $Path)
    {
        Trace-Message "Checking if error log files matching the filter $Filter exist in $Path"

        Get-ChildItem -Path $Path -Filter $Filter | 
            ForEach-Object 
            { 
                $file = $_.FullName
                $len = $_.Length

                Trace-Warning "Found error log file $file with size $len"

                if ($ThrowIfExists) 
                {
                    throw "CDPXERROR: At least one error log file $file matching $Filter was found in $Path."
                }

                if ($ThrowIfNotEmpty -and ($len -gt 0)) 
                {
                    throw "At least one non-empty log file $file matching $filter was found in $folder" 
                }
            }
    }
    else
    {
        Trace-Warning "Folder $Path does not exist. Skipping checks."
    }
}

#####################################################################################################
# Stop-ProcessByName
#####################################################################################################

<#
    .SYNOPSIS
        Kills all processes with a given name.
    .DESCRIPTION
        Some installers start multiple instances of other applications to perform various
        post-installer or initialization actions. The most notable is devenv.exe. This function
        provides a mechanism to brute force kill all such instances.
    .PARAMETER Name
        The name of the process to kill.
    .PARAMETER WaitBefore
        The optional number of minutes to wait before killing the process. This provides time for
        the process to finish its processes.
    .PARAMETER WaitAfter
        The optional number of minutes to wait after killing the process. This provides time for
        the process to exit and any handles to expire.
#>
function Stop-ProcessByName 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$WaitBefore = 3,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$WaitAfter = 3
    )

    Wait-WithMessage -Message "Waiting for $WaitBefore minutes before killing all processes named $processName" -Minutes $WaitBefore
    &tasklist /v

    $count = 0

    Get-Process -Name $Name -ErrorAction SilentlyContinue | 
        ForEach-Object 
        {
            $process = $_
            Trace-Warning "Killing process with name $Name and ID $($process.Id)"
            $process.Kill()
            ++$count
        }

    Trace-Warning "Killed $count processes with name $Name"

    Wait-WithMessage -Message "Waiting for $WaitAfter minutes after killing all processes named $Name" -Minutes $WaitAfter

    &tasklist /v
}

#####################################################################################################
# Wait-WithMessage
#####################################################################################################

<#
    .SYNOPSIS
        Performs a synchronous sleep.
    .DESCRIPTION
        Some asynchronous and other operations require a wait time before 
        assuming a failure. This function forces the caller to sleep. The sleep is
        performed in 1-minute intervals and a message is printed on each wakeup.
    .PARAMETER Message
        The message to print after each sleep period.
    .PARAMETER Minutes
        The number of minutes to sleep.
#>
function Wait-WithMessage 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Minutes
    )

    $elapsed = 0

    while ($true) 
    {
        if ($elapsed -ge $Minutes) 
        {
            Write-Host "Done waiting for $elapsed minutes"
            break
        }

        Trace-Message $Message
        Start-Sleep -Seconds 60
        ++$elapsed
    }
}


#####################################################################################################
# Wait-WithMessageAndMonitor
#####################################################################################################

<#
    .SYNOPSIS
        Performs a synchronous sleep and on each wakeup runs a script block that may contain some
        monitoring code.
    .DESCRIPTION
        Some asynchronous and other operations require a wait time before 
        assuming a failure. This function forces the caller to sleep. The sleep is performed
        in 1-minute intervals and a message is printed and a script block is run on each wakeup.
    .PARAMETER Message
        The message to print after each sleep period.
    .PARAMETER Block
        The script block to run after each sleep period.
    .PARAMETER Minutes
        The number of minutes to sleep.
#>
function Wait-WithMessageAndMonitor
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ScriptBlock]$Monitor,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Minutes
    )

    $elapsed = 0

    while ($true) 
    {
        if ($elapsed -ge $Minutes) 
        {
            Write-Host "Done waiting for $elapsed minutes"
            break
        }

        Trace-Message $Message
        Start-Sleep -Seconds 60
        $Monitor.Invoke()
        ++$elapsed
    }
}

#####################################################################################################
# Reset-TempFolders
#####################################################################################################

<#
    .SYNOPSIS
        Deletes the contents of well known temporary folders.
    .DESCRIPTION
        Installing lots of software can leave the TEMP folder built up with crud. This function
        wipes the well known temp folders $Env:TEMP and C:\Windows\TEMP of all contentes. The
        folders are preserved however.
#>
function Reset-TempFolders 
{
    try 
    {
        Trace-Message "Wiping contents of the $($Env:TEMP) and C:\Windows\TEMP folders."

        Get-ChildItem -Directory -Path $Env:TEMP |  ForEach-Object {
                $p = $_.FullName
                Trace-Message "Removing temporary file $p"
                Remove-Item -Recurse -Force -Path $p -ErrorAction SilentlyContinue
            }

        Get-ChildItem -File -Path $Env:TEMP | ForEach-Object {
                $p = $_.FullName
                Trace-Message "Removing temporary file $p"
                Remove-Item -Force -Path $_.FullName -ErrorAction SilentlyContinue
            }

        Get-ChildItem -Directory -Path "C:\Windows\Temp" | ForEach-Object {
                $p = $_.FullName
                Trace-Message "Removing temporary file $p"
                Remove-Item -Recurse -Force -Path $_.FullName -ErrorAction SilentlyContinue
            }

        Get-ChildItem -File -Path "C:\Windows\Temp" | ForEach-Object {
                $p = $_.FullName
                Trace-Message "Removing temporary file $p"
                Remove-Item -Force -Path $_.FullName -ErrorAction SilentlyContinue
            }
    } 
    catch 
    {
        Trace-Warning "Errors occurred while trying to clean up temporary folders."
        $_.Exception | Format-List
    } 
    finally 
    {
        Trace-Message "Cleaned up temporary folders at $Env:TEMP and C:\Windows\Temp"
    }
}

#####################################################################################################
# Get-SecretFromKeyVault
#####################################################################################################

<#
    .SYNOPSIS
        Retrieves a secret from a KeyVault using an AAD OAuth token.
    .DESCRIPTION
        A function that is expected to be used in global images that enables fetching 
        license data to activate software that requires licensing.
    .PARAMETER VaultName
        The vault to fetch from.
    .PARAMETER SecretName
        The name of the secret.
    .PARAMETER OAuthToken
        The OAuth token to use to authenticate to the vault. The host MSI token is passed in for
        global images.
    .PARAMETER SecretDescription
        An optional description of the secret being fetched.
    .PARAMETER ErrorMessage
        An optional error message to display in case of failures.
    .OUTPUTS
        The value of the secret.
#>
function Get-SecretFromKeyVault
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$VaultName,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$OAuthToken,
        
        [Parameter(Mandatory=$false)]
        [string]$SecretDescription,
        
        [Parameter(Mandatory=$false)]
        [string]$ErrorMessage
    )
    
    $fullDescription = "$SecretDescription ('$SecretName' from Vault '$VaultName')"
    $fullErrorMessage = "Unable to retrieve $fullDescription from Key Vault via MSI. $ErrorMessage"
    $keyVaultApiVersion = "?api-version=2016-10-01";
    $secretUrl = "https://${VaultName}.vault.azure.net/secrets/${SecretName}";
    $secretUrl += $keyVaultApiVersion;

    Trace-Message "Attempting to retrieve $fullDescription using OAuth token"
    Trace-Message "Fetching secret from URL $secretUrl"

    $response = Invoke-WebRequest -UseBasicParsing -Uri $secretUrl -Method GET -Header @{Authorization="Bearer $OAuthToken"} | ConvertFrom-Json;

    $secretValue = $response.value;
        
    if([string]::IsNullOrWhiteSpace($secretValue))
    {
        throw "CDPXERROR: Failed to fetch secret data from vault. $fullErrorMessage"
    }

    Trace-Message "Successfully acquired $fullDescription from Key Vault"
    return $secretValue
}

#####################################################################################################
# Confirm-FileHash
#####################################################################################################

<#
    .SYNOPSIS
        Verifies the content hash of downloaded content.
    .DESCRIPTION
        By default computes the SHA256 hash of downloaded content and compares it against 
        a given hash assuming it to be a SHA256 hash as well.
    .PARAMETER FileName
        The name of the file. If the IsFullPath switch is not specified, assumes a file within
        the downloaded content cache.
    .PARAMETER ExpectedHash
        The expected hash value of the content.
    .PARAMETER Algorithm
        The optional hash algorithm to hash. Defaults to SHA256.
    .OUTPUTS
#>
function Confirm-FileHash 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedHash,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Algorithm = "sha256"
    )

    Trace-Message "Verifying content hash for file $Path"

    $exists = Test-Path -Path $Path -PathType Leaf

    if (-not $exists) 
    {
        throw "CDPXERROR: Failed to find file $Path in order to verify hash."
    }

    $hash = Get-FileHash $Path -Algorithm $Algorithm
    
    if ($hash.Hash -ne $ExpectedHash) 
    {
        throw "File $Path hash $hash.Hash did not match expected hash $expectedHash"
    }
}

#####################################################################################################
# Start-ExternalProcess
#####################################################################################################

<#
    .SYNOPSIS
        Executes an external application
    .DESCRIPTION
        PowerShell does not deal well with applications or scripts that write to 
        standard error. This wrapper function handles starting the process,
        waiting for output and then captures the standard output/error streams and
        reports them without writing them to stderr.
    .PARAMETER Path
        The path to the application to run.
    .PARAMETER Arguments
        The array of arguments to pass to the external application.
    .OUTPUTS
        Returns the exit code that the application exited with.
#>
function Start-ExternalProcess 
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [string[]]$Arguments
    )

    Trace-Message "Executing application: $Path $Arguments"

    $guid = [System.Guid]::NewGuid().ToString("N")
    $errLogFileName = -join($guid, "-stderr.log")
    $outLogFileName = -join($guid, "-stdout.log")
    $errLogFile = Join-Path -Path $Env:TEMP -ChildPath $errLogFileName
    $outLogFile = Join-Path -Path $Env:TEMP -ChildPath $outLogFileName
    $workDir = [System.IO.Path]::GetDirectoryName($Path)
    [System.Diagnostics.Process]$process = $null

    if (($Arguments -ne $null) -and ($Arguments.Length -gt 0))
    {
        $process = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardError $errLogFile -RedirectStandardOutput $outLogFile
    }
    else
    {
        $process = Start-Process -FilePath $Path -NoNewWindow -PassThru -RedirectStandardError $errLogFile -RedirectStandardOutput $outLogFile
    }

    $handle = $process.Handle
    $pid = $process.Id
    $ex = 0

    Trace-Message -Message "Started process from $Path with PID $pid (and cached handle $handle)"

    while ($true)
    {
        Trace-Message -Message "Waiting for PID $pid to exit ..."

        if ($process.HasExited)
        {
            Trace-Message -Message "PID $pid has exited!"
            break
        }

        Sleep -Seconds 60
    }

    Trace-Message "STDERR ---------------------------"
    Get-Content $errLogFile | Write-Host

    Trace-Message "STDOUT ---------------------------"
    Get-Content $outLogFile | Write-Host

    $ex = $process.ExitCode

    if ($ex -eq $null)
    {
        Trace-Warning -Message "The process $pid returned a null or invalid exit code value. Assuming and returning 0"
        $ex = 0
    }
    else
    {
        Trace-Message "Process $pid exited with exit code $ex"
    }

    return $ex
}

#####################################################################################################
# Run-ExternalProcessWithWaitAndKill
#####################################################################################################

<#
    .SYNOPSIS
        Executes an external application, waits for a specified amount of time and then kills it.
    .DESCRIPTION
        Some applications get stuck when running for the first time. This function starts the
        application, then waits and then kills it so that a subsequent run can succeed.
    .PARAMETER Path
        The path to the application to run.
    .PARAMETER Arguments
        The array of arguments to pass to the external application.
    .PARAMETER Minutes
        The amount of time to wait in minutes before killing the external application.
    .OUTPUTS
        The exit code if one is available from the process.
#>
function Run-ExternalProcessWithWaitAndKill
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$false)]
        [string[]]$Arguments,

        [Parameter(Mandatory=$false)]
        [ScriptBlock]$Monitor,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Minutes
    )

    Trace-Message "Executing application: $Path $Arguments. Will wait $Minutes minutes before killing it."
 
    $guid = [System.Guid]::NewGuid().ToString("N")
    $errLogFileName = -join($guid, "-stderr.log")
    $outLogFileName = -join($guid, "-stdout.log")
    $errLogFile = Join-Path -Path $Env:TEMP -ChildPath $errLogFileName
    $outLogFile = Join-Path -Path $Env:TEMP -ChildPath $outLogFileName
    $workDir = [System.IO.Path]::GetDirectoryName($Path)
    [System.Diagnostics.Process]$process = $null

    if (-not $Arguments)
    {
        $process = Start-Process -FilePath $Path -NoNewWindow -PassThru -RedirectStandardError $errLogFile -RedirectStandardOutput $outLogFile
    }
    else
    {
        $process = Start-Process -FilePath $Path -ArgumentList $Arguments -NoNewWindow -PassThru -RedirectStandardError $errLogFile -RedirectStandardOutput $outLogFile
    }

    $handle = $process.Handle
    $pid = $process.Id
    $ex = 0

    Trace-Message -Message "Started process from $Path with PID $pid (and cached handle $handle)"

    $exited = Wait-ForProcess -Process $process -Minutes $Minutes -Monitor $Monitor

    if (-not $exited)
    {
        Trace-Warning "CDPXERROR: Process with ID $pid failed to exit within $Minutes minutes. Killing it."
        
        try
        {
            $process.Kill()
            Trace-Warning "Killed PID $pid"
        }
        catch 
        {
            Trace-Warning "Exception raised while attempting to kill PID $pid. Perhaps the process has already exited."
            $_.Exception | Format-List
        }
    }
    else
    {
        $ex = $process.ExitCode
        Trace-Message "Application $Path exited with exit code $ex"
    }
    
    Trace-Message "STDERR ---------------------------"
    Get-Content $errLogFile | Write-Host

    Trace-Message "STDOUT ---------------------------"
    Get-Content $outLogFile | Write-Host

    if ($ex -eq $null)
    {
        Trace-Warning -Message "The process $pid returned a null or invalid exit code value. Assuming and returning 0"
        return 0
    }

    return $ex
}

#####################################################################################################
# Wait-ForProcess
#####################################################################################################

<#
    .SYNOPSIS
        Waits for a previously started process until it exits or there is a timeout.
    .DESCRIPTION
        Waits for a started process until it exits or a certain amount of time has elapsed.
    .PARAMETER Process
        The [System.Process] project to wait for.
    .PARAMETER Minutes
        The amount of time to wait for in minutes.
    .PARAMETER Monitor
        An optional script block that will be run after each wait interval.
#>
function Wait-ForProcess
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Minutes = 10,

        [Parameter(Mandatory=$false)]
        [ScriptBlock]$Monitor
    )

    $waitTime = $Minutes

    $handle = $process.Handle
    $pid = $Process.Id

    while ($waitTime -gt 0)
    {
        Trace-Message -Message "Waiting for process with ID $pid to exit in $waitTime minutes."

        if ($Process.HasExited)
        {
            $ex = $Process.ExitCode
            Trace-Message "Process with ID $pid has already exited with exit code $ex"
            return $true
        }

        Sleep -Seconds 60

        if ($Monitor)
        {
            try
            {
                Trace-Message "Invoking monitor script: $Monitor"
                $Monitor.Invoke()
            }
            catch 
            {
                Trace-Warning "Exception occurred invoking monitoring script"
                $_.Exception | Format-List
            }
        }

        --$waitTime
    }

    return $false
}

#####################################################################################################
# Trace-Message
#####################################################################################################

<#
    .SYNOPSIS
        Logs an informational message to the console.
    .DESCRIPTION
        Writes a message to the console with the current timestamp and an information tag.
    .PARAMETER Message
        The message to write.
#>
function Trace-Message
{
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    $Message = $Message -replace "##vso", "__VSO_DISALLOWED"
    $timestamp = Get-Date
    Write-Host "[INFO] [$timestamp] $Message" 
}

#####################################################################################################
# Trace-Warning
#####################################################################################################

<#
    .SYNOPSIS
        Logs a warning message to the console.
    .DESCRIPTION
        Writes a warning to the console with the current timestamp and a warning tag.
    .PARAMETER Message
        The warning to write.
#>
function Trace-Warning
{
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    $timestamp = Get-Date
    $Message = $Message -replace "##vso", "__VSO_DISALLOWED"
    Write-Host "[WARN] [$timestamp] $Message" -ForegroundColor Yellow
    Write-Host "##vso[task.logissue type=warning]$Message"
}

#####################################################################################################
# Trace-Error
#####################################################################################################

<#
    .SYNOPSIS
        Logs an error message to the console.
    .DESCRIPTION
        Writes an error to the console with the current timestamp and an error tag.
    .PARAMETER Message
        The error to write.
#>
function Trace-Error
{
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    $timestamp = Get-Date
    $Message = $Message -replace "##vso", "__VSO_DISALLOWED"
    Write-Host "[ERROR] [$timestamp] $Message" -ForegroundColor Red
    Write-Host "##vso[task.logissue type=error]$Message"
}

#####################################################################################################
# Expand-ArchiveWith7Zip
#####################################################################################################

<#
    .SYNOPSIS
        Uses 7-Zip to expand an archive instead of the standard Expand-Archive cmdlet.
    .DESCRIPTION
        The Expand-Archive cmdlet is slow compared to using 7-Zip directly. This function
        assumes that 7-Zip is installed at C:\7-Zip.
    .PARAMETER -Source
        The path to the archive file.
    .PARAMETER -Destination
        The folder to expand into.
    .PARAMETER ToolPath
        The path to where the 7z.exe tool is available.
#>
function Expand-ArchiveWith7Zip
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ToolPath = "C:\7-Zip\7z.exe",

        [Parameter(Mandatory=$false)]
        [switch]$IgnoreFailures=$false
    )

    Write-Host $Separator

    if (-not $ToolPath)
    {
        throw "CDPXERROR: The 7-Zip tool was not found at $ToolPath."
    }

    if (-not (Test-Path $Source))
    {
        throw "CDPXERROR: The specified archive file $Source could not be found."
    }

    if (-not $Destination)
    {
        $sourceDir = [System.IO.Path]::GetDirectoryName($Source);
        $Destination = $sourceDir

        Trace-Message "No destination was specified so the default location $Destination was chosen."
    }

    Trace-Message "Uncompressing archive $Source into folder $Destination using 7-Zip at $ToolPath"

    Install-FromEXE -Path $ToolPath -Arguments "x -aoa -y `"$Source`" -o`"$Destination`"" -IgnoreFailures:$IgnoreFailures

    Trace-Message "Successfully uncompressed archive at $Source into $Destination"
    Write-Host $Separator
}

#####################################################################################################
# Get-VisualStudioProductKeyArguments
#####################################################################################################

<#
    .SYNOPSIS
        Retrieves a string that can be passed into Visual Studio installations for activating 
        the product.
    .DESCRIPTION
        This function returns the full command to pass into Visual Studio installer for 
        using a product key to activate the product. The returned string can be passed in directly
        and will be of the form --productKey KEY. The returned value has a leading space but no
        trailing space.
    .PARAMETER SecretName
        If the product key is being retrieved from KeyVault, then the name of the secret that
        holds the required key. 
    .OUTPUTS
        The arguments to pass to the Visual Studio command line installer.
#>
function Get-VisualStudioProductKeyArguments
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SecretName
    )

    $vsProductKey = $Env:TEMP_VS_PRODUCT_KEY
    $productKeyArgs = $null
    $ctrHost = $Env:TEMP_CONTAINER_HOST_NAME

    if ([string]::IsNullOrWhiteSpace($vsProductKey))
    {
        $vsProductKey = Get-SecretFromKeyVault -VaultName "cxprod-basic" -SecretName $SecretName -OAuthToken $Env:TEMP_MSI_OAUTH_TOKEN -SecretDescription "Visual Studio Volume Activation Key"
    }

    if ($vsProductKey -eq "")
    {
        Trace-Warning -Message "Using an empty product key. Visual Studio installation will not be activated."
    }
    else
    {
        $productKeyArgs = " --productKey $vsProductKey"
    }

    Write-Host "##vso[task.setvariable variable=VS_PRODUCT_KEY_SECRET;issecret=true]$vsProductKey"
    return $productKeyArgs
}

#####################################################################################################
# Get-BlobPackageFromBase
#####################################################################################################

<#
    .SYNOPSIS
        Uses AzCopy to download a blob package from blob store.
    .DESCRIPTION
        Some very large content such as Visual Studio offline installer files are stored in
        a CDPX hosted blob store. This method fetches the contents of such blob packages
        using AzCopy.
#>
function Get-BlobPackageFromBase
{
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContainerName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$nodePath,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$downloadPath="C:\Downloads"

    )

    Write-Host $Separator

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    $Env:AZCOPY_LOG_LOCATION = $Env:TEMP

    $url = Get-BlobPackageBaseUrl -ContainerName $ContainerName
    
    Trace-Message "Invoking AzCopy CLI to download package $Name version $Version to $Path from $url"

    $Arguments = @("copy", $url, $downloadPath, "--recursive", "--include-path $nodePath", "--include-pattern *")

    Run-ExternalProcessWithWaitAndKill -Path "C:\AzCopy\azcopy.exe" -Arguments $Arguments -Minutes 30

    Trace-Message "Finished downloading blob package"

    Write-Host $Separator

    return $Path
}

#####################################################################################################
# Get-BlobPackageFromEdge
#####################################################################################################

<#
    .SYNOPSIS
        Uses a HTTP/S request to download a blob package from CDN.
    .DESCRIPTION
        Some content such as third party OSS or free software are hosted on a CDPX hosted
        blob store which is replicated to a CDN. This function fetches the blob package from
        the CDN.
#>
function Get-BlobPackageFromEdge
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$Version,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [string]$FileName,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Path="C:\Downloads",

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContainerName
    )

    Write-Host $Separator

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

    $url = Get-BlobPackageEdgeUrl -Name $Name -Version $Version -Container $ContainerName

    Trace-Message "Downloading blob package $Name and $Version from $url"

    $path = Get-File -Url $url -FileName $FileName

    Trace-Message "Finished downloading blob package to $FileName"

    Write-Host $Separator

    return $path
}

#####################################################################################################
# Enum HostEnvironment
#####################################################################################################

enum HostEnvironment
{
    Dev
    Test
    Prod
}

#####################################################################################################
# Get-HostEnvironment
#####################################################################################################

<#
    .SYNOPSIS
        Uses some heuristics about the underlying host to determine what kind of environment the 
        host is in.
    .DESCRIPTION
        Leverages CDPX host naming conventions to determine if a host is a test or production host. If 
        neither is true, this function always assumes that the host is a developer box.
    .OUTPUTS
        An instance of the enumeration HostEnvironment.
#>
function Get-HostEnvironment
{
    $ctrHost = $Env:TEMP_CONTAINER_HOST_NAME

    if ($ctrHost)
    {
        if ($ctrHost.StartsWith("XWT"))
        {
            Trace-Message -Message "Running on CDPX test host."
            return [HostEnvironment]::Test
        }
        elseif ($ctrHost.StartsWith("XWP"))
        {
            Trace-Message -Message "Running on CDPX prod host."
            return [HostEnvironment]::Prod
        }
    }

    Trace-Message "Unsure what kind of CDPX environment underlying host `"$ctrHost`" is in. Assuming development box."
    return [HostEnvironment]::Dev
}

#####################################################################################################
# Get-BlobContainerName
#####################################################################################################

<#
    .SYNOPSIS
        Returns the container name to use for blob packages.
    .DESCRIPTION
        Returns a OS specific container name within which blob packages specific to that OS are 
        stored.
    .OUTPUTS
        Returns a lower case string that is the container name within the blob store in which
        blob packages are stored.
#>
function Get-BlobContainerName
{
    if ($Env:os -eq "Windows_NT")
    {
        return "windows"
    }
    elseif ($Env:OS -eq "Linux")
    {
        return "linux"
    }

    throw "CDPXERROR: Only supported operating systems are Windows and Linux. Unknown OS $($Env:OS)"
}

#####################################################################################################
# Get-BlobAccountName
#####################################################################################################

<#
    .SYNOPSIS
        Returns the base storage account in which blob packages are stored.
    .DESCRIPTION
        Returns an environment specific base storage account in which blob packages are stored.
    .OUTPUTS
        Returns a string that is an environment specific value for the blob storage account
        in which blob packages are stored.
#>
function Get-BlobAccountName
{
    $hostEnv = Get-HostEnvironment
    $hostEnvStr = $hostEnv.ToString().ToLowerInvariant()
    $prefix = "cxswdist"
    $accountName = $prefix + $hostEnvStr

    Trace-Warning "Currently overriding blob storage account to cxswdisttest for all host environments."
    return "cxswdisttest"
}

#####################################################################################################
# Get-BlobPackageEdgeUrl
#####################################################################################################

<#
    .SYNOPSIS
        Gets the Azure blob store URL for a given blob package and version.
    .DESCRIPTION
        CDPX hosts some well known packages in blob store. This ensures that these packages
        are always available. This method returns the blob store to use that is appropriate for
        the executing environment.
    .NOTE
        This function is for use with AzCopy.
    .OUTPUTS
        The blob store URL for the package.
#>
function Get-BlobPackageEdgeUrl
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Version,
  
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContainerName
    )

    $packageFullName = Get-PackageFullName -Name $Name -Version $Version
    if ($ContainerName -eq "")
    {
      $containerName = Get-BlobContainerName
    }
    $accountName = Get-BlobAccountName

    $edgeUrl = -join("https://", $accountName, ".azureedge.net", "/", $containerName, "/", $packageFullName)
    return $edgeUrl
}

#####################################################################################################
# Get-BlobPackageBaseUrl
#####################################################################################################


<#
    .SYNOPSIS
        Gets the CDN URL for a given blob package and version.
    .DESCRIPTION
        The binary blob store that CDPX uses is replicated to an anonymous CDN. This enables
        packages to be fetched much faster. This function returns the CDN URL to use.
    .NOTE
        This is only valid for actual blobs; not for containers that can be used with AzCopy.
    .OUTPUTS
        The CDN URL for this package.
#>
function Get-BlobPackageBaseUrl
{
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ContainerName
    )

    if ($ContainerName -eq "")
    {
      $containerName = Get-BlobContainerName
    }
  
    $accountName = Get-BlobAccountName

    $edgeUrl = -join("https://", $accountName, ".blob.core.windows.net", "/", $containerName)
    return $edgeUrl
}

#####################################################################################################
# Get-PackageFullName
#####################################################################################################

<#
    .SYNOPSIS
        Gets the full name of a blob or universal package that can be downloaded by the functions
        in this module.
    .DESCRIPTION
        Given a package name and a version, returns a full name to the package for use with 
        AzCopy or Az UPack CLI. The returned version is packagename-packageversion in lower case.
    .OUTPUTS
        The name of the package to use with blob store.
#>

function Get-PackageFullName
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Version
    )

    $packageFullName = -join($Name, "-", $Version)
    return $packageFullName.ToLowerInvariant()
}

#####################################################################################################
# Get-LatestInstalledNetFrameworkVersion
#####################################################################################################

<#
    .SYNOPSIS
        Gets the latest installed version of the .NET Framework.
    .DESCRIPTION
        Retrieves information from the registry based on the documentation at this link:
        https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed#net_b.
        Returns the entire child object from the registry.
    .OUTPUTS
        The child registry entry for the .NET framework installation.
#>
function Get-LatestInstalledNetFrameworkVersion
{
    Trace-Message -Message "Retrieving latest installed .NET Framework version from registry entry: HKLM:`\SOFTWARE`\Microsoft`\NET Framework Setup`\NDP`\v4`\Full"

    $item = Get-ChildItem HKLM:"\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"

    return $item
}

#####################################################################################################
# Run-VisualStudioInstallerProcessMonitor
#####################################################################################################

<#
    .SYNOPSIS
        Monitors progress of Visual Studio installation.
    .DESCRIPTION
        Checks if VS installer processes named vs_installer or vs_enteprise are still running.
        Returns true if processes with those names were found. Otherwise returns false. In addition,
        lists all dd_setup* log files found in $Env:TEMP where VS installers traditionally place
        log files. Finally, if any error log files are present, prints out the contents of those
        files.
    .OUTPUTS
        True if VS installer or bootstrapper processes are still running. Otherwise false.
#>
function Run-VisualStudioInstallerProcessMonitor
{
    Write-Host $Separator

    $processes = Get-Process
    $numTotalProcesses = 0
    $numVSIProcesses = 0

    $processes | ForEach-Object {

        $process = $_
        $handle = $process.Handle
        $pid = $process.Id
        $ppath = $process.Path

        if ($process.Name.StartsWith("vs_installer") -or
            $process.Name.StartsWith("vs_enterprise"))
        {
            $numVSIProcesses++

            Trace-Message -Message "Found VS Installer process with PID $pid launched from $ppath"
        }
        
        ++$numTotalProcesses
    }

    Trace-Message "Total processes: $numTotalProcesses. VS Installer processes: $numVSIProcesses"

    $setupLogs = Get-ChildItem $Env:TEMP -Filter "dd_setup*.log"
    $setupLogs | Write-Host 
    
    $setupLogs | ForEach-Object {
        
        $setupLog = $_
        $setupLogPath = $setupLog.FullName

        if ($setupLog.Name.Contains("errors"))
        {
            Trace-Message "Contents of VS installer error log: $setupLogPath"
            Get-Content -Path $setupLogPath | Write-Host 
        }
    }

    Write-Host $Separator

    if ($numVSIProcesses -gt 0)
    {
        return $true
    }

    return $false
}

#####################################################################################################
# Monitor-VisualStudioInstallation
#####################################################################################################

<#
#>
function Monitor-VisualStudioInstallation
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$WaitBefore,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$WaitAfter
    )

    $minutes = $WaitBefore

    while ($minutes -gt 0)
    {
        Trace-Message -Message "WAITING for VS installer kickoff." 

        Run-VisualStudioInstallerProcessMonitor

        Sleep -Seconds 60

        --$minutes
    }

    $minutes = $WaitAfter

    while ($minutes -gt 0)
    {
        Trace-Message -Message "WAITING for VS installer kickoff." 

        $ex = Run-VisualStudioInstallerProcessMonitor

        if (-not $ex)
        {
            Trace-Message -Message "DONE Looks like VS installer processes are no longer running."
            break
        }

        Sleep -Seconds 120

        --$minutes
    }
}