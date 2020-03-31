Param (
    [Parameter(Mandatory = $false)]
    [string] $module
)

[string] $ComputerName = $Env:COMPUTERNAME
[string] $irPath = "C:\Windows\Temp"

if (!(Test-Path $irPath)) {
    mkdir -Path $irPath -Force
}


function usage {
    Write-Output "
    Usage:
      -module all           : run all modules
      -module <name>        : run specific module
      -folder <path>        : output folder [Default: C:\Windows\Temp]
      -module help          : display usage

    Modules:
      AutoRuns              : Gather files in common startup locations
      Services              : Gather Windows Services
      InstalledSoftware     : Gather Installed Software from Uninstall Key
      DNSCache              : Get clients local DNS cache
      RunningProcesses      : Get all running processes and hashes
      Prefetch              : Get list of files in prefetch
      PEFiles               : Get list of PE files and hashes in user writeable locations
      OfficeFiles           : Get list of office docs and hashes in user writeable locations
      ScriptFiles           : Get list of scripts and hashes in user writeable locations

    Examples:
      runscript -CloudFile='Menagerie' -CommandLine='-module all'
      runscript -CloudFile='Menagerie' -CommandLine='-module Services'"
}


function Get-AutoRuns {
    Write-Output "[+] Gathering Windows AutoRuns ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_AutoRuns.csv"
    $results = Get-CimInstance -Class Win32_StartupCommand | Select-Object Name, Caption, Description, Command, Location, User
    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-Services {
    Write-Output "[+] Gathering Windows Services ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_Services.csv"
    $results = Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Caption, Description, DisplayName, Name, PathName, ProcessId, StartMode, State, Status
    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-InstalledSoftware {
    Write-Output "[+] Gathering Installed Software ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_InstalledSoftware.csv"
    $regPaths = @("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\*")

    $results = @()
    foreach ($path in $regPaths) {
        $results = $results + (Get-ItemProperty -Path "Registry::$path" | Where-Object DisplayName -ne $null | Select-Object Publisher, DisplayName, DisplayVersion, InstallDate, InstallSource, InstallLocation)
    }

    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-DNSCache {
    Write-Output "[+] Gathering DNS Client Cache ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_DNSClientCache.csv"
    Get-DnsClientCache | Select-Object TTL, Data, DataLength, Entry, Name, TimeToLive, Type | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-RunningProcesses {
    Write-Output "[+] Gathering Running Processes ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_Processes.csv"

    $procs = Get-Process -IncludeUserName

    foreach ($proc in $procs) {
        $procInfo = Get-CimInstance Win32_Process | Where-Object ProcessID -eq $proc.Id | Select-Object -Property Path, CommandLine
        $proc | Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $procInfo.CommandLine
        $proc | Add-Member -MemberType NoteProperty -Name "Hash" -Value $procInfo.Path
    }

    $results = Get-Process | Select-Object Id, Name, ProcessName, Path, Hash, FileVersion, CommandLine, Company, Product, Description, StartTime
    $results | Export-CSV -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-Prefetch {
    Write-Output "[+] Gathering Prefetch Cache ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_Prefetch.csv"
    $results = Get-ChildItem -Path "C:\Windows\Prefetch\" | Select-Object Name, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc

    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-PEFiles {
    Write-Output "[+] Gathering list of PE files in TEMP locations ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_PEFiles.csv"

    $PEExtPattern = ".exe|.dll|.sys"
    $filePaths = @(
        "${env:TEMP}\*",
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
        "${env:windir}\Temp\*"
    )

    $peFiles = @()

    try {
        Foreach ($path in $filePaths) {
            Get-ChildItem -Force -Recurse -Path $path -Attributes !System, !ReparsePoint -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match $PEExtPattern } |
            ForEach-Object {
                $filePath = $_.FullName
                $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

                $peFiles += New-Object PSObject -Property @{
                    Hash     = $hash
                    FilePath = $filePath
                }
            }
        }
    }
    catch { }

    $peFiles | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-OfficeTextFiles {
    Write-Output "[+] Gathering list of Office files in TEMP locations ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_OfficeFiles.csv"

    $PEExtPattern = ".docx|.docm|.xlsx|.xlsm|.pptx|.pptm"
    $filePaths = @(
        "${env:TEMP}\*",
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
        "${env:windir}\Temp\*"
    )

    $peFiles = @()

    try {
        Foreach ($path in $filePaths) {
            Get-ChildItem -Force -Recurse -Path $path -Attributes !System, !ReparsePoint -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match $PEExtPattern } |
            ForEach-Object {
                $filePath = $_.FullName
                $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

                $peFiles += New-Object PSObject -Property @{
                    Hash     = $hash
                    FilePath = $filePath
                }
            }
        }
    }
    catch { }

    $peFiles | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-ScriptFiles {
    Write-Output "[+] Gathering list of Script files in TEMP locations ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_ScriptFiles.csv"

    $PEExtPattern = ".bat|.vbs|.cmd|.js|.com|.ps1|.psm|.psm1|.psd|.txt"
    $filePaths = @(
        "${env:TEMP}\*",
        "${env:USERPROFILE}\Downloads\*",
        "${env:USERPROFILE}\Documents\*",
        "${env:LOCALAPPDATA}\Microsoft\Windows\INetCache\Content.Outlook\*",
        "${env:windir}\Temp\*"
    )

    $peFiles = @()

    try {
        Foreach ($path in $filePaths) {
            Get-ChildItem -Force -Recurse -Path $path -Attributes !System, !ReparsePoint -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match $PEExtPattern } |
            ForEach-Object {
                $filePath = $_.FullName
                $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

                $peFiles += New-Object PSObject -Property @{
                    Hash     = $hash
                    FilePath = $filePath
                }
            }
        }
    }
    catch { }

    $peFiles | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Invoke-AllIRModules {
    Write-Output "[+] Running all IR modules ..."
    Get-AutoRuns
    Get-Services
    Get-InstalledSoftware
    Get-DNSCache
    Get-RunningProcesses
    Get-Prefetch
    Get-PEFiles
    Get-OfficeTextFiles
    Get-ScriptFiles
}

if ($module) {
    switch ($module.ToLower()) {
        all { Invoke-AllIRModules }
        autoruns { Get-AutoRuns($irPath) }
        installedsoftware { Get-InstalledSoftware }
        dnscache { Get-DNSCache }
        runningprocesses { Get-RunningProcesses }
        prefetch { Get-Prefetch }
        pefiles { Get-PEFiles }
        officefiles { Get-OfficeFiles }
        scriptfiles { Get-ScriptFiles }
        help { usage }
        default { usage }
    }
}
else {
    usage
    exit
}
