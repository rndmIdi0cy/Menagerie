Param (
    [Parameter(Mandatory = $false)]
    [string] $module,

    [Parameter(Mandatory = $false)]
    [string] $folder
)

[string] $date = Get-Date -Format yyyyMMddHHmmss
[string] $ComputerName = $Env:COMPUTERNAME

function usage {
    Write-Output "
    Usage:
      -module all           : run all modules
      -module <name>        : run specific module
      -folder <path>        : output folder [Default: C:\Windows\Temp\IR]
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
      EventLogs             : Gather Event Logs
      RecentFiles           : Get history of recent files
      LNKFiles              : Get LNK files on desktop and recent files list
      HiddenFilesDirs       : Get hidden files and directories
      WindowsUpdates        : Get installed windows updates
      BrowserExtensions     : Get list of extensions for Chrome and Firefox
      KrbSessions           : Get list of kerberos sessions

    Examples:
      runscript -CloudFile='Menagerie' -CommandLine='-module all'
      runscript -CloudFile='Menagerie' -CommandLine='-module Services'"
}


function Get-AutoRuns {
    Write-Output "[+] Gathering Windows AutoRuns ..."
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_AutoRuns.csv"
    $results = Get-CimInstance -Class Win32_StartupCommand | Select-Object Name, Caption, Description, Command, Location, User
    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-Services {
    Write-Output "[+] Gathering Windows Services ..."
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_Services.csv"
    $results = Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Caption, Description, DisplayName, Name, PathName, ProcessId, StartMode, State, Status
    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-InstalledSoftware {
    Write-Output "[+] Gathering Installed Software ..."
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_InstalledSoftware.csv"
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
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_DNSClientCache.csv"
    Get-DnsClientCache | Select-Object TTL, Data, DataLength, Entry, Name, TimeToLive, Type | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-RunningProcesses {
    Write-Output "[+] Gathering Running Processes ..."
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_Processes.csv"

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
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_Prefetch.csv"
    $results = Get-ChildItem -Path "C:\Windows\Prefetch\" -Filter *.pf -ErrorAction SilentlyContinue | Select-Object Name, FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc

    $results | Export-Csv -NoTypeInformation -Path $outputFile
    Write-Output "[ done ]"
}


function Get-PEFiles {
    Write-Output "[+] Gathering list of PE files in TEMP locations ..."
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_PEFiles.csv"

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
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_OfficeFiles.csv"

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
    $outputFile = Join-Path $Global:irPath "\${ComputerName}_ScriptFiles.csv"

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

function Get-EventLogs {
    Write-Output "[+] Gathering Event Logs ..."
    $ir_evtx_path = Join-Path $Global:irPath "\${ComputerName}_evtx"
    New-Item -Path $ir_evtx_path -Type Directory | Out-Null
    $evtx_files = Get-ChildItem -Path "C:\Windows\system32\winevt\logs\" -Filter *.evtx -ErrorAction SilentlyContinue

    foreach ($file in $evtx_files) {
        Copy-Item -Path $file.FullName -Destination $ir_evtx_path -ErrorAction SilentlyContinue
    }

    Write-Output "[ done ]"

}

function Get-RecentFiles {
    Write-Output "[+] Gathering Recent File Cache ..."
    $ir_recentfiles_path = Join-Path $Global:irPath "\${ComputerName}_RecentFiles"
    New-Item -Path $ir_recentfiles_path -Type Directory | Out-Null

    $recentfiles_path = "C:\Windows\AppCompat\Programs\RecentFileCache.bcf"

    if (Test-Path $recentfiles_path) {
        Copy-Item -Path $recentfiles_path -Destination $ir_recentfiles_path
    }

    Write-Output "[ done ]"
}

function Get-LnkFiles {
    Write-Output "[+] Gathering LNK files ..."
    $ir_lnkfiles_path = Join-Path $Global:irPath "\${ComputerName}_LnkFiles"
    New-Item -Path $ir_lnkfiles_path -Type Directory | Out-Null

    $lnkfiles_path = @("${env:LOCALAPPDATA}\Microsoft\Windows\Recent\", "${env:LOCALAPPDATA}\Microsoft\Office\Recent\", "C:\Users\*\Desktop\")

    foreach ($path in $lnkfiles_path) {
        $lnk_files = Get-ChildItem -Path $path -Filter *.lnk -Recurse -ErrorAction SilentlyContinue

        foreach ($file in $lnk_files) {
            Copy-Item -Path $file.FullName -Destination $ir_lnkfiles_path -ErrorAction SilentlyContinue
        }
    }
}

function Get-Hidden {
    Write-Output "[+] Gathering hidden files and directories ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_HiddenFilesDirs.csv"

    Get-ChildItem C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
}


function Get-InstalledWindowsUpdates {
    Write-Output "[+] Gathering installed Windows Updates and Hotfixes ..."
    $outputFileHotFixes = Join-Path $irPath "\${ComputerName}_WinHotfixes.csv"
    $outputFileWinUpdates = Join-Path $irPath "\${ComputerName}_WinUpdates.csv"

    Get-HotFix | Select-Object InstalledOn, InstalledBy, HotFixID, Description | Export-Csv -NoTypeInformation -Path $outputFileHotFixes
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Search("IsInstalled=1").Updates | Select-Object Title | Export-Csv -NoTypeInformation -Path $outputFileWinUpdates
}

function Get-BrowserExtensions {
    Write-Output "[+] Gathering browser extensions for all users and major browsers ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_BrowserExtensions.csv"
    $chromePath = "C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Extensions"
    $firefoxPath = "C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles"

    $extArray = @()

    # Chrome
    $chromeManifests = Get-ChildItem -Path $chromePath -Include manifest.json -Recurse -ErrorAction SilentlyContinue

    foreach ($manifest in $chromeManifests) {
        $info = Get-Content -Path $manifest.FullName -Raw | ConvertFrom-Json
        $manifest.FullName -match 'users\\(.*?)\\appdata' | Out-Null

        if ($matches) {
            $username = $matches[1]
        }
        else {
            $username = "N/A"
        }

        $extObject = New-Object -TypeName psobject
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Application -Value "Google Chrome"
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Username -Value $username
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name ExtensionName -Value $info.name
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Description -Value ($info.description -replace "`n", " ")
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Version -Value $info.version
        Add-Member -InputObject $extObject -MemberType NoteProperty -Name Path -Value $manifest.FullName

        $extArray += $extObject
    }

    # Firefox
    $firefoxProfiles = Get-ChildItem -Path $firefoxPath -Include addons.json -Recurse -ErrorAction SilentlyContinue

    foreach ($profile in $firefoxProfiles) {
        $info = Get-Content -Path $profile.FullName -Raw | ConvertFrom-Json
        $profile.FullName -match 'users\\(.*?)\\appdata' | Out-Null

        if ($matches) {
            $username = $matches[1]
        }
        else {
            $username = "N/A"
        }

        foreach ($addon in $info.addons) {
            $extObject = New-Object -TypeName psobject
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Application -Value "Firefox"
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Username -Value $username
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name ExtensionName -Value $addon.name
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Description -Value ($addon.description -replace "`n", " ")
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Version -Value $addon.version
            Add-Member -InputObject $extObject -MemberType NoteProperty -Name Path -Value $profile.FullName

            $extArray += $extObject
        }
    }

    $extArray | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
}

function Get-KrbSessions {
    Write-Output "[+] Gathering klist sessions ..."
    $outputFile = Join-Path $irPath "\${ComputerName}_klistsessions.csv"

    $sessions = klist sessions
    $klistArray = @()

    foreach ($session in $sessions) {
        $listNumber = ($session.split(' ')[0] -replace "`n", "")
        $sessionNumber = ($session.split(' ')[2] -replace "`n", "")
        $logonId = ($session.split(' ')[3] -replace "0:", "" -replace "`n", "")
        $identity = ($session.split(' ')[4] -replace "`n", "")
        $authType = ($session.split(' ')[5] -replace "`n", "")

        $klistObject = New-Object -TypeName psobject
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name ListNumber -Value $listNumber
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name SessionNumber -Value $sessionNumber
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name LogonId -Value $logonId
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name Identity -Value $identity
        Add-Member -InputObject $klistObject -MemberType NoteProperty -Name AuthType -Value $authType

        $klistArray += $klistObject
    }

    $klistArray | Export-Csv -Path $outputFile -NoTypeInformation
    Write-Output "[ done ]"
    Write-Output "[*] Session List"
    $sessions
    Write-Output ""
    Write-Output "To view further details run: klist -li [logon_id]"
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
    Get-EventLogs
    Get-RecentFiles
    Get-LnkFiles
    Get-Hidden
    Get-InstalledWindowsUpdates
    Get-BrowserExtensions
    Get-KrbSessions
}

if ($module) {
    if ($folder) {
        if (-Not (Test-Path $folder)) {
            New-Item -Path $folder -Type Directory -Force | Out-Null
        }

        $Global:irPath = $folder
    }
    else {
        $Global:irPath = "C:\Windows\Temp\IR"
    }

    switch ($module.ToLower()) {
        all { Invoke-AllIRModules }
        autoruns { Get-AutoRuns }
        installedsoftware { Get-InstalledSoftware }
        dnscache { Get-DNSCache }
        runningprocesses { Get-RunningProcesses }
        prefetch { Get-Prefetch }
        pefiles { Get-PEFiles }
        officefiles { Get-OfficeFiles }
        scriptfiles { Get-ScriptFiles }
        eventlogs { Get-EventLogs }
        recentfiles { Get-RecentFiles }
        lnkfiles { Get-LnkFiles }
        hiddenfiles { Get-Hidden }
        windowsupdates { Get-InstalledWindowsUpdates }
        browserextensions { Get-BrowserExtensions }
        krbsessions { Get-KrbSessions }
        help { usage }
        default { usage }
    }
}
else {
    usage
    exit
}
