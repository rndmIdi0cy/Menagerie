# Menagerie

A CrowdStrike Response script for doing simple intial triage and data collection from a system (autorun information, installedsoftware, files and hashes, etc..)

Create a new script via Configuration -> Response Scripts & Files and name it Menagerie

```
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

Examples:
  runscript -CloudFile='Menagerie' -CommandLine='-module all'
  runscript -CloudFile='Menagerie' -CommandLine='-module Services'"
```

