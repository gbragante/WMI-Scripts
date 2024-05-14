param( 
  [string]$DataPath,
  [switch]$AcceptEula,
  [switch]$Logs,
  [switch]$Trace,
  [string]$StartAt,
  [string]$Duration,
  [switch]$Auth
)

$version = "Sched-Collect (20231031)"
<# 
  Created by Gianni Bragante - gbrag@microsoft.com

  Updates:
      2023-10-31 Marius Porcolean (maporcol@microsoft.com)
          - Added new flag parameter -Auth
          - This new parameter adds authentication related tracing providers to the main trace
          - A bunch of automatic cosmetic/formatting changes (spaces, lines, etc)

#>

Function SchedTraceCapture {
  if ($DateStart) {
    $diff = New-TimeSpan -Start (Get-Date) -End $DateStart # Recalculating the difference because the user may have been taking time to read the EULA
    if ($diff.TotalSeconds -lt 0) {
      $waitSeconds = 0
    }
    else {
      $waitSeconds = [int]$diff.TotalSeconds
    }
    Write-Log ("Waiting " + $waitSeconds + " seconds until $DateStart")
    Start-Sleep -Seconds $waitSeconds
  }

  Invoke-CustomCommand ("logman create trace 'Sched-Trace' -ow -o '" + $TracesDir + "Sched-Trace-$env:COMPUTERNAME.etl" + "' -p '{6A187A25-2325-45F4-A928-B554329EBD51}' 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets")

  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{A7C8D6F2-1088-484B-A516-1AE0C3BF8216}' 0xffffffffffffffff 0xff -ets" # SchedWmiGuid
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{10FF35F4-901F-493F-B272-67AFB81008D4}' 0xffffffffffffffff 0xff -ets" # Microsoft.Windows.TaskScheduler
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{1D665082-C852-4AB0-A1B2-C26488454C41}' 0xffffffffffffffff 0xff -ets" # UBPM
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{047311A9-FA52-4A68-A1E4-4E289FBB8D17}' 0xffffffffffffffff 0xff -ets" # JobCtlGuid
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-TaskScheduler
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{42695762-EA50-497A-9068-5CBBB35E0B95}' 0xffffffffffffffff 0xff -ets" # Windows Notification Facility Provider
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{0657ADC1-9AE8-4E18-932D-E6079CDA5AB3}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-TimeBroker
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{E8109B99-3A2C-4961-AA83-D1A7A148ADA8}' 0xffffffffffffffff 0xff -ets" # BrokerCommon
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{19043218-3029-4BE2-A6C1-B6763CECB3CC}' 0xffffffffffffffff 0xff -ets" # EventAggregation
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{077E5C98-2EF4-41D6-937B-465A791C682E}' 0xffffffffffffffff 0xff -ets" # DAB/Desktop Activity Broker
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{B6BFCC79-A3AF-4089-8D4D-0EECB1B80779}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-SystemEventsBroker
  Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{E6835967-E0D2-41FB-BCEC-58387404E25A}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-BrokerInfrastructure

  if ($Auth) {
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{199FE037-2B82-40A9-82AC-E1D46C792B99}' 0xffffffffffffffff 0xff -ets" # LsaSrv
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{CC85922F-DB41-11D2-9244-006008269001}' 0xffffffffffffffff 0xff -ets" # Local Security Authority (LSA)
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{4D9DFB91-4337-465A-A8B5-05A27D930D48}' 0xffffffffffffffff 0xff -ets" # LsaSrvTraceLogger
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{A4E69072-8572-4669-96B7-8DB1520FC93A}' 0xffffffffffffffff 0xff -ets" # LsaIsoTraceProv
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{366B218A-A5AA-4096-8131-0BDAFCC90E93}' 0xffffffffffffffff 0xff -ets" # LsaIsoTraceControlGuid
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{1F678132-5938-4686-9FDC-C8FF68F15C85}' 0xffffffffffffffff 0xff -ets" # Schannel
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{37D2C3CD-C5D4-4587-8531-4696C44244C8}' 0xffffffffffffffff 0xff -ets" # Security: SChannel
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{DDDC1D91-51A1-4A8D-95B5-350C4EE3D809}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-AuthenticationProvider
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{6B510852-3583-4E2D-AFFE-A67F9F223438}' 0xffffffffffffffff 0xff -ets" # Security: Kerberos Authentication
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}' 0xffffffffffffffff 0xff -ets" # Active Directory: Kerberos Client
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{98E6CFCB-EE0A-41E0-A57B-622D4E1B30B1}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-Security-Kerberos
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{6165F3E2-AE38-45D4-9B23-6B4818758BD9}' 0xffffffffffffffff 0xff -ets" # Security: TSPkg
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{AC43300D-5FCC-4800-8E99-1BD3F85F0320}' 0xffffffffffffffff 0xff -ets" # Microsoft-Windows-NTLM
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{C92CF544-91B3-4DC0-8E11-C580339A0BF8}' 0xffffffffffffffff 0xff -ets" # NTLM Security Protocol
    Invoke-CustomCommand "logman update trace 'Sched-Trace' -p '{5BBB6C18-AA45-49B1-A15F-085F7ED0AA90}' 0xffffffffffffffff 0xff -ets" # Security: NTLM Authentication
  }

  Write-Log "Trace capture started"
  if ($Duration) {
    Write-Log ("The capture will be stopped in " + $durSec + " seconds")
    Start-Sleep $durSec
  }
  else {
    read-host "Press ENTER to stop the capture"
  }
  Invoke-CustomCommand "logman stop 'Sched-Trace' -ets"  
  Invoke-CustomCommand "tasklist /svc" -DestinationFile "Traces\tasklist-$env:COMPUTERNAME.txt"
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
$resName = "Sched-Results-" + $env:computername + "-" + $(get-date -f yyyyMMdd_HHmmss)

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
}
else {
  $global:resDir = $global:Root + "\" + $resName
}

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

if (-not $Trace -and -not $Logs) {
  Write-Host "$version, a data collection tool for Task Scheduler troubleshooting"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "Sched-Collect -Logs"
  Write-Host "  Collects dumps, logs, registry keys, command outputs"
  Write-Host ""
  Write-Host "Sched-Collect -Trace [-StartAt <YYYYMMDD-HHMMSS>] [-Duration <seconds>]"
  Write-Host "  Collects live trace"
  Write-Host ""
  Write-Host "Sched-Collect -Logs -Trace"
  Write-Host "  Collects live trace then -Logs data"
  Write-Host ""
  Write-Host "Parameters for -Trace"
  Write-Host "  -StartAt : Will start the trace at the specified date/time"
  Write-Host "  -Duration : Stops the trace after the specified numner of seconds"
  Write-Host "  -Auth : Adds many authentication related tracing providers to the main trace"
  exit
}

if ($Trace -and $StartAt) {
  try {
    $DateStart = Get-Date -Year $StartAt.Substring(0, 4) -Month $StartAt.Substring(4, 2) -Day $StartAt.Substring(6, 2) -Hour $StartAt.Substring(9, 2) -Minute $StartAt.Substring(11, 2) -Second $StartAt.Substring(13, 2)
    Write-Host $DateStart
  }
  catch {
    Write-Host "Invalid date $StartAt"
    exit
  }
  $diff = New-TimeSpan -Start (Get-Date) -End $DateStart
  if ($diff.TotalSeconds -lt 0) {
    Write-Host "The specified date $DateStart is in the past"
    exit
  }
}

if ($Trace -and $Duration) {
  try {
    $durSec = [int]$Duration
  }
  catch {
    Write-Host "Invalid value for duration : $duration"
    exit
  }
  if ($durSec -lt 0) {
    Write-Host "Specified value for duration is less than 0"
    exit
  }
}

New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "Sched-Collect" 2
}
else {
  $eulaAccepted = ShowEULAIfNeeded "Sched-Collect" 0
  if ($eulaAccepted -ne "Yes") {
    Write-Log "EULA declined, exiting"
    exit
  }
}
Write-Log "EULA accepted, continuing"

if ($Trace) {
  $TracesDir = $global:resDir + "\Traces\"
  New-Item -itemtype directory -path $TracesDir | Out-Null
  SchedTraceCapture
  if (-not $Logs) {
    exit
  }
}

$pidsvc = (ExecQuery -Namespace "root\cimv2" -Query "select ProcessID from win32_service where Name='Schedule'").ProcessId
if ($pidsvc) {
  Write-Log "Collecting dump of the svchost process hosting the Schedule service"
  CreateProcDump $pidsvc $global:resDir "scvhost-Schedule"
}
else {
  Write-Log "Schedule service PID not found"
}

$pidsvc = (ExecQuery -Namespace "root\cimv2" -Query "select ProcessID from win32_service where Name='SystemEventsBroker'").ProcessId
if ($pidsvc) {
  Write-Log "Collecting dump of the svchost process hosting the System Events Broker service"
  CreateProcDump $pidsvc $global:resDir "scvhost-SystemEventsBroker"
}
else {
  Write-Log "System Events Broker service PID not found"
}

# $tasks = Get-ScheduledTask
# $tasks | Out-File -FilePath ($global:resDir + "\Tasks.txt" )

Write-Log "Exporting tasks information"

$tbTasks = New-Object system.Data.DataTable
$col = New-Object system.Data.DataColumn Path, ([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn Name, ([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn Enabled, ([boolean]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn State, ([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastRunTime, ([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn LastResult, ([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn NextRunTime, ([string]); $tbTasks.Columns.Add($col)
$col = New-Object system.Data.DataColumn Maintenance, ([string]); $tbTasks.Columns.Add($col)

$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
  $info = Get-ScheduledTaskInfo $task
  $row = $tbTasks.NewRow()
  $row.Path = $task.TaskPath
  $row.Name = $task.TaskName
  $row.Enabled = $task.Settings.Enabled
  $row.State = $task.State
  $row.LastRunTime = $info.LastRunTime
  if ($info.LastTaskResult -ne 0) {
    $row.LastResult = ( $info.LastTaskResult.ToString() + " " + (DecodeError $info.LastTaskResult))
  }
  $row.NextRunTime = $info.NextRunTime
  if ($task.Settings.MaintenanceSettings) {
    $row.Maintenance = "Yes" 
  }
  else {
    $row.Maintenance = "No" 
  } 
  $tbTasks.Rows.Add($row)
}
$tbTasks | Export-Csv ($global:resDir + "\Tasks.csv" ) -NoTypeInformation

Write-Log "Copying C:\Windows\Tasks"
Copy-Item "C:\Windows\Tasks" -Recurse ($global:resDir + "\Windows-Tasks")

Write-Log "Copying C:\Windows\System32\Tasks"
Copy-Item "C:\Windows\System32\Tasks" -Recurse ($global:resDir + "\System32-Tasks")

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule"" """ + $global:resDir + "\Schedule.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data"" """ + $global:resDir + "\NotificationsData.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State"" """ + $global:resDir + "\SetupState.reg.txt"" /y >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

ExpRegFeatureManagement

Invoke-CustomCommand -Command "WHOAMI /all" -DestinationFile "WHOAMI.txt"
Invoke-CustomCommand -Command "cmdkey /list" -DestinationFile "cmdkeyList.txt"

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """ + $global:resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """ + $global:resDir + "\" + $env:computername + "-System.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting TaskScheduler/Maintenance log"
$cmd = "wevtutil epl Microsoft-Windows-TaskScheduler/Maintenance """ + $global:resDir + "\" + $env:computername + "-TaskScheduler-Maintenance.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "TaskScheduler-Maintenance"

Write-Log "Exporting TaskScheduler/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-TaskScheduler/Operational """ + $global:resDir + "\" + $env:computername + "-TaskScheduler-Operational.evtx"" >>""" + $global:outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "TaskScheduler-Operational"

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex Schedule >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "sc.exe qc Schedule >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "sc.exe enumdepend Schedule 3000 >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "sc.exe sdshow Schedule >>""" + $global:resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecting details about running processes"
if (ListProcsAndSvcs) {
  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")

  Write-Log "Collecting the list of installed hotfixes"
  Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn | Out-File $global:resDir\hotfixes.txt

  Write-Log "Collecing GPResult output"
  $cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
  write-log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  $cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append
}
else {
  Write-Log "WMI is not working"
  $proc = Get-Process | Where-Object { $_.Name -ne "Idle" }
  $proc | Format-Table -AutoSize -property id, name, @{N = "WorkingSet"; E = { "{0:N0}" -f ($_.workingset / 1kb) }; a = "right" },
  @{N = "VM Size"; E = { "{0:N0}" -f ($_.VirtualMemorySize / 1kb) }; a = "right" },
  @{N = "Proc time"; E = { ($_.TotalProcessorTime.ToString().substring(0, 8)) } }, @{N = "Threads"; E = { $_.threads.count } },
  @{N = "Handles"; E = { ($_.HandleCount) } }, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
}

