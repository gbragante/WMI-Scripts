param( [string]$DataPath, [switch]$AcceptEula )

$version = "Evt-Collect (20211118)"
# by Gianni Bragante - gbrag@microsoft.com

Function EvtLogDetails {
  param(
    [string] $LogName
  )
  Write-Log ("Collecting the details for the " + $LogName + " log")
  $cmd = "wevtutil gl """ + $logname + """ >>""" + $global:resDir + "\EventLogs.txt""" + $RdrErr
  Write-Log $cmd
  Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

  "" | Out-File -FilePath ($global:resDir + "\EventLogs.txt") -Append

  if ($logname -ne "ForwardedEvents") {
    $evt = (Get-WinEvent -Logname $LogName -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue)
    if ($evt) {
      "Oldest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -FilePath ($global:resDir + "\EventLogs.txt") -Append
      $evt = (Get-WinEvent -Logname $LogName -MaxEvents 1)
      "Newest " + $evt.TimeCreated + " (" + $evt.RecordID + ")" | Out-File -FilePath ($global:resDir + "\EventLogs.txt") -Append
      "" | Out-File -FilePath ($global:resDir + "\EventLogs.txt") -Append
    }
  }
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
Import-Module ($global:Root + "\Collect-Commons.psm1") -Force -DisableNameChecking

Deny-IfNotAdmin

$resName = "Evt-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)

if ($DataPath) {
  if (-not (Test-Path $DataPath)) {
    Write-Host "The folder $DataPath does not exist"
    exit
  }
  $global:resDir = $DataPath + "\" + $resName
} else {

  $global:resDir = $global:Root + "\" + $resName
}
New-Item -itemtype directory -path $global:resDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

$RdrOut =  " >>""" + $global:outfile + """"
$RdrErr =  " 2>>""" + $global:errfile + """"
$fqdn = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName

$OSVer = ([environment]::OSVersion.Version.Major) + ([environment]::OSVersion.Version.Minor) /10

Write-Log $version
if ($AcceptEula) {
  Write-Log "AcceptEula switch specified, silently continuing"
  $eulaAccepted = ShowEULAIfNeeded "Evt-Collect" 2
} else {
  $eulaAccepted = ShowEULAIfNeeded "Evt-Collect" 0
  if($eulaAccepted -ne "Yes") {
    Write-Log "EULA declined, exiting"
    exit
  }
}
Write-Log "EULA accepted, continuing"

Write-Log "Collecting dump of the svchost process hosting the EventLog service"
$pidEventLog = FindServicePid "EventLog"
if ($pidEventLog) {
  CreateProcDump $pidEventLog $global:resDir "scvhost-EventLog"
}

Invoke-CustomCommand -Command "ipconfig /all" -DestinationFile "ipconfig.txt"

Write-Log "Collecing GPResult output"
$cmd = "gpresult /h """ + $global:resDir + "\gpresult.html""" + $RdrErr
write-log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "gpresult /r >""" + $global:resDir + "\gpresult.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Collecing Auditpol output"
$cmd = "auditpol /get /category:* > """ + $global:resDir + "\auditpol.txt""" + $RdrErr
write-log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Checking lost events for each EventLog etw session"
("EventLog-Application : " + (Get-Counter -Counter "\Event Tracing for Windows Session(EventLog-Application)\Events Lost").CounterSamples[0].CookedValue) | Out-File -FilePath ($global:resDir + "\EventsLost.txt") -Append
("EventLog-System : " + (Get-Counter -Counter "\Event Tracing for Windows Session(EventLog-System)\Events Lost").CounterSamples[0].CookedValue) | Out-File -FilePath ($global:resDir + "\EventsLost.txt") -Append
("EventLog-Security : " + (Get-Counter -Counter "\Event Tracing for Windows Session(EventLog-Security)\Events Lost").CounterSamples[0].CookedValue) | Out-File -FilePath ($global:resDir + "\EventsLost.txt") -Append
if (Get-AutologgerConfig "EventLog-ForwardedEvents" -ErrorAction SilentlyContinue) {
  ("EventLog-ForwardedEvents : " + (Get-Counter -Counter "\Event Tracing for Windows Session(EventLog-ForwardedEvents)\Events Lost").CounterSamples[0].CookedValue) | Out-File -FilePath ($global:resDir + "\EventsLost.txt") -Append
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger """ + $global:resDir + "\WMI-Autologger.reg.txt"" /y " + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels """+ $global:resDir + "\WINEVT-Channels.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers """+ $global:resDir + "\WINEVT-Publishers.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog """+ $global:resDir + "\EventLog-Policies.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog"
$cmd = "reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog """+ $global:resDir + "\EventLogService.reg.txt"" /y" + $RdrOut + $RdrErr
Write-Log $cmd
Invoke-Expression $cmd

if ((Get-Service EventLog).Status -eq "Running") {
  Export-EventLog -LogName "Application"
  Export-EventLog -LogName "System"

  Write-Log "Exporting Kernel-EventTracing log"
  $cmd = "wevtutil epl ""Microsoft-Windows-Kernel-EventTracing/Admin"" """+ $global:resDir + "\" + $env:computername + "-EventTracing.evtx""" + $RdrOut + $RdrErr
  Write-Log $cmd
  Invoke-Expression $cmd
  ArchiveLog "EventTracing"

  EvtLogDetails "Application"
  EvtLogDetails "System"
  EvtLogDetails "Security"
  EvtLogDetails "HardwareEvents"
  EvtLogDetails "Internet Explorer"
  EvtLogDetails "Key Management Service"
  EvtLogDetails "Windows PowerShell"
} else {
  Write-Log "Copying Application log"
  if (Test-path -path C:\Windows\System32\winevt\Logs\Application.evtx) {
    Copy-Item C:\Windows\System32\winevt\Logs\Application.evtx ($global:resDir + "\" + $env:computername + "-Application.evtx") -ErrorAction Continue 2>>$global:errfile
  }
  Write-Log "Copying System log"
  if (Test-path -path C:\Windows\System32\winevt\Logs\System.evtx) {
    Copy-Item C:\Windows\System32\winevt\Logs\System.evtx ($global:resDir + "\" + $env:computername + "-System.evtx") -ErrorAction Continue 2>>$global:errfile
  }
}

Write-Log "Checking permissions of the C:\Windows\System32\winevt\Logs folder"
$cmd = "cacls C:\Windows\System32\winevt\Logs >>""" + $global:resDir + "\Permissions.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

Write-Log "Checking permissions of the C:\Windows\System32\LogFiles\WMI\RtBackup folder"
$cmd = "cacls C:\Windows\System32\LogFiles\WMI\RtBackup >>""" + $global:resDir + "\Permissions.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

try {
  Write-Log "Getting a copy of the RTBackup folder"
  Copy-Item "C:\Windows\System32\LogFiles\WMI\RtBackup" -Recurse $global:resDir -ErrorAction SilentlyContinue
}
catch {
  Write-Log "Cannot access the RTBackup folder, please run the script as SYSTEM with PSExec"
}

Write-Log "Listing evtx files"
Get-ChildItem $env:windir\System32\winevt\Logs -Recurse | Out-File $global:resDir\WinEvtLogs.txt

Write-Log "Listing RTBackup folder"
Get-ChildItem $env:windir\System32\LogFiles\WMI\RtBackup -Recurse | Out-File $global:resDir\RTBackup.txt

$cmd = "logman -ets query ""EventLog-Application"" >""" + $global:resDir + "\EventLog-Application.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "logman -ets query ""EventLog-System"" >""" + $global:resDir + "\EventLog-System.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "logman query providers >""" + $global:resDir + "\QueryProviders.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "logman query -ets >""" + $global:resDir + "\QueryETS.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

$cmd = "wevtutil el >""" + $global:resDir + "\EnumerateLogs.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $global:outfile -Append

ExpRegFeatureManagement

Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
  $Owner = @{N="User";E={(GetOwnerCim($_))}}
} else {
  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
  $Owner = @{N="User";E={(GetOwnerWmi($_))}}
}

if ($proc) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
  @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
  @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
  @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, $StartTime, $Owner, CommandLine |
  Out-String -Width 500 | Out-File -FilePath ($global:resDir + "\processes.txt")

  Write-Log "Retrieving file version of running binaries"
  $binlist = $proc | Group-Object -Property ExecutablePath
  foreach ($file in $binlist) {
    if ($file.Name) {
      FileVersion -Filepath ($file.name) -Log $true
    }
  }

  Write-Log "Collecting services details"
  $svc = ExecQuery -NameSpace "root\cimv2" -Query "select  ProcessId, DisplayName, StartMode,State, Name, PathName, StartName from Win32_Service"

  if ($svc) {
    $svc | Sort-Object DisplayName | Format-Table -AutoSize -Property ProcessId, DisplayName, StartMode,State, Name, PathName, StartName |
    Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\services.txt")
  }

  CollectSystemInfoWMI
  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  CollectSystemInfoNoWMI
  Write-Log "Exiting since WMI is not working"
}

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn -ErrorAction SilentlyContinue | Out-File $global:resDir\hotfixes.txt

Write-Log "Exporting driverquery /v output"
$cmd = "driverquery /v >""" + $global:resDir + "\drivers.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append