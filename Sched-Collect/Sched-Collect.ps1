param( [string]$Path )

$version = "Sched-Collect (20191023)"
# by Gianni Bragante - gbrag@microsoft.com

Function Write-Log {
  param( [string] $msg )
  $msg = (get-date).ToString("yyyyMMdd HH:mm:ss.fff") + " " + $msg
  Write-Host $msg
  $msg | Out-File -FilePath $outfile -Append
}

Function ExecQuery {
  param(
    [string] $NameSpace,
    [string] $Query
  )
  Write-Log ("Executing query " + $Query)
  if ($PSVersionTable.psversion.ToString() -ge "3.0") {
    $ret = Get-CimInstance -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  } else {
    $ret = Get-WmiObject -Namespace $NameSpace -Query $Query -ErrorAction Continue 2>>$errfile
  }
  Write-Log (($ret | measure).count.ToString() + " results")
  return $ret
}

Function ArchiveLog {
  param( [string] $LogName )
  $cmd = "wevtutil al """+ $resDir + "\" + $env:computername + "-" + $LogName + ".evtx"" /l:en-us >>""" + $outfile + """ 2>>""" + $errfile + """"
  Write-Log $cmd
  Invoke-Expression $cmd
}

Function Win10Ver {
  param(
    [string] $Build
  )
  if ($build -eq 14393) {
    return " (RS1 / 1607)"
  } elseif ($build -eq 15063) {
    return " (RS2 / 1703)"
  } elseif ($build -eq 16299) {
    return " (RS3 / 1709)"
  } elseif ($build -eq 17134) {
    return " (RS4 / 1803)"
  } elseif ($build -eq 17763) {
    return " (RS5 / 1809)"
  } elseif ($build -eq 18362) {
    return " (19H1 / 1903)"
  } elseif ($build -eq 18363) {
    return " (19H2 / 1909)" 
  }
}

Add-Type -MemberDefinition @"
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern uint NetApiBufferFree(IntPtr Buffer);
[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern int NetGetJoinInformation(
  string server,
  out IntPtr NameBuffer,
  out int BufferType);
"@ -Namespace Win32Api -Name NetApi32

function GetNBDomainName {
  $pNameBuffer = [IntPtr]::Zero
  $joinStatus = 0
  $apiResult = [Win32Api.NetApi32]::NetGetJoinInformation(
    $null,               # lpServer
    [Ref] $pNameBuffer,  # lpNameBuffer
    [Ref] $joinStatus    # BufferType
  )
  if ( $apiResult -eq 0 ) {
    [Runtime.InteropServices.Marshal]::PtrToStringAuto($pNameBuffer)
    [Void] [Win32Api.NetApi32]::NetApiBufferFree($pNameBuffer)
  }
}

Function FileVersion {
  param(
    [string] $FilePath,
    [bool] $Log = $false
  )
  if (Test-Path -Path $FilePath) {
    $fileobj = Get-item $FilePath
    $filever = $fileobj.VersionInfo.FileMajorPart.ToString() + "." + $fileobj.VersionInfo.FileMinorPart.ToString() + "." + $fileobj.VersionInfo.FileBuildPart.ToString() + "." + $fileobj.VersionInfo.FilePrivatepart.ToString()

    if ($log) {
      ($FilePath + "," + $filever + "," + $fileobj.CreationTime.ToString("yyyyMMdd HH:mm:ss")) | Out-File -FilePath ($resDir + "\FilesVersion.csv") -Append
    }
    return $filever | Out-Null
  } else {
    return ""
  }
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

Write-Host "This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows."
Write-Host "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names."
Write-Host "Once the tracing and data collection has completed, the script will save the data in a subfolder. This folder is not automatically sent to Microsoft."
Write-Host "You can send this folder to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have."
Write-Host "Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy"
$confirm = Read-Host ("Are you sure you want to continue[Y/N]?")
if ($confirm.ToLower() -ne "y") {exit}


$Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
if ($Path) {
  if (-not (Test-Path $path)) {
    Write-Host "The folder $Path does not esist"
    exit
  }
  $resDir = $Path
} else {
  $resName = "Sched-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
  $resDir = $Root + "\" + $resName
  New-Item -itemtype directory -path $resDir | Out-Null
}

$outfile = $resDir + "\script-output.txt"
$errfile = $resDir + "\script-errors.txt"

if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
  $procdump = "procdump64.exe"
} else {
  $procdump = "procdump.exe"
}
if (-not (Test-Path ($root + "\" + $procdump))) {
  $confirm = Read-Host ("The file " + $root + "\" + $procdump + " does not exist, the process dumps cannot be collected.`r`nDo you want to continue ? [Y / N]")
  if ($confirm.ToLower() -ne "y") {exit}
}

Write-Log $version
Write-Log "Collecting dump of the svchost process hosting the Schedule service"
$cmd = "&""" + $Root + "\" +$procdump + """ -accepteula -ma Schedule """ + $resDir + "\Svchost.exe-Schedule.dmp"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

$tasks = Get-ScheduledTask
$tasks | Out-File -FilePath ($resDir + "\Tasks.txt" )

Write-Log "Copying C:\Windows\Tasks"
Copy-Item "C:\Windows\Tasks" -Recurse ($resDir + "\Windows-Tasks")

Write-Log "Copying C:\Windows\System32\Tasks"
Copy-Item "C:\Windows\System32\Tasks" -Recurse ($resDir + "\System32-Tasks")

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule"
$cmd = "reg export ""HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule"" """+ $resDir + "\Schedule.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting TaskScheduler/Maintenance log"
$cmd = "wevtutil epl Microsoft-Windows-TaskScheduler/Maintenance """+ $resDir + "\" + $env:computername + "-TaskScheduler-Maintenance.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "TaskScheduler-Maintenance"

Write-Log "Exporting TaskScheduler/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-TaskScheduler/Operational """+ $resDir + "\" + $env:computername + "-TaskScheduler-Operational.evtx"" >>""" + $outfile + """ 2>>""" + $errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "TaskScheduler-Operational"

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex Schedule >>""" + $resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe qc Schedule >>""" + $resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe enumdepend Schedule 3000 >>""" + $resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe sdshow Schedule >>""" + $resDir + "\ScheduleServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

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
  Out-String -Width 500 | Out-File -FilePath ($resDir + "\processes.txt")

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
    Out-String -Width 400 | Out-File -FilePath ($resDir + "\services.txt")
  }

  Write-Log "Collecting system information"
  $pad = 27
  $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles, MUILanguages from Win32_OperatingSystem"
  $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
  $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
  $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
  $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

  $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction Continue 2>>$errfile
  $PoolPaged = $ctr.CounterSamples[0].CookedValue 
  $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction Continue 2>>$errfile
  $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

  "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Build Number".PadRight($pad) + " : " + $OS.BuildNumber + "." + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ubr + (Win10Ver $OS.BuildNumber)| Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Language packs".PadRight($pad) + " : " + ($OS.MUILanguages -join " ") | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
  $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
  "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append

  $drives = @()
  $drvtype = "Unknown", "No Root Directory", "Removable Disk", "Local Disk", "Network Drive", "Compact Disc", "RAM Disk"
  $Vol = ExecQuery -NameSpace "root\cimv2" -Query "select * from Win32_LogicalDisk"
  foreach ($disk in $vol) {
    $drv = New-Object PSCustomObject
    $drv | Add-Member -type NoteProperty -name Letter -value $disk.DeviceID 
    $drv | Add-Member -type NoteProperty -name DriveType -value $drvtype[$disk.DriveType]
    $drv | Add-Member -type NoteProperty -name VolumeName -value $disk.VolumeName 
    $drv | Add-Member -type NoteProperty -Name TotalMB -Value ($disk.size)
    $drv | Add-Member -type NoteProperty -Name FreeMB -value ($disk.FreeSpace)
    $drives += $drv
  }
  $drives | 
  Format-Table -AutoSize -property Letter, DriveType, VolumeName, @{N="TotalMB";E={"{0:N0}" -f ($_.TotalMB/1MB)};a="right"}, @{N="FreeMB";E={"{0:N0}" -f ($_.FreeMB/1MB)};a="right"} |
  Out-File -FilePath ($resDir + "\SystemInfo.txt") -Append
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($resDir + "\processes.txt")
}

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$errfile | Sort-Object -Property InstalledOn | Out-File $resDir\hotfixes.txt
