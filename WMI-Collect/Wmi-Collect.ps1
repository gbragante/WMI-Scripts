param( [string]$Path, [switch]$NoPrompt )

$version = "WMI-Collect (20210208)"
# by Gianni Bragante - gbrag@microsoft.com

Function GetOwnerCim{
  param( $prc )
  $ret = Invoke-CimMethod -InputObject $prc -MethodName GetOwner
  return ($ret.Domain + "\" + $ret.User)
}

Function GetOwnerWmi{
  param( $prc )
  $ret = $prc.GetOwner()
  return ($ret.Domain + "\" + $ret.User)
}

$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
if (-not $myWindowsPrincipal.IsInRole($adminRole)) {
  Write-Output "This script needs to be run as Administrator"
  exit
}

if ($NoPrompt) {
  Write-Host "NoPrompt switch specified"
} else {
  Write-Host "This script is designed to collect information that will help Microsoft Customer Support Services (CSS) troubleshoot an issue you may be experiencing with Windows."
  Write-Host "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, PC names, and user names."
  Write-Host "Once the tracing and data collection has completed, the script will save the data in a subfolder. This folder is not automatically sent to Microsoft."
  Write-Host "You can send this folder to Microsoft CSS using a secure file transfer tool - Please discuss this with your support professional and also any concerns you may have."
  Write-Host "Find our privacy statement here: https://privacy.microsoft.com/en-us/privacy"
  $confirm = Read-Host ("Are you sure you want to continue[Y/N]?")
  if ($confirm.ToLower() -ne "y") {exit}
}

$global:Root = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
if ($Path) {
  if (-not (Test-Path $path)) {
    Write-Host "The folder $Path does not esist"
    exit
  }
  $global:resDir = $Path
} else {
  $resName = "WMI-Results-" + $env:computername +"-" + $(get-date -f yyyyMMdd_HHmmss)
  $global:resDir = $global:Root + "\" + $resName
  New-Item -itemtype directory -path $global:resDir | Out-Null
}
$subDir = $global:resDir + "\Subscriptions"
New-Item -itemtype directory -path $subDir | Out-Null

$global:outfile = $global:resDir + "\script-output.txt"
$global:errfile = $global:resDir + "\script-errors.txt"

Import-Module ($global:Root + "\Collect-Commons.psm1") -Force

Write-Log $version
if ($NoPrompt) {
  Write-Log "NoPrompt switch specified"
}

#if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
#  $procdump = "procdump64.exe"
#} else {
#  $procdump = "procdump.exe"
#}

Write-Log "Collecting dump of the svchost process hosting the WinMgmt service"
$pidsvc = FindServicePid "winmgmt"
if ($pidsvc) {
  Write-Log "Found the PID using FindServicePid"
  CreateProcDump $pidsvc $global:resDir "scvhost-WinMgmt"
} else {
  Write-Log "Cannot find the PID using FindServicePid, looping through processes"
  $list = Get-Process
  $found = $false
  if (($list | measure).count -gt 0) {
    foreach ($proc in $list) {
      $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmisvc.dll"} 
      if (($prov | measure).count -gt 0) {
        Write-Log "Found the PID having wmisvc.dll loaded"
        CreateProcDump $proc.id $global:resDir "scvhost-WinMgmt"
        $found = $true
        break
      }
    }
  }
  if (-not $found) {
    Write-Log "Cannot find any process having wmisvc.dll loaded, probably the WMI service is not running"
  }
}

Write-Log "Collecing the dumps of WMIPrvSE.exe processes"
$list = get-process -Name "WmiPrvSe" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    Write-Log ("Found WMIPrvSE.exe with PID " + $proc.Id)
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No WMIPrvSE.exe processes found"
}

Write-Log "Collecing the dumps of decoupled WMI providers"
$list = Get-Process
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
    if (($prov | measure).count -gt 0) {
      Write-Log ("Found " + $proc.Name + "(" + $proc.id + ")")
      CreateProcDump $proc.id $global:resDir
    }
  }
}

$proc = get-process "WmiApSrv" -ErrorAction SilentlyContinue
if ($proc) {
  Write-Log "Collecting dump of the WmiApSrv.exe process"
  CreateProcDump $proc.id $global:resDir
}

Write-Log "Collecing the dumps of scrcons.exe processes"
$list = get-process -Name "scrcons" -ErrorAction SilentlyContinue 2>>$global:errfile
if (($list | measure).count -gt 0) {
  foreach ($proc in $list)
  {
    CreateProcDump $proc.id $global:resDir
  }
} else {
  Write-Log "No scrcons.exe processes found"
}

Write-Log "Collecting Autorecover MOFs content"
$mof = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM")).'Autorecover MOFs'
if ($mof.length -eq 0) {
  Write-Log ("The registry key ""HKLM:\SOFTWARE\Microsoft\Wbem\CIMOM\Autorecover MOFs"" is missing or empty")
  exit
}
$mof | Out-File ($global:resDir + "\Autorecover MOFs.txt")

Write-Log "Listing WBEM folder"
Get-ChildItem $env:windir\system32\wbem -Recurse | Out-File $global:resDir\wbem.txt

Write-Log "Exporting WMIPrvSE AppIDs and CLSIDs registration keys"
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """ + $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\Wow6432Node\AppID\{1F87137D-0E7C-44d5-8C73-4EFFB68962F2}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
$cmd = "reg query ""HKEY_CLASSES_ROOT\CLSID\{4DE225BF-CF59-4CFC-85F7-68B90F185355}"" >> """+ $global:resDir + "\WMIPrvSE.reg.txt"" 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Ole """+ $global:resDir + "\Ole.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Rpc """+ $global:resDir + "\Rpc.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc") {
  Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
  $cmd = "reg export ""HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"" """ + $global:resDir + "\Rpc-policies.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
  Invoke-Expression $cmd
}

Write-Log "Exporting registry key HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem"
$cmd = "reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Wbem """+ $global:resDir + "\wbem.reg.txt"" /y >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Invoke-Expression $cmd

Write-Log "Exporting Application log"
$cmd = "wevtutil epl Application """+ $global:resDir + "\" + $env:computername + "-Application.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "Application"

Write-Log "Exporting System log"
$cmd = "wevtutil epl System """+ $global:resDir + "\" + $env:computername + "-System.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "System"

Write-Log "Exporting WMI-Activity/Operational log"
$cmd = "wevtutil epl Microsoft-Windows-WMI-Activity/Operational """+ $global:resDir + "\" + $env:computername + "-WMI-Activity.evtx"" >>""" + $outfile + """ 2>>""" + $global:errfile + """"
Write-Log $cmd
Invoke-Expression $cmd
ArchiveLog "WMI-Activity"

if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $actLog = Get-WinEvent -logname Microsoft-Windows-WMI-Activity/Operational -Oldest -ErrorAction Continue 2>>$global:errfile
  if (($actLog  | measure).count -gt 0) {
    Write-Log "Exporting WMI-Activity log"
    $actLog | Out-String -width 1000 | Out-File -FilePath ($global:resDir + "\WMI-Activity.txt")
  }
}

Write-Log "Exporting netstat output"
$cmd = "netstat -anob >""" + $global:resDir + "\netstat.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting ipconfig /all output"
$cmd = "ipconfig /all >""" + $global:resDir + "\ipconfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

Write-Log "Exporting service configuration"
$cmd = "sc.exe queryex winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe qc winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe enumdepend winmgmt 3000 >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

$cmd = "sc.exe sdshow winmgmt >>""" + $global:resDir + "\WinMgmtServiceConfig.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append

FileVersion -Filepath ($env:windir + "\system32\wbem\wbemcore.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\repdrvfs.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPrvSE.exe") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiPerfClass.dll") -Log $true
FileVersion -Filepath ($env:windir + "\system32\wbem\WmiApRpl.dll") -Log $true

Write-Log "Collecting details about running processes"
$proc = ExecQuery -Namespace "root\cimv2" -Query "select Name, CreationDate, ProcessId, ParentProcessId, WorkingSetSize, UserModeTime, KernelModeTime, ThreadCount, HandleCount, CommandLine, ExecutablePath, ExecutionState from Win32_Process"
if ($PSVersionTable.psversion.ToString() -ge "3.0") {
  $StartTime= @{e={$_.CreationDate.ToString("yyyyMMdd HH:mm:ss")};n="Start time"}
  $Owner = @{N="User";E={(GetOwnerCim($_))}}
} else {
  $StartTime= @{n='StartTime';e={$_.ConvertToDateTime($_.CreationDate)}}
  $Owner = @{N="User";E={(GetOwnerWmi($_))}}
}

if ($proc.count -gt 3) {
  $proc | Sort-Object Name |
  Format-Table -AutoSize -property @{e={$_.ProcessId};Label="PID"}, @{e={$_.ParentProcessId};n="Parent"}, Name,
  @{N="WorkingSet";E={"{0:N0}" -f ($_.WorkingSetSize/1kb)};a="right"},
  @{e={[DateTime]::FromFileTimeUtc($_.UserModeTime).ToString("HH:mm:ss")};n="UserTime"}, @{e={[DateTime]::FromFileTimeUtc($_.KernelModeTime).ToString("HH:mm:ss")};n="KernelTime"},
  @{N="Threads";E={$_.ThreadCount}}, @{N="Handles";E={($_.HandleCount)}}, @{N="State";E={($_.ExecutionState)}}, $StartTime, $Owner, CommandLine |
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

  Write-Log "Collecting system information"
  $pad = 27
  $OS = ExecQuery -Namespace "root\cimv2" -Query "select Caption, CSName, OSArchitecture, BuildNumber, InstallDate, LastBootUpTime, LocalDateTime, TotalVisibleMemorySize, FreePhysicalMemory, SizeStoredInPagingFiles, FreeSpaceInPagingFiles, MUILanguages from Win32_OperatingSystem"
  $CS = ExecQuery -Namespace "root\cimv2" -Query "select Model, Manufacturer, SystemType, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, DNSHostName, Domain, DomainRole from Win32_ComputerSystem"
  $BIOS = ExecQuery -Namespace "root\cimv2" -query "select BIOSVersion, Manufacturer, ReleaseDate, SMBIOSBIOSVersion from Win32_BIOS"
  $TZ = ExecQuery -Namespace "root\cimv2" -Query "select Description from Win32_TimeZone"
  $PR = ExecQuery -Namespace "root\cimv2" -Query "select Name, Caption from Win32_Processor"

  $ctr = Get-Counter -Counter "\Memory\Pool Paged Bytes" -ErrorAction Continue 2>>$global:errfile
  $PoolPaged = $ctr.CounterSamples[0].CookedValue 
  $ctr = Get-Counter -Counter "\Memory\Pool Nonpaged Bytes" -ErrorAction Continue 2>>$global:errfile
  $PoolNonPaged = $ctr.CounterSamples[0].CookedValue 

  "Computer name".PadRight($pad) + " : " + $OS.CSName | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Model".PadRight($pad) + " : " + $CS.Model | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Manufacturer".PadRight($pad) + " : " + $CS.Manufacturer | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "BIOS Version".PadRight($pad) + " : " + $BIOS.BIOSVersion | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "BIOS Manufacturer".PadRight($pad) + " : " + $BIOS.Manufacturer | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "BIOS Release date".PadRight($pad) + " : " + $BIOS.ReleaseDate | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "SMBIOS Version".PadRight($pad) + " : " + $BIOS.SMBIOSBIOSVersion | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "SystemType".PadRight($pad) + " : " + $CS.SystemType | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Processor".PadRight($pad) + " : " + $PR.Name + " / " + $PR.Caption | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Processors physical/logical".PadRight($pad) + " : " + $CS.NumberOfProcessors + " / " + $CS.NumberOfLogicalProcessors | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Memory physical/visible".PadRight($pad) + " : " + ("{0:N0}" -f ($CS.TotalPhysicalMemory/1mb)) + " MB / " + ("{0:N0}" -f ($OS.TotalVisibleMemorySize/1kb)) + " MB" | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Pool Paged / NonPaged".PadRight($pad) + " : " + ("{0:N0}" -f ($PoolPaged/1mb)) + " MB / " + ("{0:N0}" -f ($PoolNonPaged/1mb)) + " MB" | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Free physical memory".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.FreePhysicalMemory/1kb)) + " MB" | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Paging files size / free".PadRight($pad) + " : " + ("{0:N0}" -f ($OS.SizeStoredInPagingFiles/1kb)) + " MB / " + ("{0:N0}" -f ($OS.FreeSpaceInPagingFiles/1kb)) + " MB" | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Operating System".PadRight($pad) + " : " + $OS.Caption + " " + $OS.OSArchitecture | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Build Number".PadRight($pad) + " : " + $OS.BuildNumber + "." + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ubr + (Win10Ver $OS.BuildNumber)| Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Time zone".PadRight($pad) + " : " + $TZ.Description | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Language packs".PadRight($pad) + " : " + ($OS.MUILanguages -join " ") | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Install date".PadRight($pad) + " : " + $OS.InstallDate | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Last boot time".PadRight($pad) + " : " + $OS.LastBootUpTime | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "Local time".PadRight($pad) + " : " + $OS.LocalDateTime | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "DNS Hostname".PadRight($pad) + " : " + $CS.DNSHostName | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "DNS Domain name".PadRight($pad) + " : " + $CS.Domain | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  "NetBIOS Domain name".PadRight($pad) + " : " + (GetNBDomainName) | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append
  $roles = "Standalone Workstation", "Member Workstation", "Standalone Server", "Member Server", "Backup Domain Controller", "Primary Domain Controller"
  "Domain role".PadRight($pad) + " : " + $roles[$CS.DomainRole] | Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append

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
  Out-File -FilePath ($global:resDir + "\SystemInfo.txt") -Append

  ExecQuery -Namespace "root\cimv2" -Query "select * from Win32_Product" | Sort-Object Name | Format-Table -AutoSize -Property Name, Version, Vendor, InstallDate | Out-String -Width 400 | Out-File -FilePath ($global:resDir + "\products.txt")
} else {
  $proc = Get-Process | Where-Object {$_.Name -ne "Idle"}
  $proc | Format-Table -AutoSize -property id, name, @{N="WorkingSet";E={"{0:N0}" -f ($_.workingset/1kb)};a="right"},
  @{N="VM Size";E={"{0:N0}" -f ($_.VirtualMemorySize/1kb)};a="right"},
  @{N="Proc time";E={($_.TotalProcessorTime.ToString().substring(0,8))}}, @{N="Threads";E={$_.threads.count}},
  @{N="Handles";E={($_.HandleCount)}}, StartTime, Path | 
  Out-String -Width 300 | Out-File -FilePath ($global:resDir + "\processes.txt")
  Write-Log "Exiting since WMI is not working"
  exit
}

Write-Log "COM Security"
$Reg = [WMIClass]"\\.\root\default:StdRegProv"
$DCOMMachineLaunchRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineLaunchRestriction").uValue
$DCOMMachineAccessRestriction = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","MachineAccessRestriction").uValue
$DCOMDefaultLaunchPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultLaunchPermission").uValue
$DCOMDefaultAccessPermission = $Reg.GetBinaryValue(2147483650,"software\microsoft\ole","DefaultAccessPermission").uValue
 
# Convert the current permissions to SDDL
$converter = new-object system.management.ManagementClass Win32_SecurityDescriptorHelper
"Default Access Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultAccessPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
"Default Launch Permission = " + ($converter.BinarySDToSDDL($DCOMDefaultLaunchPermission)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
"Machine Access Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineAccessRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append
"Machine Launch Restriction = " + ($converter.BinarySDToSDDL($DCOMMachineLaunchRestriction)).SDDL | Out-File -FilePath ($global:resDir + "\COMSecurity.txt") -Append

Write-Log "Collecting the list of installed hotfixes"
Get-HotFix -ErrorAction SilentlyContinue 2>>$global:errfile | Sort-Object -Property InstalledOn | Out-File $global:resDir\hotfixes.txt

Write-Log "Collecting details of provider hosts"
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR -ErrorAction SilentlyContinue | Out-Null

"Coupled providers (WMIPrvSE.exe processes)" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
"" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

$totMem = 0

$prov = ExecQuery -NameSpace "root\cimv2" -Query "select HostProcessIdentifier, Provider, Namespace, User from MSFT_Providers"
if ($prov) {
  $proc = ExecQuery -NameSpace "root\cimv2" -Query "select ProcessId, HandleCount, ThreadCount, PrivatePageCount, CreationDate, KernelModeTime, UserModeTime from Win32_Process where name = 'wmiprvse.exe'"
  foreach ($prv in $proc) {
    $provhost = $prov | Where-Object {$_.HostProcessIdentifier -eq $prv.ProcessId}

    if (($provhost | measure).count -gt 0) {
      if ($PSVersionTable.psversion.ToString() -ge "3.0") {
        $ut = New-TimeSpan -Start $prv.CreationDate
      } else {
        $ut = New-TimeSpan -Start $prv.ConvertToDateTime($prv.CreationDate)
      }

      $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

      $ks = $prv.KernelModeTime / 10000000
      $kt = [timespan]::fromseconds($ks)
      $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

      $us = $prv.UserModeTime / 10000000
      $ut = [timespan]::fromseconds($us)
      $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

      "PID" + " " + $prv.ProcessId + " (" + [String]::Format("{0:x}", $prv.ProcessId) + ") Handles:" + $prv.HandleCount +" Threads:" + $prv.ThreadCount + " Private KB:" + ($prv.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      $totMem = $totMem + $prv.PrivatePageCount
    } else {
      Write-Log ("No provider found for the WMIPrvSE process with PID " +  $prv.ProcessId)
    }

    foreach ($provname in $provhost) {
      $provdet = ExecQuery -NameSpace $provname.Namespace -Query ("select * from __Win32Provider where Name = """ + $provname.Provider + """")
      $hm = $provdet.hostingmodel
      $clsid = $provdet.CLSID
      $dll = (get-itemproperty -ErrorAction SilentlyContinue -literalpath ("HKCR:\CLSID\" + $clsid + "\InprocServer32")).'(default)' 2>>$global:errfile
      $dll = $dll.Replace("""","")
      $file = Get-Item ($dll)
      $dtDLL = $file.CreationTime
      $verDLL = $file.VersionInfo.FileVersion

      $provname.Namespace + " " + $provname.Provider + " " + $dll + " " + $hm + " " + $provname.user + " " + $dtDLL + " " + $verDLL 2>>$global:errfile | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    }
    " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  }
}
"Total memory used by coupled providers: " + ($totMem/1kb) + " KB" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
" " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

# Details of decoupled providers
$list = Get-Process
foreach ($proc in $list) {
  $prov = Get-Process -id $proc.id -Module -ErrorAction SilentlyContinue | Where-Object {$_.ModuleName -eq "wmidcprv.dll"} 
  if (($prov | measure).count -gt 0) {
    if (-not $hdr) {
      "Decoupled providers" | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      $hdr = $true
    }

    $prc = ExecQuery -Namespace "root\cimv2" -Query ("select ProcessId, CreationDate, HandleCount, ThreadCount, PrivatePageCount, ExecutablePath, KernelModeTime, UserModeTime from Win32_Process where ProcessId = " +  $proc.id)
    if ($PSVersionTable.psversion.ToString() -ge "3.0") {
      $ut= New-TimeSpan -Start $prc.CreationDate
    } else {
      $ut= New-TimeSpan -Start $prc.ConvertToDateTime($prc.CreationDate)
    }

    $uptime = ($ut.Days.ToString() + "d " + $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00"))

    $ks = $prc.KernelModeTime / 10000000
    $kt = [timespan]::fromseconds($ks)
    $kh = $kt.Hours.ToString("00") + ":" + $kt.Minutes.ToString("00") + ":" + $kt.Seconds.ToString("00")

    $us = $prc.UserModeTime / 10000000
    $ut = [timespan]::fromseconds($us)
    $uh = $ut.Hours.ToString("00") + ":" + $ut.Minutes.ToString("00") + ":" + $ut.Seconds.ToString("00")

    $svc = ExecQuery -Namespace "root\cimv2" -Query ("select Name from Win32_Service where ProcessId = " +  $prc.ProcessId)
    $svclist = ""
    if ($svc) {
      foreach ($item in $svc) {
        $svclist = $svclist + $item.name + " "
      }
      $svc = " Service: " + $svclist
    } else {
      $svc = ""
    }

    ($prc.ExecutablePath + $svc) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
    "PID " + $prc.ProcessId  + " (" + [String]::Format("{0:x}", $prc.ProcessId) + ")  Handles: " + $prc.HandleCount + " Threads: " + $prc.ThreadCount + " Private KB: " + ($prc.PrivatePageCount/1kb) + " KernelTime:" + $kh + " UserTime:" + $uh + " Uptime:" + $uptime | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append

    $Keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Wbem\Transports\Decoupled\Client
    $Items = $Keys | Foreach-Object {Get-ItemProperty $_.PsPath }
    ForEach ($key in $Items) {
      if ($key.ProcessIdentifier -eq $prc.ProcessId) {
        ($key.Scope + " " + $key.Provider) | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
      }
    }
    " " | Out-File -FilePath ($global:resDir + "\ProviderHosts.txt") -Append
  }
}

Write-Log "Collecting quota details"
$quota = ExecQuery -Namespace "Root" -Query "select * from __ProviderHostQuotaConfiguration"
if ($quota) {
  ("ThreadsPerHost : " + $quota.ThreadsPerHost + "`r`n") + `
  ("HandlesPerHost : " + $quota.HandlesPerHost + "`r`n") + `
  ("ProcessLimitAllHosts : " + $quota.ProcessLimitAllHosts + "`r`n") + `
  ("MemoryPerHost : " + $quota.MemoryPerHost + "`r`n") + `
  ("MemoryAllHosts : " + $quota.MemoryAllHosts + "`r`n") | Out-File -FilePath ($global:resDir + "\ProviderHostQuotaConfiguration.txt")
}

ExecQuery -Namespace "root\subscription" -Query "select * from ActiveScriptEventConsumer" | Export-Clixml -Path ($subDir + "\ActiveScriptEventConsumer.xml")
ExecQuery -Namespace "root\subscription" -Query "select * from __eventfilter" | Export-Clixml -Path ($subDir + "\__eventfilter.xml")
ExecQuery -Namespace "root\subscription" -Query "select * from __IntervalTimerInstruction" | Export-Clixml -Path ($subDir + "\__IntervalTimerInstruction.xml")
ExecQuery -Namespace "root\subscription" -Query "select * from __AbsoluteTimerInstruction" | Export-Clixml -Path ($subDir + "\__AbsoluteTimerInstruction.xml")
ExecQuery -Namespace "root\subscription" -Query "select * from __FilterToConsumerBinding" | Export-Clixml -Path ($subDir + "\__FilterToConsumerBinding.xml")

Write-Log "Exporting driverquery /v output"
$cmd = "driverquery /v >""" + $global:resDir + "\drivers.txt""" + $RdrErr
Write-Log $cmd
Invoke-Expression ($cmd) | Out-File -FilePath $outfile -Append
